//! Native accepted additional Device, real Add/Welcome and cross-Station Signal.

use std::sync::Mutex;

use arkret_models_collaboration::SignalDeliveryAuthority;

use super::*;

struct Decryptor<'a> {
    group: &'a ArkretMlsGroup,
    state: &'a EventId,
    head: &'a RealmCommitId,
    replay: Mutex<arkret::AeadNonceReplayTracker>,
}

impl garth::signal::SignalDecryptor for Decryptor<'_> {
    async fn decrypt(
        &self,
        envelope: &SignalEnvelope,
        key: &arkret_wire::StationSigningKey,
    ) -> garth::Result<Vec<u8>> {
        let mut replay = self
            .replay
            .lock()
            .map_err(|_| garth::Error::Protocol("nonce replay lock poisoned".into()))?;
        self.group
            .open_signal_envelope_with_station_key(
                envelope,
                key,
                self.state.as_str(),
                self.head,
                &mut replay,
            )
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

async fn next(
    stream: &mut arkret_http_client::SignalSubscribeFrameStream,
    expected: &SignalEnvelope,
) -> Result<(SignalEnvelope, SignalDeliveryAuthority)> {
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        loop {
            match stream
                .next_frame()
                .await?
                .context("same-Actor Signal stream closed")?
            {
                SignalStreamFrame::Heartbeat => {}
                SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } if envelope.proof.envelope_digest == expected.proof.envelope_digest => {
                    return Ok((envelope, delivery_authority));
                }
                _ => anyhow::bail!("unexpected frame in same-Actor Signal delivery"),
            }
        }
    })
    .await
    .context("same-Actor Signal delivery deadline")?
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn exercise(
    phone: &Member,
    laptop: &Member,
    receiver: &Member,
    phone_group: &mut ArkretMlsGroup,
    mut laptop_group: ArkretMlsGroup,
    receiver_group: &ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    head: &RealmCommitId,
) -> Result<()> {
    ensure!(phone.actor == laptop.actor && phone.device != laptop.device);
    ensure!(phone.authorize_event_id != laptop.authorize_event_id);
    ensure!(
        phone_group.epoch() == laptop_group.epoch()
            && laptop_group.epoch() == receiver_group.epoch()
    );
    ensure!(
        phone_group.signal_nonce_reservation()?.1 == 0
            && laptop_group.signal_nonce_reservation()?.1 == 0
    );
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let first_plain = arkret_canonical::canonical_json_bytes(&TypingPlaintext::new(
        1,
        arkret_wire::StrandId::new(strand)?,
        true,
    )?)?;
    let second_plain = arkret_canonical::canonical_json_bytes(&TypingPlaintext::new(
        1,
        arkret_wire::StrandId::new(strand)?,
        false,
    )?)?;
    let first = scoped_envelope_with_payload(
        phone,
        phone_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        1,
        scope.clone(),
        None,
        Some(first_plain.clone()),
    )?;
    let second = scoped_envelope_with_payload(
        laptop,
        &mut laptop_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        1,
        scope.clone(),
        None,
        Some(second_plain.clone()),
    )?;
    ensure!(first.encrypted_payload.nonce == second.encrypted_payload.nonce);
    ensure!(
        phone_group.local_signal_nonce_context()? != laptop_group.local_signal_nonce_context()?
    );
    let first_cipher = arkret_canonical::base64url_decode(&first.encrypted_payload.ciphertext)?;
    let second_cipher = arkret_canonical::base64url_decode(&second.encrypted_payload.ciphertext)?;
    let length = first_plain.len().min(second_plain.len());
    let plain_xor: Vec<_> = first_plain[..length]
        .iter()
        .zip(&second_plain[..length])
        .map(|(a, b)| a ^ b)
        .collect();
    let cipher_xor: Vec<_> = first_cipher[..length]
        .iter()
        .zip(&second_cipher[..length])
        .map(|(a, b)| a ^ b)
        .collect();
    ensure!(
        plain_xor != cipher_xor,
        "same-Actor native endpoints leaked plaintext XOR"
    );
    let mut stream = receiver.client.sdk().signal_subscribe_frames().await?;
    ensure!(matches!(
        stream.next_frame().await?,
        Some(SignalStreamFrame::Heartbeat)
    ));
    let decryptor = Decryptor {
        group: receiver_group,
        state,
        head,
        replay: Default::default(),
    };
    let mut recipient = garth::signal::SignalReceiver::new();
    let mut last = None;
    for (sender, signal) in [(phone, first), (laptop, second)] {
        let outcome = sender.client.sdk().signal_send(&signal).await?;
        ensure!(outcome.accepted);
        let delivered = next(&mut stream, &signal).await?;
        ensure!(
            delivered.1.recipient_account_id == receiver.account
                && delivered.1.key.actor == sender.actor
                && delivered.1.key.authorization_ref == sender.authorize_event_id
        );
        ensure!(matches!(
            recipient
                .receive(&delivered.0, &delivered.1, &decryptor, Utc::now())
                .await?,
            garth::signal::SignalReceiveOutcome::Accepted { .. }
        ));
        last = Some(delivered);
    }
    let (last, authority) = last.context("two native frames delivered")?;
    ensure!(
        recipient
            .receive(&last, &authority, &decryptor, Utc::now())
            .await
            .is_err(),
        "exact nonce replay bypassed the shared receiver"
    );
    let checkpoint = tempfile::NamedTempFile::new()?;
    std::fs::write(
        checkpoint.path(),
        serde_json::to_vec(&laptop_group.export_state_record()?)?,
    )?;
    checkpoint.as_file().sync_all()?;
    laptop_group = ArkretMlsGroup::restore_from_state_record(&serde_json::from_slice(
        &std::fs::read(checkpoint.path())?,
    )?)?;
    let after_restart = scoped_envelope(
        laptop,
        &mut laptop_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        2,
        scope,
        None,
    )?;
    ensure!(after_restart.encrypted_payload.nonce != last.encrypted_payload.nonce);
    ensure!(
        laptop
            .client
            .sdk()
            .signal_send(&after_restart)
            .await?
            .accepted
    );
    let delivered = next(&mut stream, &after_restart).await?;
    ensure!(matches!(
        recipient
            .receive(&delivered.0, &delivered.1, &decryptor, Utc::now())
            .await?,
        garth::signal::SignalReceiveOutcome::Accepted { .. }
    ));
    println!(
        "[signal-same-actor] native_additional_device=1 actual_add_welcome=1 distinct_endpoint_keys=1 equal_first_nonce=1 xor_leak_absent=1 cross_station_frames=3 shared_replay_domains=2 true_replay_rejected=1 restarted_sender_continues=1"
    );
    Ok(())
}
