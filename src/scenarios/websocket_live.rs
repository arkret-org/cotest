//! Real TLS transport, accepted device, issuer ledger and shared PostgreSQL gates.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::sync_frames::websocket::*;
use arkret_signatures::websocket_auth::{WebSocketAuthProofRequest, build_websocket_auth_proof};
use arkret_wire::websocket_binding::{WEBSOCKET_SUBPROTOCOL, WebSocketOperationId};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::harness::{ArkretServer, ClientSession, TestActorClient};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::human_device_producer_live::{database, standard_client};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::security_rotation_live::rotation_station_env;

pub struct Socket {
    stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    pub operations: std::collections::BTreeMap<String, WebSocketOperationId>,
}
impl std::ops::Deref for Socket {
    type Target = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}
impl std::ops::DerefMut for Socket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}
pub const WAIT: Duration = Duration::from_secs(40);

pub fn socket_url(server: &ArkretServer) -> Result<String> {
    let mut url = server.base_url().join("/_arkret/ws")?;
    url.set_scheme("wss")
        .map_err(|_| anyhow::anyhow!("WSS scheme"))?;
    Ok(url.to_string())
}

pub async fn connect(
    server: &ArkretServer,
    origin: Option<&str>,
    protocol: &str,
) -> Result<Socket> {
    let ca = std::fs::read(server.tls_ca_path().context("real TLS fixture CA")?)?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&ca) {
        roots.add(certificate?)?;
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut request = socket_url(server)?.into_client_request()?;
    if let Some(origin) = origin {
        request.headers_mut().insert("Origin", origin.parse()?);
    }
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", protocol.parse()?);
    let (socket, response) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        true,
        Some(Connector::Rustls(Arc::new(tls))),
    )
    .await?;
    ensure!(
        response.status() == 101
            && response
                .headers()
                .get("sec-websocket-protocol")
                .is_some_and(|selected| selected == WEBSOCKET_SUBPROTOCOL),
        "exact selected subprotocol"
    );
    Ok(Socket {
        stream: socket,
        operations: Default::default(),
    })
}

pub async fn send(socket: &mut Socket, frame: &WebSocketClientFrame) -> Result<()> {
    frame.validate()?;
    socket
        .stream
        .send(Message::Text(
            String::from_utf8(arkret_canonical::canonical_json_bytes(frame)?)?.into(),
        ))
        .await?;
    if let WebSocketClientFrame::Open {
        channel_id,
        operation_id,
        ..
    } = frame
    {
        socket.operations.insert(channel_id.clone(), *operation_id);
    }
    Ok(())
}

pub async fn next(socket: &mut Socket) -> Result<WebSocketServerFrame> {
    loop {
        let message = tokio::time::timeout(WAIT, socket.next())
            .await?
            .context("live connection remains open")??;
        match message {
            Message::Text(text) => {
                let frame = WebSocketFrameIngress::new(262_144, None)
                    .decode_server_frame_for_channels(text.as_bytes(), |id| {
                        socket.operations.get(id).copied()
                    })
                    .map_err(|error| {
                        anyhow::anyhow!("server direction/schema: {}", error.message)
                    })?;
                if let WebSocketServerFrame::Ping { ping_id, .. } = frame {
                    send(socket, &WebSocketClientFrame::Pong { ping_id }).await?;
                } else {
                    match &frame {
                        WebSocketServerFrame::Opened {
                            channel_id,
                            operation_id,
                        } => eprintln!(
                            "[websocket-live] opened channel={channel_id} operation={operation_id}"
                        ),
                        WebSocketServerFrame::ChannelError {
                            channel_id, error, ..
                        } => eprintln!(
                            "[websocket-live] channel_error channel={channel_id} code={}",
                            error.code
                        ),
                        WebSocketServerFrame::ChannelControl {
                            channel_id,
                            payload: WebSocketChannelControlPayload::Account(control),
                            ..
                        } => eprintln!(
                            "[websocket-live] control channel={channel_id} kind={:?} cursor_present={}",
                            control.kind,
                            control.cursor.is_some()
                        ),
                        WebSocketServerFrame::ChannelControl {
                            channel_id,
                            payload: WebSocketChannelControlPayload::Events(control),
                            ..
                        } => eprintln!(
                            "[websocket-live] control channel={channel_id} kind={:?} cursor_present={}",
                            control.kind,
                            control.cursor.is_some()
                        ),
                        _ => {}
                    }
                    return Ok(frame);
                }
            }
            Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await?,
            Message::Pong(_) => {}
            Message::Close(close) => {
                bail!("unexpected physical close: {:?}", close.map(|c| c.code))
            }
            _ => bail!("server sent a non-text application frame"),
        }
    }
}

pub async fn until(
    socket: &mut Socket,
    predicate: impl Fn(&WebSocketServerFrame) -> bool,
) -> Result<WebSocketServerFrame> {
    tokio::time::timeout(WAIT, async {
        loop {
            let frame = next(socket).await?;
            if predicate(&frame) {
                return Ok(frame);
            }
            if let WebSocketServerFrame::ChannelError {
                channel_id, error, ..
            } = frame
            {
                bail!("unexpected channel error {channel_id}: {}", error.code);
            }
        }
    })
    .await?
}

pub fn auth(
    client: &TestActorClient,
    url: &str,
    challenge: &WebSocketServerFrame,
    jti: &str,
) -> Result<WebSocketClientFrame> {
    let (connection_id, nonce) = match challenge {
        WebSocketServerFrame::Challenge {
            connection_id,
            nonce,
            ..
        }
        | WebSocketServerFrame::ReauthRequired {
            connection_id,
            nonce,
            ..
        } => (connection_id, nonce),
        _ => bail!("authentication requires the current socket challenge"),
    };
    let ClientSession::Canonical { grant, signing_key } = client.session() else {
        bail!("standard device grant");
    };
    let proof = build_websocket_auth_proof(
        &WebSocketAuthProofRequest {
            base_url: url,
            session_grant: grant,
            nonce,
            issued_at: Utc::now(),
            jti,
        },
        signing_key,
    )?;
    Ok(WebSocketClientFrame::Authenticate {
        connection_id: connection_id.clone(),
        session_grant: grant.clone(),
        dpop_proof: proof.compact_jws,
    })
}

pub async fn authenticated(
    server: &ArkretServer,
    client: &TestActorClient,
) -> Result<(Socket, WebSocketClientFrame)> {
    authenticated_with_jti(server, client, &fresh_jti()).await
}

pub async fn authenticated_with_jti(
    server: &ArkretServer,
    client: &TestActorClient,
    jti: &str,
) -> Result<(Socket, WebSocketClientFrame)> {
    let origin = server.base_url().origin().ascii_serialization();
    let mut socket = connect(server, Some(&origin), WEBSOCKET_SUBPROTOCOL).await?;
    let challenge = next(&mut socket)
        .await
        .context("initial socket challenge")?;
    let frame = auth(client, &socket_url(server)?, &challenge, jti)?;
    send(&mut socket, &frame).await?;
    ensure!(
        matches!(
            next(&mut socket)
                .await
                .context("proof and current grant admission")?,
            WebSocketServerFrame::Welcome { .. }
        ),
        "authenticated welcome"
    );
    Ok((socket, frame))
}

pub fn fresh_jti() -> String {
    format!(
        "{}{}",
        crate::scenarios::mls_lifecycle_live::fresh_uuid_v7(),
        crate::scenarios::mls_lifecycle_live::fresh_uuid_v7()
    )
}

pub async fn closed(socket: &mut Socket, expected: u16) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(12), async {
        while let Some(message) = socket.next().await {
            match message? {
                Message::Close(Some(frame)) => {
                    ensure!(
                        u16::from(frame.code) == expected,
                        "physical close {} != {expected}",
                        u16::from(frame.code)
                    );
                    return Ok(());
                }
                Message::Text(text) => {
                    WebSocketFrameIngress::new(262_144, None)
                        .decode_server_frame(text.as_bytes())
                        .map_err(|e| anyhow::anyhow!(e.message))?;
                }
                Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await?,
                _ => {}
            }
        }
        bail!("connection ended without its normative close code")
    })
    .await?
}

pub async fn finish(socket: &mut Socket) -> Result<()> {
    socket
        .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "".into(),
        }))
        .await?;
    closed(socket, 1000)
        .await
        .context("peer-initiated normal close reply")
}

pub fn events(realm: &str, after: Option<String>) -> Result<WebSocketOpenParameters> {
    Ok(WebSocketOpenParameters::Events(
        WebSocketEventsOpenParameters {
            realm_ids: Some(vec![arkret_wire::RealmId::new(realm)?]),
            actor_ids: None,
            catchup: after.as_ref().map(|_| true),
            after,
        },
    ))
}

pub async fn open(
    socket: &mut Socket,
    id: &str,
    parameters: WebSocketOpenParameters,
    operation: WebSocketOperationId,
) -> Result<()> {
    send(
        socket,
        &WebSocketClientFrame::Open {
            channel_id: id.to_owned(),
            operation_id: operation,
            parameters,
        },
    )
    .await?;
    until(socket,|frame|matches!(frame,WebSocketServerFrame::Opened {channel_id,operation_id} if channel_id==id && *operation_id==operation)).await.with_context(||format!("open {id}"))?;
    Ok(())
}

pub fn cursor(frame: &WebSocketServerFrame, id: &str) -> Option<String> {
    match frame {
        WebSocketServerFrame::Data {
            channel_id,
            payload: WebSocketDataPayload::Account(frame),
        } if channel_id == id => frame.cursor.clone(),
        WebSocketServerFrame::ChannelControl {
            channel_id,
            payload: WebSocketChannelControlPayload::Account(frame),
            ..
        } if channel_id == id => frame.cursor.clone(),
        WebSocketServerFrame::Data {
            channel_id,
            payload: WebSocketDataPayload::Events(frame),
        } if channel_id == id => frame.cursor.clone(),
        WebSocketServerFrame::ChannelControl {
            channel_id,
            payload: WebSocketChannelControlPayload::Events(frame),
            ..
        } if channel_id == id => frame.cursor.clone(),
        _ => None,
    }
}

/// Consume a real Signal while the two durable rails share the same socket.
pub(crate) struct LiveSignalReader(Socket);

impl LiveSignalReader {
    pub(crate) async fn connect(
        server: &ArkretServer,
        client: &TestActorClient,
        realm: &str,
    ) -> Result<Self> {
        let (mut socket, _) = authenticated(server, client).await?;
        open(
            &mut socket,
            "account-1",
            WebSocketOpenParameters::Account(Default::default()),
            WebSocketOperationId::AccountStreamSubscribe,
        )
        .await?;
        until(&mut socket, |frame| cursor(frame, "account-1").is_some()).await?;
        open(
            &mut socket,
            "events-1",
            events(realm, None)?,
            WebSocketOperationId::CommittedEventStreamSubscribe,
        )
        .await?;
        until(&mut socket, |frame| cursor(frame, "events-1").is_some()).await?;
        open(
            &mut socket,
            "signal-1",
            WebSocketOpenParameters::Signal(Default::default()),
            WebSocketOperationId::SignalStreamSubscribe,
        )
        .await?;
        Ok(Self(socket))
    }

    pub(crate) async fn next_frame(&mut self) -> Result<Option<arkret_wire::SignalStreamFrame>> {
        loop {
            match next(&mut self.0).await? {
                WebSocketServerFrame::Data {
                    channel_id,
                    payload: WebSocketDataPayload::Signal(frame),
                } if channel_id == "signal-1" => return Ok(Some(*frame)),
                WebSocketServerFrame::ChannelControl {
                    channel_id,
                    payload: WebSocketChannelControlPayload::Heartbeat(_),
                    ..
                } if channel_id == "signal-1" => {
                    return Ok(Some(arkret_wire::SignalStreamFrame::Heartbeat));
                }
                WebSocketServerFrame::ChannelControl {
                    channel_id,
                    payload: WebSocketChannelControlPayload::Signal(frame),
                    ..
                } if channel_id == "signal-1" => return Ok(Some(*frame)),
                WebSocketServerFrame::ChannelError { error, .. } => {
                    bail!("shared Signal socket channel error: {}", error.code)
                }
                WebSocketServerFrame::Closed { .. } => bail!("shared Signal socket channel closed"),
                _ => {}
            }
        }
    }

    pub(crate) async fn finish(&mut self) -> Result<()> {
        finish(&mut self.0).await
    }
}

/// This does not replace the deterministic SDK known-answer fixture. It tests
/// the implementation's real Upgrade, pump, readers and durable auth store.
pub async fn run_transport_and_three_rails() -> Result<()> {
    crate::conformance::run_websocket_binding_suite()?;
    let Some(database) = database("websocket-live")? else {
        return Ok(());
    };
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let env = rotation_station_env(&issuer);
    let refs = env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let server =
        ArkretServer::spawn_with_database_url("websocket-live", &database.connect_url, &refs)
            .await?;
    advertised_websocket(&server).await?;
    let (alice, _) = standard_client(
        &server,
        &issuer,
        "socket-alice",
        "ak:device:01904100-0000-7000-8000-000000002801",
    )
    .await?;
    let (bob, _) = standard_client(
        &server,
        &issuer,
        "socket-bob",
        "ak:device:01904100-0000-7000-8000-000000002802",
    )
    .await?;
    let realm = alice.create_realm("Socket authority tail").await?;
    let origin = server.base_url().origin().ascii_serialization();
    for (selected_origin, protocol) in [
        (None, WEBSOCKET_SUBPROTOCOL),
        (Some("https://unregistered.invalid"), WEBSOCKET_SUBPROTOCOL),
        (Some(origin.as_str()), "invalid.protocol"),
    ] {
        ensure!(
            connect(&server, selected_origin, protocol).await.is_err(),
            "Upgrade trust boundary rejects"
        );
    }
    let mut unauth = connect(&server, Some(&origin), WEBSOCKET_SUBPROTOCOL).await?;
    ensure!(matches!(
        next(&mut unauth).await?,
        WebSocketServerFrame::Challenge { .. }
    ));
    closed(&mut unauth, 1008).await?;

    let used_jti = fresh_jti();
    let (mut socket, proof) = authenticated_with_jti(&server, &alice, &used_jti).await?;
    let mut replay = connect(&server, Some(&origin), WEBSOCKET_SUBPROTOCOL).await?;
    next(&mut replay).await?;
    send(&mut replay, &proof).await?;
    closed(&mut replay, 1008).await?;
    let mut ledger_replay = connect(&server, Some(&origin), WEBSOCKET_SUBPROTOCOL).await?;
    let fresh_challenge = next(&mut ledger_replay).await?;
    // A valid proof for the new nonce still cannot reuse a consumed JTI.
    send(
        &mut ledger_replay,
        &auth(&alice, &socket_url(&server)?, &fresh_challenge, &used_jti)?,
    )
    .await?;
    closed(&mut ledger_replay, 1008)
        .await
        .context("shared replay ledger rejects fresh-nonce JTI reuse")?;
    eprintln!("[websocket-live] authentication and shared replay passed");
    let account = WebSocketOperationId::AccountStreamSubscribe;
    let committed = WebSocketOperationId::CommittedEventStreamSubscribe;
    let signal = WebSocketOperationId::SignalStreamSubscribe;
    open(
        &mut socket,
        "account-1",
        WebSocketOpenParameters::Account(Default::default()),
        account,
    )
    .await?;
    let account_baseline = until(&mut socket, |frame| cursor(frame, "account-1").is_some())
        .await
        .context("account baseline cursor")?;
    let account_cursor = cursor(&account_baseline, "account-1").unwrap();
    open(&mut socket, "events-1", events(&realm, None)?, committed).await?;
    let events_baseline = until(&mut socket, |frame| cursor(frame, "events-1").is_some())
        .await
        .context("events baseline cursor")?;
    let events_cursor = cursor(&events_baseline, "events-1").unwrap();
    ensure!(
        account_cursor != events_cursor,
        "independent opaque cursor families"
    );
    open(
        &mut socket,
        "signal-1",
        WebSocketOpenParameters::Signal(Default::default()),
        signal,
    )
    .await?;
    // A refused logical channel must leave all three admitted rails alive.
    for index in 0..13 {
        open(
            &mut socket,
            &format!("capacity-{index}"),
            events(&realm, None)?,
            committed,
        )
        .await?;
    }
    send(
        &mut socket,
        &WebSocketClientFrame::Open {
            channel_id: "over-capacity".to_owned(),
            operation_id: committed,
            parameters: events(&realm, None)?,
        },
    )
    .await?;
    until(&mut socket, |frame| {
        matches!(frame,WebSocketServerFrame::ChannelError {channel_id,error,..}
        if channel_id=="over-capacity" && error.code==arkret_wire::ErrorCode::RateLimited)
    })
    .await?;
    until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::Closed {channel_id,..} if channel_id=="over-capacity")).await?;
    for index in 0..13 {
        let id = format!("capacity-{index}");
        send(
            &mut socket,
            &WebSocketClientFrame::Close {
                channel_id: id.clone(),
                reason: WebSocketCloseReason::ClientRequest,
            },
        )
        .await?;
        until(
            &mut socket,
            |frame| matches!(frame,WebSocketServerFrame::Closed {channel_id,..} if channel_id==&id),
        )
        .await?;
    }
    send(
        &mut socket,
        &WebSocketClientFrame::Open {
            channel_id: "bad-cursor".to_owned(),
            operation_id: committed,
            parameters: events(&realm, Some("ak:cursor:AAAAAAAAAAAAAAAAAAAAAA".to_owned()))?,
        },
    )
    .await?;
    until(&mut socket, |frame| {
        matches!(frame,WebSocketServerFrame::ChannelError {channel_id,error,..}
        if channel_id=="bad-cursor" && error.code==arkret_wire::ErrorCode::ParamInvalid)
    })
    .await?;
    until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::Closed {channel_id,..} if channel_id=="bad-cursor")).await?;
    eprintln!(
        "[websocket-live] channel_limit_16=1 refused_17th_isolated=1 invalid_cursor_isolated=1"
    );
    socket
        .send(Message::Text(
            r#"{"kind":"open","channel_id":"missing-selector","parameters":{"invalid":true}}"#
                .into(),
        ))
        .await?;
    until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::ChannelError {channel_id,error,..} if channel_id=="missing-selector" && error.code==arkret_wire::ErrorCode::OperationSelectorRequired)).await?;
    until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::Closed {channel_id,..} if channel_id=="missing-selector")).await?;
    send(
        &mut socket,
        &WebSocketClientFrame::Close {
            channel_id: "events-1".to_owned(),
            reason: WebSocketCloseReason::ClientRequest,
        },
    )
    .await?;
    until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::Closed {channel_id,..} if channel_id=="events-1")).await?;
    send(
        &mut socket,
        &WebSocketClientFrame::Open {
            channel_id: "events-1".to_owned(),
            operation_id: committed,
            parameters: events(&realm, Some(events_cursor.clone()))?,
        },
    )
    .await?;
    until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::ChannelError {channel_id,error,..} if channel_id=="events-1" && error.code==arkret_wire::ErrorCode::Conflict)).await?;
    open(
        &mut socket,
        "events-2",
        events(&realm, Some(events_cursor.clone()))?,
        committed,
    )
    .await?;
    until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::ChannelControl {channel_id,payload:WebSocketChannelControlPayload::Events(frame),..} if channel_id=="events-2" && frame.kind==arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrameKind::CatchupComplete)).await?;
    let add_member = alice.add_member(&realm, &bob);
    tokio::pin!(add_member);
    let mut tail = None;
    loop {
        tokio::select! {
            result = &mut add_member => { result.context("accept member while serving socket heartbeats")?; break; }
            frame = next(&mut socket) => {
                let frame = frame.context("live socket during member admission")?;
                if matches!(&frame,WebSocketServerFrame::Data {channel_id,payload:WebSocketDataPayload::Events(_)} if channel_id=="events-2") {
                    tail = Some(frame);
                }
            }
        }
    }
    let data = if let Some(frame) = tail {
        frame
    } else {
        until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::Data {channel_id,payload:WebSocketDataPayload::Events(_)} if channel_id=="events-2")).await.context("committed tail after member admission")?
    };
    let tail_cursor =
        cursor(&data, "events-2").context("formal committed Event carries continuation")?;
    ensure!(
        tail_cursor != events_cursor,
        "accepted tail advances only its own progress"
    );
    if let WebSocketServerFrame::Data {
        payload: WebSocketDataPayload::Events(frame),
        ..
    } = data
    {
        ensure!(
            frame
                .committed_event()
                .context("formal committed view")?
                .commit()
                .realm_id
                .as_str()
                == realm
        );
    }
    eprintln!("[websocket-live] accepted member tail received; normal close begins");
    finish(&mut socket)
        .await
        .context("normal close after committed tail")?;
    drop(socket);
    let (mut resumed, _) = authenticated(&server, &alice).await?;
    open(
        &mut resumed,
        "account-resume",
        WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
            after: Some(account_cursor),
            catchup: Some(true),
            ..Default::default()
        }),
        account,
    )
    .await?;
    until(&mut resumed, |frame| {
        cursor(frame, "account-resume").is_some()
    })
    .await?;
    open(
        &mut resumed,
        "events-resume",
        events(&realm, Some(tail_cursor))?,
        committed,
    )
    .await?;
    until(&mut resumed,|frame|matches!(frame,WebSocketServerFrame::ChannelControl {channel_id,payload:WebSocketChannelControlPayload::Events(frame),..} if channel_id=="events-resume" && frame.kind==arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrameKind::CatchupComplete)).await?;
    open(
        &mut resumed,
        "signal-resume",
        WebSocketOpenParameters::Signal(Default::default()),
        signal,
    )
    .await?;
    finish(&mut resumed).await?;
    drop(resumed);
    eprintln!("[websocket-live] three rails and independent durable resume passed");

    let (mut malformed, _) = authenticated(&server, &alice).await?;
    malformed
        .send(Message::Text(
            r#"{"kind":"pong","kind":"pong","ping_id":"duplicate"}"#.into(),
        ))
        .await?;
    closed(&mut malformed, 1002)
        .await
        .context("duplicate member close 1002")?;
    let (mut binary, _) = authenticated(&server, &alice).await?;
    binary.send(Message::Binary(vec![1, 2, 3].into())).await?;
    closed(&mut binary, 1002)
        .await
        .context("binary frame close 1002")?;
    let (mut oversized, _) = authenticated(&server, &alice).await?;
    oversized
        .send(Message::Text("x".repeat(262_145).into()))
        .await?;
    closed(&mut oversized, 1009)
        .await
        .context("advertised limit close 1009")?;
    eprintln!("[websocket-live] malformed, binary and oversized frames passed");

    issuer.set_grant_expiry(
        alice.session().credential(),
        Utc::now() + chrono::Duration::seconds(15),
    )?;
    let (mut refresh, _) = authenticated(&server, &alice).await?;
    open(
        &mut refresh,
        "reauth-signal",
        WebSocketOpenParameters::Signal(Default::default()),
        signal,
    )
    .await?;
    let challenge = until(&mut refresh, |frame| {
        matches!(frame, WebSocketServerFrame::ReauthRequired { .. })
    })
    .await?;
    let principal = alice
        .principal
        .as_ref()
        .context("accepted founding device")?;
    let new_grant =
        crate::scenarios::bridge_contracts::session_grant::issuer_key_forged_session_grant_jwt(
            principal.core_id.as_str(),
            principal.device_id.as_str(),
            server.service_id().as_str(),
        );
    issuer.bind_founding_device_grant(
        &new_grant,
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        principal.founding_authorize_event_id.as_str(),
        &principal.device_signing_key.verifying_key(),
    )?;
    let refreshed = server.client_with_founding_device_grant(principal, new_grant.clone())?;
    send(
        &mut refresh,
        &auth(&refreshed, &socket_url(&server)?, &challenge, &fresh_jti())?,
    )
    .await?;
    ensure!(
        matches!(
            next(&mut refresh).await?,
            WebSocketServerFrame::Welcome { .. }
        ),
        "same holder fresh grant reauth accepted"
    );
    issuer.revoke_grant(&new_grant)?;
    closed(&mut refresh, 1008).await?;
    eprintln!(
        "[websocket-live] TLS Upgrade negatives=3 auth_timeout=1 proof_replay=1 three_rails=1 selector_precedence=1 channel_isolation=1 durable_resume=2 binary_duplicate_oversize=3 reauth=1 current_grant_revoke=1"
    );
    Ok(())
}

pub async fn realm_head(
    client: &TestActorClient,
    realm: &str,
) -> Result<arkret_wire::CommitStreamHead> {
    Ok(client
        .sdk()
        .realm_authority_bundle(&arkret_wire::AuthorityBundleRequest {
            realm_id: arkret_wire::RealmId::new(realm)?,
            nonce: arkret_wire::Base64UrlString::new(fresh_jti()).map_err(anyhow::Error::msg)?,
        })
        .await?
        .realm_stream_head)
}

pub async fn advertised_websocket(
    server: &ArkretServer,
) -> Result<arkret_models_discovery::ServiceDescribe> {
    let description = server.sdk()?.describe().await?;
    description.validate()?;
    ensure!(
        description
            .supported_profiles
            .iter()
            .any(|profile| profile.as_str() == arkret_wire::ProfileId::BINDING_WEBSOCKET_V1)
    );
    ensure!(
        arkret_models_discovery::websocket_binding::websocket_operations_reachable(&description)
    );
    let Some(arkret_models_discovery::TransportBinding::Websocket {
        base_url,
        max_frame_bytes,
        max_channels,
    }) =
        arkret_models_discovery::websocket_binding::select_websocket_binding(&description, 262_144)
    else {
        bail!("complete canonical WS discovery required")
    };
    ensure!(base_url == &socket_url(server)? && *max_frame_bytes == 262_144 && *max_channels == 16);
    for operation in arkret_wire::WebSocketOperationId::ALL {
        let operation = arkret_wire::ServiceOperationId::from_wire(operation.as_str())
            .context("registered operation")?;
        ensure!(
            description.supports_operation_binding(operation, arkret_wire::BindingKind::HttpJson)
        );
    }
    Ok(description)
}

pub async fn run_production_discovery() -> Result<()> {
    let Some(database) = database("websocket-production")? else {
        return Ok(());
    };
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut env = rotation_station_env(&issuer);
    env.push(("SOLAND_DEVELOPMENT_MODE".to_owned(), "0".to_owned()));
    let refs = env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let server =
        ArkretServer::spawn_with_database_url("websocket-production", &database.connect_url, &refs)
            .await?;
    let description = advertised_websocket(&server).await?;
    ensure!(!description.development_mode);
    ensure!(
        !description
            .supported_profiles
            .iter()
            .any(|profile| profile.as_str() == "ak.profile.conformance_harness.v1")
    );
    let origin = server.base_url().origin().ascii_serialization();
    let mut socket = connect(&server, Some(&origin), WEBSOCKET_SUBPROTOCOL).await?;
    ensure!(matches!(
        next(&mut socket).await?,
        WebSocketServerFrame::Challenge { .. }
    ));
    socket.close(None).await?;
    eprintln!(
        "[websocket-live] production_mode=1 complete_discovery=1 canonical_tls_upgrade_challenge=1 harness_profile_absent=1 http_fallback_reachable=3"
    );
    Ok(())
}
