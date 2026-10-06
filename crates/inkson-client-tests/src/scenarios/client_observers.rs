use anyhow::Result;
use cotest::scenarios::mls_lifecycle_live::Member;

use crate::conformance::account_blocklist_projection as observer;

struct ClientObserver;
#[async_trait::async_trait(?Send)]
impl cotest::scenarios::direct_conversation_founding_live::DirectClientObserver for ClientObserver {
    async fn block_direct_peer(&self, holder: &Member, peer: &Member) -> Result<()> {
        observer::block_direct_peer(holder, peer).await
    }
    async fn unblock_direct_peer(&self, holder: &Member) -> Result<()> {
        observer::unblock_direct_peer(holder).await
    }
    async fn observe_dm_retained_receipt(
        &self,
        sender: &Member,
        holder: &Member,
        realm: &arkret_wire::RealmId,
        strand: &str,
        accepted_group: &arkret_wire::EventId,
        sender_group: &arkret::ArkretMlsGroup,
        holder_group: &arkret::ArkretMlsGroup,
        message_id: &arkret_wire::EventId,
        latest_cursor: &arkret_wire::EventId,
    ) -> Result<()> {
        observer::observe_dm_retained_receipt(
            sender,
            holder,
            realm,
            strand,
            accepted_group,
            sender_group,
            holder_group,
            message_id,
            latest_cursor,
        )
        .await
    }
}
#[async_trait::async_trait(?Send)]
impl cotest::scenarios::mls_lifecycle_live::MlsClientObserver for ClientObserver {
    async fn observe_ordinary_call_invite(
        &self,
        sender: &Member,
        holder: &Member,
        station: &cotest::harness::ArkretServer,
        realm: &arkret_wire::RealmId,
        accepted_group: &arkret_wire::EventId,
        sender_group: &mut arkret::ArkretMlsGroup,
        holder_group: &arkret::ArkretMlsGroup,
        observe_receipt: bool,
    ) -> Result<()> {
        observer::observe_ordinary_call_invite(
            sender,
            holder,
            station,
            realm,
            accepted_group,
            sender_group,
            holder_group,
            observe_receipt,
        )
        .await
    }
}
pub async fn blocklist_dm_retained_receipt_live() -> Result<()> {
    cotest::scenarios::direct_conversation_founding_live::run_with_client_observer(
        &ClientObserver,
        false,
    )
    .await
}
pub async fn blocklist_case5_dm_history_and_contact_terminal_live() -> Result<()> {
    cotest::scenarios::direct_conversation_founding_live::run_with_client_observer(
        &ClientObserver,
        true,
    )
    .await
}
pub async fn blocklist_contact_first_dm_pending_request_live() -> Result<()> {
    observer::contact_and_first_dm_pending_request_live().await
}
pub async fn run_blocklist_call_invite_live() -> Result<()> {
    cotest::scenarios::mls_lifecycle_live::run_with_blocklist_observer(Some(&ClientObserver), false)
        .await
}
pub async fn run_blocklist_automatic_receipt_live() -> Result<()> {
    cotest::scenarios::mls_lifecycle_live::run_with_blocklist_observer(Some(&ClientObserver), true)
        .await
}
