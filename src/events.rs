//! placeholder
pub struct IncomingTracker;
impl IncomingTracker {
    pub async fn on_incoming(
        &self,
        _a: &std::sync::Arc<crate::accounts::Account>,
        _m: &grammers_client::message::Message,
    ) {
    }
}
