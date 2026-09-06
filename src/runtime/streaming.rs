use super::*;

impl GatewayRuntime {
    pub fn open_sse_stream(
        &self,
        request_context: &RequestContext,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.session_store.open_sse_stream(
            request_context.session_id.as_deref(),
            request_context.resume_cursor.as_ref(),
        )
    }

    pub fn stream_protocol_response(
        &self,
        session_id: &str,
        protocol_response: &ProtocolResponse,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.session_store
            .stream_protocol_response(session_id, protocol_response)
    }

    pub fn stream_protocol_response_with_pending(
        &self,
        session_id: &str,
        protocol_response: &ProtocolResponse,
        pending_notifications: &[String],
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.session_store.stream_protocol_response_with_pending(
            session_id,
            protocol_response,
            pending_notifications,
        )
    }

    pub fn stream_raw_message(
        &self,
        session_id: &str,
        message_json: &str,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.session_store
            .stream_raw_message(session_id, message_json)
    }

    /// Stream a server-push delivery, tagging the SSE event id with the
    /// delivery's coordinator-KV backlog id so a later reconnect can
    /// ack/prune the backlog row. When `delivery_id` is empty
    /// (e.g. a single-node message produced before a store), falls back to
    /// the untagged path.
    pub fn stream_delivery_message(
        &self,
        session_id: &str,
        message_json: &str,
        delivery_id: &str,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.session_store
            .stream_message(session_id, message_json, delivery_id)
    }

    /// Prune the backlog rows a reconnecting client has acknowledged by
    /// echoing a delivery-tagged `Last-Event-Id`: the exact acked row plus
    /// every row with a lower sequence (deliveries stream in sequence order,
    /// so acknowledging one acknowledges its prefix). The rows left after
    /// this are exactly the suffix the client missed, which the reconnect
    /// drain then replays in order. The prefix prune is epoch-guarded in the
    /// store, so a stale ack can never drop an unseen result. Idempotent and
    /// best-effort.
    pub fn ack_deliveries_from_cursor(&self, session_id: &str, last_event_id: &str) {
        if let Some(delivery_id) = session_store::delivery_id_from_event_id(last_event_id) {
            let _ = self
                .pipeline_store
                .ack_prune_deliveries(session_id, delivery_id);
        }
    }
}
