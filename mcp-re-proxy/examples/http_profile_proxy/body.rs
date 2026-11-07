//! Reading the JSON-RPC body a request carries.

/// Remove the top-level `_meta` object (carrying the proxy-owned request evidence
/// block) so the forwarded body is clean MCP JSON-RPC. Non-object bodies pass
/// through unchanged (the inner would reject them anyway).
pub(super) fn strip_top_level_meta(body: &[u8]) -> Vec<u8> {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("_meta");
            }
            serde_json::to_vec(&v).unwrap_or_else(|_| body.to_vec())
        }
        Err(_) => body.to_vec(),
    }
}

/// A JSON-RPC NOTIFICATION: a message with a `method` and NO `id` (JSON-RPC 2.0 §4.1).
/// The same classification the production serving path performs.
pub(super) fn is_notification(body: &[u8]) -> bool {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => v.get("method").is_some() && v.get("id").is_none(),
        Err(_) => false,
    }
}
