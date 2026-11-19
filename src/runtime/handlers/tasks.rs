use crate::protocol::v_2026_07_28::dispatch::tasks::wire_task;
use crate::protocol::v_2026_07_28::extensions::tasks::wire::TaskStatusNotification;

/// The SEP-2663 `notifications/tasks` status ping for `task`: the bare
/// method with the flat task state (`ttlMs` / `pollIntervalMs`). The
/// terminal `result` / `error` are surfaced by `tasks/get`, so the
/// notification carries the status, not the result. A
/// `subscriptions/listen` subscriber that names the tasks target
/// receives it.
pub(crate) fn task_status_notification(task: &crate::protocol::Task) -> TaskStatusNotification {
    TaskStatusNotification::new(wire_task(task))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_ping_is_notifications_tasks_with_the_flat_task() {
        let task = crate::protocol::Task {
            task_id: "t-1".to_owned(),
            status: crate::protocol::TaskStatus::InputRequired,
            status_message: Some("awaiting input".to_owned()),
            created_at: "2026-07-28T00:00:00Z".to_owned(),
            last_updated_at: "2026-07-28T00:00:01Z".to_owned(),
            ttl: Some(60_000),
            poll_interval: Some(500),
        };
        let value = serde_json::to_value(task_status_notification(&task)).unwrap();
        assert_eq!(value["method"], "notifications/tasks");
        assert_eq!(value["params"]["taskId"], "t-1");
        assert_eq!(value["params"]["status"], "input_required");
        assert_eq!(value["params"]["ttlMs"], 60_000);
        assert_eq!(value["params"]["pollIntervalMs"], 500);
        assert!(value["params"].get("_meta").is_none());
        assert!(value["params"].get("result").is_none());
    }
}
