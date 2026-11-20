//! The JSON event format of the log sinks.
//!
//! [`JsonEvents`] writes the bytes of `tracing_subscriber`'s JSON format
//! with the target and the thread names on: `timestamp`, `level`, `fields`,
//! `target` and `threadName`, in that order. It serialises the line into
//! one reused buffer, hands it to the sink's writer in one piece, and
//! formats the date and the time of day once a second per thread. An event
//! in a span, an event with `log.*` fields (the `log` crate's metadata) and
//! a time outside the years 1970 to 9999 go to `tracing_subscriber`'s own
//! formatter, which writes the span keys and the `log` metadata.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::ser::{Serialize, SerializeMap, Serializer};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::{Format, Json, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// `YYYY-MM-DDTHH:MM:SS.ffffffZ`, the text of `tracing_subscriber`'s
/// `SystemTime` timer.
const TIMESTAMP_LEN: usize = 27;
/// The part of a timestamp up to the fraction: `YYYY-MM-DDTHH:MM:SS.`.
const SECOND_LEN: usize = 20;
/// The last second after the epoch whose year has four digits
/// (9999-12-31T23:59:59Z).
const LAST_FOUR_DIGIT_YEAR_SECOND: u64 = 253_402_300_799;

thread_local! {
    /// The line being serialised.
    static LINE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// The second the cached text belongs to, and its text up to the
    /// fraction.
    static SECOND: Cell<Option<(u64, [u8; SECOND_LEN])>> = const { Cell::new(None) };
}

/// The JSON event format; see the module docs.
pub(crate) struct JsonEvents {
    stock: Format<Json>,
}

impl JsonEvents {
    pub(crate) fn new() -> Self {
        Self {
            stock: Format::default()
                .json()
                .with_target(true)
                .with_thread_names(true),
        }
    }
}

impl<S, N> FormatEvent<S, N> for JsonEvents
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'w> FormatFields<'w> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let in_span = event
            .parent()
            .and_then(|id| ctx.span(id))
            .or_else(|| ctx.lookup_current())
            .is_some();
        if in_span || has_log_fields(event) {
            return self.stock.format_event(ctx, writer, event);
        }
        let Some(timestamp) = timestamp(SystemTime::now()) else {
            return self.stock.format_event(ctx, writer, event);
        };
        let timestamp = std::str::from_utf8(&timestamp).map_err(|_| fmt::Error)?;
        LINE.with(|line| match line.try_borrow_mut() {
            Ok(mut line) => write_line(&mut line, &mut writer, timestamp, event),
            // An event formatted while this thread formats another one.
            Err(_) => write_line(&mut Vec::new(), &mut writer, timestamp, event),
        })
    }
}

/// Whether `event` has a field under `log.`, as an event from the `log`
/// crate does.
fn has_log_fields(event: &Event<'_>) -> bool {
    event
        .metadata()
        .fields()
        .iter()
        .any(|field| field.name().starts_with("log."))
}

fn write_line(
    line: &mut Vec<u8>,
    writer: &mut Writer<'_>,
    timestamp: &str,
    event: &Event<'_>,
) -> fmt::Result {
    line.clear();
    serialize_line(line, timestamp, event).map_err(|_| fmt::Error)?;
    line.push(b'\n');
    writer.write_str(std::str::from_utf8(line).map_err(|_| fmt::Error)?)
}

fn serialize_line(
    line: &mut Vec<u8>,
    timestamp: &str,
    event: &Event<'_>,
) -> serde_json::Result<()> {
    let meta = event.metadata();
    let mut serializer = serde_json::Serializer::new(line);
    let mut map = serializer.serialize_map(None)?;
    map.serialize_entry("timestamp", timestamp)?;
    map.serialize_entry("level", meta.level().as_str())?;
    map.serialize_entry("fields", &EventFields(event))?;
    map.serialize_entry("target", meta.target())?;
    let thread = std::thread::current();
    match thread.name() {
        Some(name) => map.serialize_entry("threadName", name)?,
        None => map.serialize_entry("threadName", &format!("{:?}", thread.id()))?,
    }
    map.end()
}

/// The event's fields as one JSON object, each value as `tracing-serde`
/// records it.
struct EventFields<'a, 'b>(&'a Event<'b>);

impl Serialize for EventFields<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let map = serializer.serialize_map(Some(self.0.fields().count()))?;
        let mut visitor = FieldVisitor { map, state: Ok(()) };
        self.0.record(&mut visitor);
        visitor.state?;
        visitor.map.end()
    }
}

/// Records each field as a map entry; the first error stops the rest.
struct FieldVisitor<M: SerializeMap> {
    map: M,
    state: Result<(), M::Error>,
}

impl<M: SerializeMap> FieldVisitor<M> {
    fn entry<T: Serialize + ?Sized>(&mut self, field: &Field, value: &T) {
        if self.state.is_ok() {
            self.state = self.map.serialize_entry(field.name(), value);
        }
    }
}

impl<M: SerializeMap> Visit for FieldVisitor<M> {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.entry(field, &value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.entry(field, &format_args!("{value:?}"));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.entry(field, &value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.entry(field, &value);
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.entry(field, &value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.entry(field, value);
    }
}

/// `now` as `YYYY-MM-DDTHH:MM:SS.ffffffZ`; `None` before the epoch and
/// after the year 9999.
fn timestamp(now: SystemTime) -> Option<[u8; TIMESTAMP_LEN]> {
    let since_epoch = now.duration_since(UNIX_EPOCH).ok()?;
    let second = since_epoch.as_secs();
    if second > LAST_FOUR_DIGIT_YEAR_SECOND {
        return None;
    }
    let prefix = SECOND.with(|cached| match cached.get() {
        Some((cached_second, prefix)) if cached_second == second => Some(prefix),
        _ => {
            let prefix = second_text(second)?;
            cached.set(Some((second, prefix)));
            Some(prefix)
        }
    })?;
    let mut text = [0u8; TIMESTAMP_LEN];
    text[..SECOND_LEN].copy_from_slice(&prefix);
    let mut micros = since_epoch.subsec_micros();
    for digit in text[SECOND_LEN..TIMESTAMP_LEN - 1].iter_mut().rev() {
        *digit = b'0' + (micros % 10) as u8;
        micros /= 10;
    }
    text[TIMESTAMP_LEN - 1] = b'Z';
    Some(text)
}

/// The date and the time of day of `second` after the epoch, up to the
/// fraction.
fn second_text(second: u64) -> Option<[u8; SECOND_LEN]> {
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(i64::try_from(second).ok()?, 0)?;
    time.format("%Y-%m-%dT%H:%M:%S.")
        .to_string()
        .as_bytes()
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl Captured {
        /// The captured lines, each timestamp checked for its shape and
        /// blanked.
        fn lines(&self) -> Vec<String> {
            const PREFIX: &str = "{\"timestamp\":\"";
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| {
                    let rest = line.strip_prefix(PREFIX).expect(line);
                    let (timestamp, rest) = rest.split_at(TIMESTAMP_LEN);
                    let shape: String = timestamp
                        .chars()
                        .map(|c| if c.is_ascii_digit() { 'd' } else { c })
                        .collect();
                    assert_eq!(shape, "dddd-dd-ddTdd:dd:dd.ddddddZ", "{line}");
                    format!("{PREFIX}T{rest}")
                })
                .collect()
        }
    }

    #[derive(Debug)]
    struct Failure;

    impl fmt::Display for Failure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the operation failed")
        }
    }

    impl std::error::Error for Failure {}

    /// Every kind of field value, escapes, levels, targets, spans, and a
    /// field named like the `log` crate's metadata.
    fn emit_events() {
        tracing::info!("a message");
        tracing::info!(
            request_id = "0b1d2c3e",
            upstream_request_id = "",
            count = 3u64,
            delta = -2i64,
            ratio = 0.5,
            not_a_number = f64::NAN,
            flag = true,
            shown = %"display",
            debugged = ?Some("x"),
            "request received"
        );
        tracing::warn!(
            text = "quote \" backslash \\ newline \n tab \t control \u{1} non-ascii é 😀",
            "escapes \"in\" the message"
        );
        tracing::error!(
            error = &Failure as &(dyn std::error::Error + 'static),
            "an error"
        );
        tracing::info!(
            big = 1u128 << 100,
            small = -(1i128 << 100),
            bytes = &b"\x00\xff"[..]
        );
        tracing::info!(target: "custom::target", "another target");
        tracing::info!(only = 1);
        tracing::debug!("debug");
        tracing::trace!("trace");
        tracing::info!(log.target = "looks::like::log", "a log-style field");
        let span = tracing::info_span!("outer", key = "value", n = 2);
        span.in_scope(|| {
            tracing::info!(inner = 1, "in a span");
            tracing::info!(parent: None, "a root event in a span");
        });
        tracing::info!(parent: &span, "an explicit parent");
        tracing::info!(parent: None, "a root event");
    }

    #[test]
    fn the_lines_are_the_bytes_of_the_stock_json_format() {
        let stock = Captured::default();
        let fast = Captured::default();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(stock.clone())
                        .with_target(true)
                        .with_thread_names(true),
                )
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(fast.clone())
                        .event_format(JsonEvents::new()),
                ),
        );
        tracing::dispatcher::with_default(&dispatch, emit_events);
        // A thread without a name is named by its id.
        let unnamed = dispatch.clone();
        std::thread::Builder::new()
            .spawn(move || tracing::dispatcher::with_default(&unnamed, emit_events))
            .unwrap()
            .join()
            .unwrap();
        let (stock, fast) = (stock.lines(), fast.lines());
        assert_eq!(stock.len(), 2 * 14, "{stock:#?}");
        assert_eq!(fast, stock);
    }

    #[test]
    fn the_timestamp_is_rfc_3339_in_microseconds() {
        for (second, nanos) in [
            (0, 0),
            (0, 999_999_999),
            (951_782_400, 123_456_789),
            (951_868_799, 1_000),
            (1_763_521_972, 214_605_999),
            (1_763_521_972, 214_606_000),
            (1_763_521_973, 7_000),
            (LAST_FOUR_DIGIT_YEAR_SECOND, 999_999_000),
        ] {
            let at = UNIX_EPOCH + Duration::new(second, nanos);
            let expected = chrono::DateTime::<chrono::Utc>::from(at)
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let text = timestamp(at).expect("in range");
            assert_eq!(std::str::from_utf8(&text).unwrap(), expected);
        }
        assert!(timestamp(UNIX_EPOCH - Duration::from_secs(1)).is_none());
        let past_9999 = UNIX_EPOCH + Duration::from_secs(LAST_FOUR_DIGIT_YEAR_SECOND + 1);
        assert!(timestamp(past_9999).is_none());
    }
}
