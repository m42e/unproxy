use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Arc, Mutex},
};

use tokio::sync::broadcast;
use tracing_subscriber::fmt::writer::MakeWriter;

const HISTORY_LIMIT: usize = 500;
const HISTORY_BYTE_LIMIT: usize = 1024 * 1024;
const LINE_BYTE_LIMIT: usize = 8 * 1024;
const REPLAY_LIMIT: usize = 64;
const EVENT_CAPACITY: usize = 256;

#[derive(Clone)]
pub(crate) struct LogStream(Arc<Mutex<LogStreamState>>);

struct LogStreamState {
    history: VecDeque<Arc<str>>,
    history_bytes: usize,
    events: broadcast::Sender<Arc<str>>,
}

impl LogStream {
    pub(crate) fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self(Arc::new(Mutex::new(LogStreamState {
            history: VecDeque::with_capacity(HISTORY_LIMIT),
            history_bytes: 0,
            events,
        })))
    }

    pub(crate) fn subscribe_with_history(&self) -> (Vec<Arc<str>>, broadcast::Receiver<Arc<str>>) {
        let state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let receiver = state.events.subscribe();
        (
            state
                .history
                .iter()
                .rev()
                .take(REPLAY_LIMIT)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            receiver,
        )
    }

    fn publish(&self, line: String) {
        let line = if line.len() > LINE_BYTE_LIMIT {
            let mut boundary = LINE_BYTE_LIMIT;
            while !line.is_char_boundary(boundary) {
                boundary -= 1;
            }
            line[..boundary].to_owned()
        } else {
            line
        };
        let line: Arc<str> = Arc::from(line);
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while state.history.len() >= HISTORY_LIMIT
            || state.history_bytes + line.len() > HISTORY_BYTE_LIMIT
        {
            let Some(oldest) = state.history.pop_front() else {
                break;
            };
            state.history_bytes -= oldest.len();
        }
        state.history_bytes += line.len();
        state.history.push_back(line.clone());
        let _ = state.events.send(line);
    }
}

pub(crate) struct CapturedWriter<M> {
    inner: M,
    stream: LogStream,
}

impl<M> CapturedWriter<M> {
    pub(crate) fn new(inner: M, stream: LogStream) -> Self {
        Self { inner, stream }
    }
}

impl<'a, M> MakeWriter<'a> for CapturedWriter<M>
where
    M: MakeWriter<'a>,
{
    type Writer = CapturedWriterGuard<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedWriterGuard {
            inner: self.inner.make_writer(),
            stream: self.stream.clone(),
            pending: Vec::new(),
            discarding_line: false,
        }
    }
}

pub struct CapturedWriterGuard<W> {
    inner: W,
    stream: LogStream,
    pending: Vec<u8>,
    discarding_line: bool,
}

impl<W> CapturedWriterGuard<W> {
    fn capture(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            if let Some(newline) = rest.iter().position(|byte| *byte == b'\n') {
                let segment = &rest[..newline];
                self.append_line_bytes(segment);
                self.publish_pending();
                rest = &rest[newline + 1..];
            } else {
                self.append_line_bytes(rest);
                break;
            }
        }
    }

    fn append_line_bytes(&mut self, bytes: &[u8]) {
        if self.discarding_line {
            return;
        }
        let remaining = LINE_BYTE_LIMIT.saturating_sub(self.pending.len());
        let retained = bytes.len().min(remaining);
        self.pending.extend_from_slice(&bytes[..retained]);
        if retained < bytes.len() {
            self.discarding_line = true;
        }
    }

    fn publish_pending(&mut self) {
        if self.pending.last() == Some(&b'\r') {
            self.pending.pop();
        }
        let mut line = String::from_utf8_lossy(&self.pending).into_owned();
        if line.len() > LINE_BYTE_LIMIT {
            let mut boundary = LINE_BYTE_LIMIT;
            while !line.is_char_boundary(boundary) {
                boundary -= 1;
            }
            line.truncate(boundary);
        }
        self.stream.publish(line);
        self.pending.clear();
        self.discarding_line = false;
    }
}

impl<W: Write> Write for CapturedWriterGuard<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.capture(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W> Drop for CapturedWriterGuard<W> {
    fn drop(&mut self) {
        if !self.pending.is_empty() {
            self.publish_pending();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_line_and_pending_buffer_are_capped() {
        let stream = LogStream::new();
        let mut writer = CapturedWriter::new(io::sink, stream.clone()).make_writer();
        writer
            .write_all(&vec![b'x'; LINE_BYTE_LIMIT * 100])
            .unwrap();
        assert!(writer.pending.len() <= LINE_BYTE_LIMIT);
        writer.write_all(b"\nvalid\n").unwrap();
        drop(writer);

        let (history, _) = stream.subscribe_with_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].len(), LINE_BYTE_LIMIT);
        assert_eq!(&*history[1], "valid");
    }

    #[test]
    fn history_has_a_total_byte_budget_and_replay_limit() {
        let stream = LogStream::new();
        let line = "x".repeat(LINE_BYTE_LIMIT);
        for _ in 0..HISTORY_LIMIT {
            stream.publish(line.clone());
        }

        let (history, _) = stream.subscribe_with_history();
        let state = stream.0.lock().unwrap();
        assert_eq!(state.history_bytes, HISTORY_BYTE_LIMIT);
        assert_eq!(history.len(), REPLAY_LIMIT);
        assert!(
            history.iter().map(|line| line.len()).sum::<usize>() <= REPLAY_LIMIT * LINE_BYTE_LIMIT
        );
    }

    #[test]
    fn subscribers_share_immutable_history_records() {
        let stream = LogStream::new();
        stream.publish("shared record".into());
        let (first, _) = stream.subscribe_with_history();
        let (second, _) = stream.subscribe_with_history();
        assert!(Arc::ptr_eq(&first[0], &second[0]));
    }

    #[test]
    fn publish_enforces_line_limit_for_direct_callers() {
        let stream = LogStream::new();
        let (_, mut receiver) = stream.subscribe_with_history();
        stream.publish("x".repeat(LINE_BYTE_LIMIT * 100));

        let (history, _) = stream.subscribe_with_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].len(), LINE_BYTE_LIMIT);
        let event = receiver.try_recv().unwrap();
        assert_eq!(event.len(), LINE_BYTE_LIMIT);
    }
}
