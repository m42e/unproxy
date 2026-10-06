use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Arc, Mutex},
};

use tokio::sync::broadcast;
use tracing_subscriber::fmt::writer::MakeWriter;

const HISTORY_LIMIT: usize = 500;
const EVENT_CAPACITY: usize = 256;

#[derive(Clone)]
pub(crate) struct LogStream(Arc<Mutex<LogStreamState>>);

struct LogStreamState {
    history: VecDeque<String>,
    events: broadcast::Sender<String>,
}

impl LogStream {
    pub(crate) fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self(Arc::new(Mutex::new(LogStreamState {
            history: VecDeque::with_capacity(HISTORY_LIMIT),
            events,
        })))
    }

    pub(crate) fn subscribe_with_history(&self) -> (Vec<String>, broadcast::Receiver<String>) {
        let state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let receiver = state.events.subscribe();
        (state.history.iter().cloned().collect(), receiver)
    }

    fn publish(&self, line: String) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.history.len() == HISTORY_LIMIT {
            state.history.pop_front();
        }
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
        }
    }
}

pub struct CapturedWriterGuard<W> {
    inner: W,
    stream: LogStream,
    pending: Vec<u8>,
}

impl<W: Write> Write for CapturedWriterGuard<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.pending.extend_from_slice(&bytes[..written]);
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<_> = self.pending.drain(..=end).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.stream
                .publish(String::from_utf8_lossy(&line).into_owned());
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W> Drop for CapturedWriterGuard<W> {
    fn drop(&mut self) {
        if self.pending.last() == Some(&b'\r') {
            self.pending.pop();
        }
        if !self.pending.is_empty() {
            self.stream
                .publish(String::from_utf8_lossy(&self.pending).into_owned());
        }
    }
}
