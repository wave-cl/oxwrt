use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

const RING_CAP: usize = 1024;
const BROADCAST_CAP: usize = 256;

#[derive(Debug, Clone)]
pub struct LogLine {
    pub service: String,
    pub line: String,
}

#[derive(Clone)]
pub struct Logd {
    inner: Arc<Inner>,
}

struct Inner {
    buffer: Mutex<VecDeque<LogLine>>,
    tx: broadcast::Sender<LogLine>,
}

impl Logd {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            inner: Arc::new(Inner {
                buffer: Mutex::new(VecDeque::with_capacity(RING_CAP)),
                tx,
            }),
        }
    }

    pub fn push(&self, service: &str, line: String) {
        let entry = LogLine {
            service: service.to_string(),
            line,
        };
        {
            let mut buf = self.inner.buffer.lock().unwrap();
            if buf.len() == RING_CAP {
                buf.pop_front();
            }
            buf.push_back(entry.clone());
        }
        let _ = self.inner.tx.send(entry);
    }

    pub fn tail(&self, service: &str, limit: usize) -> Vec<LogLine> {
        let buf = self.inner.buffer.lock().unwrap();
        buf.iter()
            .filter(|l| l.service == service)
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LogLine> {
        self.inner.tx.subscribe()
    }
}

impl Default for Logd {
    fn default() -> Self {
        Self::new()
    }
}
