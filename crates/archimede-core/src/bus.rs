use crate::event::Event;
use flume::{Receiver, Sender};

/// Lightweight typed event bus (multiple producers, multiple consumers).
#[derive(Clone)]
pub struct EventBus {
    tx: Sender<Event>,
}

impl EventBus {
    pub fn unbounded() -> (Self, Receiver<Event>) {
        let (tx, rx) = flume::unbounded();
        (Self { tx }, rx)
    }

    pub fn publish(&self, event: Event) -> Result<(), flume::SendError<Event>> {
        self.tx.send(event)
    }

    pub fn try_publish(&self, event: Event) -> Result<(), flume::TrySendError<Event>> {
        self.tx.try_send(event)
    }

    pub fn sender(&self) -> Sender<Event> {
        self.tx.clone()
    }
}
