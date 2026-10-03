//! Native macOS notifications for Kerberos internal-network availability.
//!
//! Create a [`NotificationAdapter`] on the daemon's main thread and call
//! [`NotificationAdapter::pump`] periodically from its event loop. Distributed
//! callbacks are delivered on the main thread's run loop.

use std::marker::PhantomData;
#[cfg(target_os = "macos")]
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::mpsc::{self, UnboundedReceiver};

#[cfg(test)]
mod portable_tests {
    #[cfg(not(target_os = "macos"))]
    use super::*;

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn unsupported_platform_adapter_closes_receiver_cleanly() {
        let mut adapter =
            NotificationAdapter::start_with_names("test.available", "test.down").unwrap();
        adapter.pump();
        assert_eq!(
            adapter.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
        assert_eq!(adapter.recv().await, None);
    }
}

/// A native observation of the organization's Kerberos internal network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkEvent {
    Available,
    Unavailable,
}

/// Owns the notification receiver and native observer registration.
///
/// This type is deliberately `!Send`: on macOS it must be created, pumped and
/// dropped on the process main thread.
pub struct NotificationAdapter {
    events: UnboundedReceiver<NetworkEvent>,
    #[cfg(target_os = "macos")]
    registration: macos::Registration,
    _main_thread_only: PhantomData<std::rc::Rc<()>>,
}

impl NotificationAdapter {
    /// Register observers for the Kerberos internal-network state notifications.
    pub fn start() -> std::io::Result<Self> {
        Self::start_with_names(AVAILABLE_NOTIFICATION, UNAVAILABLE_NOTIFICATION)
    }

    /// Wait for the next queued notification.
    pub async fn recv(&mut self) -> Option<NetworkEvent> {
        self.events.recv().await
    }

    /// Pump the macOS default run-loop mode for up to 100 ms.
    ///
    /// Call this periodically from the same main thread that called [`Self::start`].
    /// It is a no-op on other platforms.
    pub fn pump(&mut self) {
        #[cfg(target_os = "macos")]
        self.registration.pump();
    }

    /// Try to receive an event without waiting. Useful for synchronous native
    /// lifecycle probes and event loops that poll after each run-loop pump.
    pub fn try_recv(&mut self) -> Result<NetworkEvent, tokio::sync::mpsc::error::TryRecvError> {
        self.events.try_recv()
    }

    /// Register named notifications. This is public for platform integration
    /// tests that must use private names; normal applications should use
    /// [`start`](Self::start).
    #[doc(hidden)]
    pub fn start_with_names(available: &str, unavailable: &str) -> std::io::Result<Self> {
        let (sender, events) = mpsc::unbounded_channel();
        #[cfg(target_os = "macos")]
        let registration = macos::Registration::new(sender, available, unavailable)?;
        #[cfg(not(target_os = "macos"))]
        let _ = (sender, available, unavailable);
        Ok(Self {
            events,
            #[cfg(target_os = "macos")]
            registration,
            _main_thread_only: PhantomData,
        })
    }
}

/// Kerberos SSO distributed notification names used by macOS.
pub const AVAILABLE_NOTIFICATION: &str = "com.apple.KerberosPlugin.InternalNetworkAvailable";
pub const UNAVAILABLE_NOTIFICATION: &str = "com.apple.KerberosPlugin.InternalNetworkNotAvailable";

/// Suppresses duplicate native states while allowing a failed PAC restoration
/// to be retried by the next Available notification. Manual policy controls
/// intentionally do not interact with this state.
#[derive(Clone, Debug)]
pub struct TransitionState {
    available: bool,
    retry_available: bool,
}

impl Default for TransitionState {
    fn default() -> Self {
        Self::new()
    }
}

impl TransitionState {
    /// The daemon's initial assumption is that the internal network is up.
    pub fn new() -> Self {
        Self {
            available: true,
            retry_available: false,
        }
    }

    /// Return a state only when it should trigger a policy operation.
    pub fn observe(&mut self, event: NetworkEvent) -> Option<NetworkEvent> {
        match event {
            NetworkEvent::Available if !self.available || self.retry_available => {
                self.available = true;
                self.retry_available = false;
                Some(NetworkEvent::Available)
            }
            NetworkEvent::Unavailable if self.available => {
                self.available = false;
                self.retry_available = false;
                Some(NetworkEvent::Unavailable)
            }
            _ => None,
        }
    }

    /// Record an automatic policy operation's result. A failed restore retries
    /// on the next Available notification, even if availability did not change.
    pub fn complete(&mut self, event: NetworkEvent, succeeded: bool) {
        if event == NetworkEvent::Available {
            self.retry_available = !succeeded;
        }
    }

    /// Last native availability observation; manual signals never change it.
    pub fn is_available(&self) -> bool {
        self.available
    }
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_suppresses_available_and_duplicate_unavailable() {
        let mut state = TransitionState::new();
        assert_eq!(state.observe(NetworkEvent::Available), None);
        assert_eq!(
            state.observe(NetworkEvent::Unavailable),
            Some(NetworkEvent::Unavailable)
        );
        assert_eq!(state.observe(NetworkEvent::Unavailable), None);
    }

    #[test]
    fn failed_restore_retries_on_the_next_available_event() {
        let mut state = TransitionState::new();
        assert_eq!(
            state.observe(NetworkEvent::Unavailable),
            Some(NetworkEvent::Unavailable)
        );
        state.complete(NetworkEvent::Unavailable, true);
        assert_eq!(
            state.observe(NetworkEvent::Available),
            Some(NetworkEvent::Available)
        );
        state.complete(NetworkEvent::Available, false);
        assert_eq!(
            state.observe(NetworkEvent::Available),
            Some(NetworkEvent::Available)
        );
        state.complete(NetworkEvent::Available, true);
        assert_eq!(state.observe(NetworkEvent::Available), None);
    }

    #[test]
    fn manual_operations_do_not_change_native_observation() {
        let mut state = TransitionState::new();
        assert!(state.is_available());
        assert_eq!(state.observe(NetworkEvent::Available), None);
    }
}
