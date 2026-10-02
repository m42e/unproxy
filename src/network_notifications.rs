//! Native macOS notifications for Kerberos internal-network availability.
//!
//! Create a [`NotificationAdapter`] on the daemon's main thread and call
//! [`NotificationAdapter::pump`] periodically from its event loop. Distributed
//! callbacks are delivered on the main thread's run loop.

use std::marker::PhantomData;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

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
    /// Call this periodically from the same main thread that called [`start`].
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
mod macos {
    use super::*;
    use std::{ffi::c_void, io, ptr};

    type Ref = *const c_void;
    type MutableRef = *mut c_void;
    type ObserverCallBack = unsafe extern "C" fn(Ref, *mut c_void, Ref, Ref, Ref);

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFNotificationCenterGetDistributedCenter() -> MutableRef;
        fn CFNotificationCenterAddObserver(
            center: MutableRef,
            observer: Ref,
            callback: ObserverCallBack,
            name: Ref,
            object: Ref,
            suspension_behavior: isize,
        );
        fn CFNotificationCenterRemoveObserver(
            center: MutableRef,
            observer: Ref,
            name: Ref,
            object: Ref,
        );
        fn CFStringCreateWithCString(allocator: Ref, text: *const i8, encoding: u32) -> MutableRef;
        fn CFRelease(value: Ref);
        fn CFRunLoopRunInMode(mode: Ref, seconds: f64, return_after_source: bool) -> i32;
        static kCFRunLoopDefaultMode: Ref;
    }

    const UTF8: u32 = 0x08000100;
    const DELIVER_IMMEDIATELY: isize = 4;

    struct CallbackContext {
        sender: UnboundedSender<NetworkEvent>,
        event: NetworkEvent,
    }

    pub(super) struct Registration {
        center: MutableRef,
        available_name: MutableRef,
        unavailable_name: MutableRef,
        available_context: Box<CallbackContext>,
        unavailable_context: Box<CallbackContext>,
    }

    unsafe extern "C" fn callback(_: Ref, observer: *mut c_void, _: Ref, _: Ref, _: Ref) {
        // The observer pointer is the boxed context, kept alive until removal.
        let context = unsafe { &*(observer.cast::<CallbackContext>()) };
        let _ = context.sender.send(context.event);
    }

    unsafe fn cf_string(text: &str) -> io::Result<MutableRef> {
        let c = std::ffi::CString::new(text).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "notification name contains NUL",
            )
        })?;
        let value = unsafe { CFStringCreateWithCString(ptr::null(), c.as_ptr(), UTF8) };
        if value.is_null() {
            Err(io::Error::other(
                "CoreFoundation could not create notification name",
            ))
        } else {
            Ok(value)
        }
    }

    impl Registration {
        pub(super) fn new(
            sender: UnboundedSender<NetworkEvent>,
            available: &str,
            unavailable: &str,
        ) -> io::Result<Self> {
            unsafe {
                let center = CFNotificationCenterGetDistributedCenter();
                if center.is_null() {
                    return Err(io::Error::other(
                        "distributed notification center unavailable",
                    ));
                }
                let available_name = cf_string(available)?;
                let unavailable_name = match cf_string(unavailable) {
                    Ok(name) => name,
                    Err(error) => {
                        CFRelease(available_name);
                        return Err(error);
                    }
                };
                let mut registration = Self {
                    center,
                    available_name,
                    unavailable_name,
                    available_context: Box::new(CallbackContext {
                        sender: sender.clone(),
                        event: NetworkEvent::Available,
                    }),
                    unavailable_context: Box::new(CallbackContext {
                        sender,
                        event: NetworkEvent::Unavailable,
                    }),
                };
                CFNotificationCenterAddObserver(
                    center,
                    (&mut *registration.available_context as *mut CallbackContext).cast::<c_void>()
                        as Ref,
                    callback,
                    registration.available_name,
                    ptr::null(),
                    DELIVER_IMMEDIATELY,
                );
                CFNotificationCenterAddObserver(
                    center,
                    (&mut *registration.unavailable_context as *mut CallbackContext)
                        .cast::<c_void>() as Ref,
                    callback,
                    registration.unavailable_name,
                    ptr::null(),
                    DELIVER_IMMEDIATELY,
                );
                Ok(registration)
            }
        }

        pub(super) fn pump(&mut self) {
            unsafe {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, true);
            }
        }
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            unsafe {
                CFNotificationCenterRemoveObserver(
                    self.center,
                    (&mut *self.available_context as *mut CallbackContext).cast::<c_void>() as Ref,
                    self.available_name,
                    ptr::null(),
                );
                CFNotificationCenterRemoveObserver(
                    self.center,
                    (&mut *self.unavailable_context as *mut CallbackContext).cast::<c_void>()
                        as Ref,
                    self.unavailable_name,
                    ptr::null(),
                );
                CFRelease(self.available_name);
                CFRelease(self.unavailable_name);
            }
        }
    }
}

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
