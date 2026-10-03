use super::*;
use std::{ffi::c_void, io, ptr};

type Ref = *const c_void;
type MutableRef = *mut c_void;
type ObserverCallBack = unsafe extern "C" fn(Ref, *mut c_void, Ref, Ref, Ref);
type RemoveObserver = unsafe extern "C" fn(MutableRef, Ref, Ref, Ref);
type Release = unsafe extern "C" fn(Ref);

#[derive(Clone, Copy)]
struct CleanupFns {
    remove_observer: RemoveObserver,
    release: Release,
}

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
    cleanup: CleanupFns,
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
                cleanup: CleanupFns {
                    remove_observer: CFNotificationCenterRemoveObserver,
                    release: CFRelease,
                },
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
                (&mut *registration.unavailable_context as *mut CallbackContext).cast::<c_void>()
                    as Ref,
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
            (self.cleanup.remove_observer)(
                self.center,
                (&mut *self.available_context as *mut CallbackContext).cast::<c_void>() as Ref,
                self.available_name,
                ptr::null(),
            );
            (self.cleanup.remove_observer)(
                self.center,
                (&mut *self.unavailable_context as *mut CallbackContext).cast::<c_void>() as Ref,
                self.unavailable_name,
                ptr::null(),
            );
            (self.cleanup.release)(self.available_name);
            (self.cleanup.release)(self.unavailable_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static CLEANUP_CALLS: Mutex<Vec<(String, usize, usize, usize)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn record_remove(center: MutableRef, observer: Ref, name: Ref, object: Ref) {
        CLEANUP_CALLS.lock().unwrap().push((
            "remove".to_owned(),
            center as usize,
            observer as usize,
            name as usize,
        ));
        if !object.is_null() {
            CLEANUP_CALLS.lock().unwrap().push((
                "unexpected object".to_owned(),
                object as usize,
                0,
                0,
            ));
        }
    }

    unsafe extern "C" fn record_release(value: Ref) {
        CLEANUP_CALLS
            .lock()
            .unwrap()
            .push(("release".to_owned(), value as usize, 0, 0));
    }

    #[test]
    fn dropping_registration_removes_both_observers_before_releasing_names() {
        CLEANUP_CALLS.lock().unwrap().clear();
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let registration = Registration {
            center: 1usize as MutableRef,
            available_name: 2usize as MutableRef,
            unavailable_name: 3usize as MutableRef,
            available_context: Box::new(CallbackContext {
                sender: sender.clone(),
                event: NetworkEvent::Available,
            }),
            unavailable_context: Box::new(CallbackContext {
                sender,
                event: NetworkEvent::Unavailable,
            }),
            cleanup: CleanupFns {
                remove_observer: record_remove,
                release: record_release,
            },
        };
        let available_observer =
            (&*registration.available_context as *const CallbackContext) as usize;
        let unavailable_observer =
            (&*registration.unavailable_context as *const CallbackContext) as usize;

        drop(registration);

        let calls = CLEANUP_CALLS.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0], ("remove".to_owned(), 1, available_observer, 2));
        assert_eq!(calls[1], ("remove".to_owned(), 1, unavailable_observer, 3));
        assert_eq!(calls[2], ("release".to_owned(), 2, 0, 0));
        assert_eq!(calls[3], ("release".to_owned(), 3, 0, 0));
    }
}
