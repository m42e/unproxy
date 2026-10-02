//! A harness-free native probe so CFDistributedNotificationCenter is registered
//! and pumped on this executable's actual main thread.

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use unproxy::network_notifications::{NetworkEvent, NotificationAdapter};
    use std::{ffi::c_void, process::Command, thread, time::Instant};

    type Ref = *const c_void;
    type MutableRef = *mut c_void;
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFNotificationCenterGetDistributedCenter() -> MutableRef;
        fn CFNotificationCenterPostNotification(
            center: MutableRef,
            name: Ref,
            object: Ref,
            user_info: Ref,
            deliver_immediately: bool,
        );
        fn CFStringCreateWithCString(allocator: Ref, text: *const i8, encoding: u32) -> MutableRef;
        fn CFRelease(value: Ref);
    }

    unsafe fn post(available: &str, unavailable: &str) {
        let create = |text: &str| {
            let text = std::ffi::CString::new(text).unwrap();
            unsafe { CFStringCreateWithCString(std::ptr::null(), text.as_ptr(), 0x08000100) }
        };
        unsafe {
            let center = CFNotificationCenterGetDistributedCenter();
            let available = create(available);
            let unavailable = create(unavailable);
            let object = create("org.unproxy.native-notification-test");
            CFNotificationCenterPostNotification(center, available, object, std::ptr::null(), true);
            CFNotificationCenterPostNotification(
                center,
                unavailable,
                object,
                std::ptr::null(),
                true,
            );
            CFRelease(available);
            CFRelease(unavailable);
            CFRelease(object);
        }
    }

    if let (Ok(available), Ok(unavailable)) = (
        std::env::var("UNPROXY_NOTIFICATION_POST_AVAILABLE"),
        std::env::var("UNPROXY_NOTIFICATION_POST_UNAVAILABLE"),
    ) {
        unsafe { post(&available, &unavailable) };
        return Ok(());
    }

    let suffix = format!(
        "{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let available = format!("org.unproxy.test.available.{suffix}");
    let unavailable = format!("org.unproxy.test.unavailable.{suffix}");
    let mut adapter = NotificationAdapter::start_with_names(&available, &unavailable)?;
    // Let the distributed notification server finish establishing this process
    // registration before the separate poster sends either state.
    thread::sleep(std::time::Duration::from_millis(200));
    let status = Command::new(std::env::current_exe()?)
        .env("UNPROXY_NOTIFICATION_POST_AVAILABLE", &available)
        .env("UNPROXY_NOTIFICATION_POST_UNAVAILABLE", &unavailable)
        .status()?;
    if !status.success() {
        return Err("notification poster process failed".into());
    }

    let deadline = Instant::now() + std::time::Duration::from_secs(3);
    let mut received = Vec::new();
    while received.len() < 2 && Instant::now() < deadline {
        adapter.pump();
        if let Ok(event) = adapter.try_recv() {
            received.push(event);
        }
    }
    assert_eq!(
        received,
        [NetworkEvent::Available, NetworkEvent::Unavailable]
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {}
