use unproxy::network_notifications::{NetworkEvent, NotificationAdapter, TransitionState};

#[test]
fn native_transition_suppression_and_restore_retry() {
    let mut state = TransitionState::new();
    assert_eq!(state.observe(NetworkEvent::Available), None);
    assert_eq!(
        state.observe(NetworkEvent::Unavailable),
        Some(NetworkEvent::Unavailable)
    );
    assert_eq!(state.observe(NetworkEvent::Unavailable), None);
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

#[tokio::test]
async fn adapter_drop_is_a_no_panic_smoke_test() {
    // This checks construction and Drop do not panic; it does not verify that
    // the native notification center received observer-removal calls.
    let adapter = NotificationAdapter::start().unwrap();
    drop(adapter);
}

#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn non_macos_adapter_closes_its_receiver_and_default_state_is_available() {
    let mut adapter = NotificationAdapter::start_with_names("available", "unavailable").unwrap();
    adapter.pump();
    assert_eq!(adapter.recv().await, None);
    let state = TransitionState::default();
    assert!(state.is_available());
}
