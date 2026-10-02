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
async fn adapter_drop_unregisters_native_observers() {
    let adapter = NotificationAdapter::start().unwrap();
    drop(adapter);
}
