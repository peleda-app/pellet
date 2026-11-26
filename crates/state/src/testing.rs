//! Conformance suites for the `State` contract.
//!
//! ```ignore
//! #[tokio::test]
//! async fn conformance() {
//!     pellet_state::testing::conformance(&MyState::new()).await;
//! }
//!
//! #[tokio::test(start_paused = true)]
//! async fn expiry() {
//!     pellet_state::testing::expiry(&MyState::new()).await;
//! }
//! ```
//!
//! Every suite uses keys under its own prefix, so suites can share one store.

use std::time::Duration;

use crate::{Entry, Expect, Key, MAX_VALUE_LEN, State, StateError, Version};

fn key(name: &str) -> Key {
    Key::new(format!("conformance/{name}")).unwrap()
}

/// Reads, writes, compare-and-swap and deletes. Does not need paused time.
pub async fn conformance(state: &dyn State) {
    let k = key("basic");
    assert_eq!(state.get(&k).await.unwrap(), None, "fresh key is absent");

    let v1 = state
        .put(&k, b"one".to_vec(), Expect::Absent, None)
        .await
        .unwrap();
    assert_eq!(
        state.get(&k).await.unwrap(),
        Some(Entry {
            value: b"one".to_vec(),
            version: v1
        }),
        "read after write"
    );

    assert_eq!(
        state.put(&k, b"x".to_vec(), Expect::Absent, None).await,
        Err(StateError::Conflict),
        "absent expectation on a present key"
    );

    let v2 = state
        .put(&k, b"two".to_vec(), Expect::Version(v1), None)
        .await
        .unwrap();
    assert_ne!(v1, v2, "a write changes the version");
    assert_eq!(
        state
            .put(&k, b"x".to_vec(), Expect::Version(v1), None)
            .await,
        Err(StateError::Conflict),
        "stale version"
    );
    assert_eq!(state.get(&k).await.unwrap().unwrap().value, b"two");

    let v3 = state
        .put(&k, b"three".to_vec(), Expect::Any, None)
        .await
        .unwrap();
    assert!(v3 != v1 && v3 != v2, "versions are not reused");

    assert_eq!(
        state.delete(&k, Expect::Version(v2)).await,
        Err(StateError::Conflict)
    );
    assert_eq!(state.delete(&k, Expect::Version(v3)).await, Ok(true));
    assert_eq!(state.get(&k).await.unwrap(), None, "read after delete");
    assert_eq!(
        state.delete(&k, Expect::Any).await,
        Ok(false),
        "deleting nothing"
    );
    assert_eq!(
        state
            .put(&k, b"x".to_vec(), Expect::Version(v3), None)
            .await,
        Err(StateError::Conflict),
        "version expectation on an absent key"
    );

    let v4 = state
        .put(&k, b"again".to_vec(), Expect::Absent, None)
        .await
        .unwrap();
    assert!(![v1, v2, v3].contains(&v4), "versions survive a delete");

    let binary = key("binary");
    let bytes: Vec<u8> = (0..=255).collect();
    state
        .put(&binary, bytes.clone(), Expect::Any, None)
        .await
        .unwrap();
    assert_eq!(
        state.get(&binary).await.unwrap().unwrap().value,
        bytes,
        "byte for byte"
    );
    state
        .put(&binary, Vec::new(), Expect::Any, None)
        .await
        .unwrap();
    assert_eq!(
        state.get(&binary).await.unwrap().unwrap().value,
        b"",
        "empty value"
    );

    assert_eq!(
        state
            .put(&key("big"), vec![0; MAX_VALUE_LEN + 1], Expect::Any, None)
            .await,
        Err(StateError::TooLarge)
    );

    let race = key("race");
    let base = state
        .put(&race, b"0".to_vec(), Expect::Any, None)
        .await
        .unwrap();
    let attempts = same_version_writes(state, &race, base).await;
    assert_eq!(
        attempts.iter().filter(|r| r.is_ok()).count(),
        1,
        "one compare-and-swap wins: {attempts:?}"
    );
}

async fn same_version_writes(
    state: &dyn State,
    key: &Key,
    base: Version,
) -> Vec<Result<Version, StateError>> {
    let mut results = Vec::new();
    for i in 0..4u8 {
        results.push(state.put(key, vec![i], Expect::Version(base), None).await);
    }
    results
}

/// Time to live on the Tokio clock. Run it on a paused runtime (`start_paused = true`).
pub async fn expiry(state: &dyn State) {
    let k = key("ttl");
    let v1 = state
        .put(
            &k,
            b"short".to_vec(),
            Expect::Any,
            Some(Duration::from_secs(10)),
        )
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(
        state.get(&k).await.unwrap().is_some(),
        "alive before its time to live"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        state.get(&k).await.unwrap(),
        None,
        "gone after its time to live"
    );
    assert_eq!(
        state
            .put(&k, b"x".to_vec(), Expect::Version(v1), None)
            .await,
        Err(StateError::Conflict),
        "an expired version does not match"
    );
    state
        .put(&k, b"new".to_vec(), Expect::Absent, None)
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(3600)).await;
    assert!(
        state.get(&k).await.unwrap().is_some(),
        "no time to live means no expiry"
    );
    assert_eq!(state.delete(&k, Expect::Any).await, Ok(true));

    let k2 = key("ttl-replaced");
    state
        .put(
            &k2,
            b"a".to_vec(),
            Expect::Any,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    state
        .put(&k2, b"b".to_vec(), Expect::Any, None)
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(
        state.get(&k2).await.unwrap().unwrap().value,
        b"b",
        "a write replaces the time to live"
    );
}
