#![allow(clippy::unwrap_used)]

//! Rate limits: per client address for endpoints without a session, per
//! group for the rest.

mod common;

use axum::http::{Method, StatusCode, header};
use common::{Harness, create_group, login};
use flectar_mail_sync_server::limits::Rate;
use std::time::Duration;

const SLOW: Rate = Rate {
    burst: 2,
    every: Duration::from_secs(3600),
};

async fn lookup(h: &Harness, forwarded_for: Option<&str>) -> (StatusCode, Option<u64>) {
    let headers: Vec<(&str, &str)> = forwarded_for
        .map(|value| ("x-forwarded-for", value))
        .into_iter()
        .collect();
    let (status, response_headers, _) = h
        .call_with(
            Method::GET,
            "/v1/pairing/codes/00000000",
            None,
            None,
            &headers,
        )
        .await;
    let retry_after = response_headers
        .get(header::RETRY_AFTER)
        .map(|value| value.to_str().unwrap().parse().unwrap());
    (status, retry_after)
}

#[tokio::test]
async fn clients_get_a_burst_then_must_wait() {
    let h = Harness::with_config(|config| config.rates.pairing_code = SLOW);
    assert_eq!(lookup(&h, None).await, (StatusCode::NOT_FOUND, None));
    assert_eq!(lookup(&h, None).await, (StatusCode::NOT_FOUND, None));
    let (status, retry_after) = lookup(&h, None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry_after.unwrap() > 3500, "{retry_after:?}");
    // Other endpoints count separately.
    let (status, _) = h.call(Method::GET, "/v1/info", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn forwarded_addresses_count_only_from_trusted_proxies() {
    // The test peer is not a trusted proxy: what it claims is ignored, so
    // every request counts against the peer itself.
    let h = Harness::with_config(|config| config.rates.pairing_code = SLOW);
    lookup(&h, Some("203.0.113.1")).await;
    lookup(&h, Some("203.0.113.2")).await;
    assert_eq!(
        lookup(&h, Some("203.0.113.3")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );

    // Behind a trusted proxy, each forwarded client has its own budget.
    let h = Harness::with_config(|config| {
        config.rates.pairing_code = SLOW;
        config.trusted_proxies = vec!["192.0.2.0/24".parse().unwrap()];
    });
    for _ in 0..2 {
        assert_eq!(
            lookup(&h, Some("203.0.113.1")).await.0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        lookup(&h, Some("203.0.113.1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // A forged entry to the left of the proxy's does not help.
    assert_eq!(
        lookup(&h, Some("198.51.100.9, 203.0.113.1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        lookup(&h, Some("203.0.113.2")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn groups_are_limited_as_a_whole() {
    let h = Harness::with_config(|config| config.rates.group = SLOW);
    let (device, _) = create_group(&h).await;
    let token = login(&h, &device).await;
    let uri = format!("/v1/groups/{}/changes", device.group());
    for _ in 0..2 {
        let (status, _) = h.call(Method::GET, &uri, Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, headers, body) = h
        .call_with(Method::GET, &uri, Some(&token), None, &[])
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"]["code"], "rate_limited");
    assert!(headers.contains_key(header::RETRY_AFTER));
}
