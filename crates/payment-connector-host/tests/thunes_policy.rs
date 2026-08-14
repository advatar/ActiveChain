use activechain_payment_connector_host::{
    ConnectorHostPolicyV1, ConnectorPolicyError, ConnectorRouteV1,
};
use activechain_payment_connector_thunes::{
    ThunesAdapter, ThunesRequest, ThunesRequests, ThunesResponse, ThunesTransport,
};
use activechain_payment_types::{ConnectorId, RailId};
use activechain_protocol_types::{AssetId, Digest384};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

#[derive(Clone, Copy)]
struct MockTransport;

impl ThunesTransport for MockTransport {
    type Error = ();

    fn send(
        &self,
        origin: &str,
        api_key: &str,
        api_secret: &str,
        _request: &ThunesRequest,
    ) -> Result<ThunesResponse, Self::Error> {
        assert_eq!(origin, "https://preprod.example.thunes.invalid");
        assert_eq!(api_key, "resolved-key");
        assert_eq!(api_secret, "resolved-secret");
        Ok(ThunesResponse { status: 200, body: b"[]".to_vec() })
    }
}

fn fixture() -> (ConnectorHostPolicyV1, ConnectorId, RailId, AssetId) {
    let connector = ConnectorId::new(digest(1)).unwrap();
    let rail = RailId::new(digest(2)).unwrap();
    let asset = AssetId::new(digest(3));
    let route = ConnectorRouteV1::new(rail, asset, 1_000_000).unwrap();
    let policy = ConnectorHostPolicyV1::new(
        connector,
        vec![b"https://preprod.example.thunes.invalid".to_vec()],
        digest(4),
        vec![route],
        5_000,
        15_000,
    )
    .unwrap();
    (policy, connector, rail, asset)
}

#[test]
fn thunes_effect_is_preceded_by_exact_host_policy_authorization() {
    let (policy, connector, rail, asset) = fixture();
    let origin = b"https://preprod.example.thunes.invalid";
    policy.authorize(connector, origin, rail, asset, 25_000).unwrap();

    let adapter = ThunesAdapter::new(String::from_utf8(origin.to_vec()).unwrap(), MockTransport)
        .unwrap();
    let request = ThunesRequests::list_payers(1, 50).unwrap();
    assert_eq!(
        adapter
            .execute("resolved-key", "resolved-secret", &request)
            .unwrap()
            .status,
        200
    );
}

#[test]
fn wrong_origin_and_amount_ceiling_fail_before_provider_transport() {
    let (policy, connector, rail, asset) = fixture();
    assert_eq!(
        policy.authorize(
            connector,
            b"https://attacker.example",
            rail,
            asset,
            25_000,
        ),
        Err(ConnectorPolicyError::Unauthorized)
    );
    assert_eq!(
        policy.authorize(
            connector,
            b"https://preprod.example.thunes.invalid",
            rail,
            asset,
            1_000_001,
        ),
        Err(ConnectorPolicyError::Unauthorized)
    );
}
