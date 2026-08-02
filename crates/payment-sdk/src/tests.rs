use super::*;
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_payment_types::{
    EvidenceClass, PaymentApiAuthorizationV1, PaymentIntentId, payment_api_authenticator_commitment,
};
use activechain_protocol_types::{
    CryptoSuiteId, ML_DSA44_PUBLIC_KEY_LENGTH, PrincipalId, ProtocolSignature, TransactionId,
};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn request(body: &[u8]) -> PaymentSdkRequestV1 {
    let public = vec![7_u8; ML_DSA44_PUBLIC_KEY_LENGTH];
    let authorization = PaymentApiAuthorizationV1::new(
        PrincipalId::new(digest(1)),
        digest(2),
        PaymentApiOperation::CreateIntent,
        payment_sdk_body_commitment(body),
        digest(3),
        None,
        1,
        10,
        20,
        payment_api_authenticator_commitment(&public),
    )
    .unwrap();
    PaymentSdkRequestV1::new(
        PaymentApiSignedAuthorizationV1::new(
            authorization,
            public,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![8_u8; 2_420]).unwrap(),
        )
        .unwrap(),
        body.to_vec(),
    )
    .unwrap()
}

fn finalized() -> PaymentLifecycleRecordV1 {
    PaymentLifecycleRecordV1::new(
        PaymentIntentId::new(digest(4)).unwrap(),
        2,
        PaymentState::Finalized,
        EvidenceClass::ActiveChainFinalized,
        digest(5),
        Some(TransactionId::new(digest(6))),
        9,
        Some(digest(7)),
        0,
    )
    .unwrap()
}

#[test]
fn request_is_body_bound_canonical_and_operation_visible() {
    let value = request(b"create-intent-v1");
    assert_eq!(value.operation(), PaymentApiOperation::CreateIntent);
    assert_eq!(decode_envelope(&encode_envelope(&value).unwrap()), Ok(value.clone()));
    assert_eq!(
        PaymentSdkRequestV1::new(value.authorization.clone(), b"substituted".to_vec()),
        Err(PaymentSdkError::InvalidRequest)
    );
}

#[test]
fn finalized_response_requires_proof_and_rejection_carries_no_false_state() {
    assert_eq!(
        PaymentSdkResponseV1::new(
            digest(8),
            PaymentSdkOutcome::Accepted,
            Some(finalized()),
            vec![]
        ),
        Err(PaymentSdkError::InvalidResponse)
    );
    assert_eq!(
        PaymentSdkResponseV1::new(
            digest(8),
            PaymentSdkOutcome::Rejected,
            Some(finalized()),
            vec![1]
        ),
        Err(PaymentSdkError::InvalidResponse)
    );
    let response = PaymentSdkResponseV1::new(
        digest(8),
        PaymentSdkOutcome::Accepted,
        Some(finalized()),
        vec![1, 2, 3],
    )
    .unwrap();
    assert_eq!(decode_envelope(&encode_envelope(&response).unwrap()), Ok(response));
}

struct MockTransport {
    response: Vec<u8>,
}
impl ActiveBridgeTransport for MockTransport {
    type Error = ();
    fn send(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let decoded: PaymentSdkRequestV1 = decode_envelope(request).unwrap();
        assert_eq!(decoded.operation(), PaymentApiOperation::CreateIntent);
        Ok(self.response.clone())
    }
}

#[test]
fn client_rejects_response_substitution_and_accepts_exact_correlation() {
    let request = request(b"create-intent-v1");
    let wrong =
        PaymentSdkResponseV1::new(digest(9), PaymentSdkOutcome::Accepted, None, vec![]).unwrap();
    let mut client =
        ActiveBridgeClient::new(MockTransport { response: encode_envelope(&wrong).unwrap() });
    assert_eq!(client.execute(&request), Err(PaymentSdkClientError::ResponseSubstitution));

    let exact = PaymentSdkResponseV1::new(
        request.commitment().unwrap(),
        PaymentSdkOutcome::IdempotentReplay,
        None,
        vec![],
    )
    .unwrap();
    let mut client =
        ActiveBridgeClient::new(MockTransport { response: encode_envelope(&exact).unwrap() });
    assert_eq!(client.execute(&request), Ok(exact));
}

#[test]
fn verified_client_never_promotes_unverified_finality() {
    let request = request(b"create-intent-v1");
    let response = PaymentSdkResponseV1::new(
        request.commitment().unwrap(),
        PaymentSdkOutcome::Accepted,
        Some(finalized()),
        vec![1, 2, 3],
    )
    .unwrap();
    let encoded = encode_envelope(&response).unwrap();
    let mut rejecting = ActiveBridgeClient::new(MockTransport { response: encoded.clone() });
    assert_eq!(
        rejecting.execute_verified(&request, |_, _| false),
        Err(PaymentSdkClientError::ProofRejected)
    );
    let mut accepting = ActiveBridgeClient::new(MockTransport { response: encoded });
    assert_eq!(accepting.execute_verified(&request, |_, proof| proof == [1, 2, 3]), Ok(response));
}
