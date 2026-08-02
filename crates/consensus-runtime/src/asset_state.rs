use activechain_application_primitives::{
    AssetLedgerAnchorV1, MultiAssetLedgerSnapshotV1, asset_ledger_anchor_type_id,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{Digest384, Object};
use activechain_state_tree::{StateProof, verify_membership};
use std::{io::Write, path::Path};

const MAX_FINALITY_BYTES: usize = 64 * 1024;

/// Complete native-asset ledger authenticated by a finalized state-tree anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedAssetLedgerSnapshot {
    chain_genesis: Digest384,
    finalized_height: u64,
    ledger: MultiAssetLedgerSnapshotV1,
    anchor_object: Object,
    anchor_proof: StateProof,
    finality: Vec<u8>,
}

impl FinalizedAssetLedgerSnapshot {
    pub const TYPE_TAG: u16 = 0x018F;

    pub fn new_verified(
        chain_genesis: Digest384,
        finalized_height: u64,
        ledger: MultiAssetLedgerSnapshotV1,
        anchor_object: Object,
        anchor_proof: StateProof,
        finality: Vec<u8>,
    ) -> Result<Self, &'static str> {
        let value =
            Self { chain_genesis, finalized_height, ledger, anchor_object, anchor_proof, finality };
        value.verify()?;
        Ok(value)
    }

    pub const fn ledger(&self) -> &MultiAssetLedgerSnapshotV1 {
        &self.ledger
    }
    pub const fn anchor_object(&self) -> &Object {
        &self.anchor_object
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        if self.chain_genesis == Digest384::ZERO
            || self.finalized_height == 0
            || self.finality.is_empty()
            || self.finality.len() > MAX_FINALITY_BYTES
        {
            return Err("invalid finalized asset snapshot bounds");
        }
        let bundle = activechain_verifier_api::verify_finality_bundle_with_chain_genesis(
            &self.finality,
            self.chain_genesis,
        )
        .map_err(|_| "invalid asset snapshot finality")?;
        if bundle.header().inputs.height != self.finalized_height {
            return Err("asset snapshot height differs from finality");
        }
        verify_membership(
            bundle.header().inputs.post_state,
            &self.anchor_object,
            &self.anchor_proof,
        )
        .map_err(|_| "asset anchor is not in finalized post-state")?;
        if self.anchor_object.type_id() != asset_ledger_anchor_type_id() {
            return Err("wrong asset anchor object type");
        }
        let public_value =
            self.anchor_object.public_value().ok_or("asset anchor public value is absent")?;
        let anchor = decode_envelope::<AssetLedgerAnchorV1>(public_value)
            .map_err(|_| "asset anchor public value is malformed")?;
        if anchor.finalized_height() != self.finalized_height {
            return Err("asset anchor height mismatch");
        }
        let ledger_commitment = commit(DomainTag::CANONICAL_VALUE, &self.ledger)
            .map_err(|_| "asset ledger commitment failed")?;
        if anchor.ledger_commitment() != ledger_commitment
            || self.anchor_object.value_root()
                != anchor.commitment().map_err(|_| "asset anchor commitment failed")?
        {
            return Err("asset anchor ledger binding mismatch");
        }
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        self.verify().map_err(std::io::Error::other)?;
        let body = encode_envelope(self)
            .map_err(|_| std::io::Error::other("asset snapshot encoding failed"))?;
        let parent = path.parent().ok_or_else(|| std::io::Error::other("missing parent"))?;
        std::fs::create_dir_all(parent)?;
        let name = path.file_name().ok_or_else(|| std::io::Error::other("missing file name"))?;
        let temporary =
            parent.join(format!(".{}.{}.tmp", name.to_string_lossy(), std::process::id()));
        let result = (|| {
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&body)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            std::fs::File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    pub fn load_verified(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        decode_envelope(&bytes).map_err(|_| std::io::Error::other("asset snapshot malformed"))
    }
}

impl CanonicalEncode for FinalizedAssetLedgerSnapshot {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_genesis.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.ledger.encode(encoder)?;
        self.anchor_object.encode(encoder)?;
        self.anchor_proof.encode(encoder)?;
        encoder.write_bytes(&self.finality, MAX_FINALITY_BYTES)
    }
}

impl CanonicalDecode for FinalizedAssetLedgerSnapshot {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new_verified(
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            MultiAssetLedgerSnapshotV1::decode(decoder)?,
            Object::decode(decoder)?,
            StateProof::decode(decoder)?,
            decoder.read_bytes(MAX_FINALITY_BYTES)?.to_vec(),
        )
        .map_err(DecodeError::InvalidValue)
    }
}

impl CanonicalType for FinalizedAssetLedgerSnapshot {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48
        + 8
        + MultiAssetLedgerSnapshotV1::MAX_ENCODED_LEN
        + Object::MAX_ENCODED_LEN
        + StateProof::MAX_ENCODED_LEN
        + 3
        + MAX_FINALITY_BYTES;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_application_primitives::AssetLedgerAnchorV1;
    use activechain_cash_kernel::FungibleCoinCellSet;
    use activechain_finality_types::{
        FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
    };
    use activechain_protocol_types::{
        ChainId, ConsensusVoteContext, CryptoSuiteId, ObjectFields, ObjectFlags, ObjectId,
        ObjectOwner, PrincipalId, ProtocolSignature, QuorumCertificate, ValidatorGenesis,
        ValidatorGenesisEntry, ValidatorVote,
    };
    use activechain_state_tree::{StateCommitment, commit_objects, prove_object};
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    fn digest(value: u8) -> Digest384 {
        Digest384::new([value; 48])
    }

    fn anchor_object(anchor: AssetLedgerAnchorV1) -> Object {
        Object::new(ObjectFields {
            object_id: ObjectId::new(digest(20)),
            object_version: 1,
            type_id: asset_ledger_anchor_type_id(),
            owner: ObjectOwner::Shared,
            control_policy_hash: digest(21),
            use_policy_hash: digest(22),
            disclosure_policy_hash: digest(23),
            upgrade_policy_hash: digest(24),
            package_id: None,
            value_root: anchor.commitment().unwrap(),
            public_value: Some(encode_envelope(&anchor).unwrap()),
            lease_expiry_epoch: 100,
            storage_deposit: 1,
            flags: ObjectFlags::TRANSFERABLE,
        })
        .unwrap()
    }

    fn finality_bundle(post_state: StateCommitment) -> FinalityCertificateBundle {
        let keys = [
            SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32])),
            SigningKey::<MlDsa44>::from_seed(&Seed::from([2; 32])),
        ];
        let entries = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                ValidatorGenesisEntry::new(
                    PrincipalId::new(digest((index + 1) as u8)),
                    1,
                    key.verifying_key().encode().into(),
                )
                .unwrap()
            })
            .collect();
        let genesis = ValidatorGenesis::new_with_revision(3, 1, 4, entries).unwrap();
        let inputs = ProofPublicInputs {
            chain_id: ChainId::new(digest(40)),
            epoch: 3,
            height: 9,
            protocol_revision: 4,
            validator_set_root: genesis.validator_set_root(),
            parent_block_id: digest(41),
            pre_state: post_state,
            authorization_root: digest(43),
            action_root: digest(44),
            execution_order_root: digest(45),
            total_fees: 0,
            pre_supply: 0,
            issuance: 0,
            burn: 0,
            post_supply: 0,
            cash_cell_root: digest(46),
            post_state,
            receipt_root: digest(47),
            data_availability_commitment: digest(48),
        };
        let header = FinalizedBlockHeader { inputs, proof_statement_commitment: digest(49) };
        let block_digest = header.digest().unwrap();
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let mut votes = Vec::new();
        let mut vote_set_hasher = Shake256::default();
        vote_set_hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        for (index, key) in keys.iter().enumerate() {
            let validator = PrincipalId::new(digest((index + 1) as u8));
            let unsigned = ValidatorVote::new(
                validator,
                context,
                9,
                2,
                block_digest,
                digest(49),
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
            )
            .unwrap();
            let signature = key.sign(&unsigned.signing_payload());
            let vote = ValidatorVote::new(
                validator,
                context,
                9,
                2,
                block_digest,
                digest(49),
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap();
            vote_set_hasher.update(key.verifying_key().encode().as_slice());
            vote_set_hasher.update(&vote.signing_payload());
            vote_set_hasher.update(vote.signature().as_bytes());
            votes.push(vote);
        }
        let mut vote_set_root = [0; 48];
        vote_set_hasher.finalize_xof().read(&mut vote_set_root);
        let certificate = QuorumCertificate::new(
            context,
            9,
            2,
            block_digest,
            digest(49),
            Digest384::new(vote_set_root),
            2,
            2,
        )
        .unwrap();
        FinalityCertificateBundle::new(header, genesis, certificate, votes).unwrap()
    }

    #[test]
    fn finalized_asset_anchor_authenticates_ledger_and_survives_restart() {
        let ledger =
            MultiAssetLedgerSnapshotV1::new(FungibleCoinCellSet::new(vec![]).unwrap(), vec![])
                .unwrap();
        let anchor = AssetLedgerAnchorV1::from_ledger(9, &ledger).unwrap();
        let object = anchor_object(anchor);
        let objects = vec![object.clone()];
        let post_state = commit_objects(&objects).unwrap();
        let proof = prove_object(&objects, object.object_id()).unwrap();
        let bundle = finality_bundle(post_state);
        let genesis = bundle.validator_genesis().genesis_commitment();
        let finality = encode_envelope(&bundle).unwrap();
        let snapshot = FinalizedAssetLedgerSnapshot::new_verified(
            genesis,
            9,
            ledger.clone(),
            object.clone(),
            proof.clone(),
            finality.clone(),
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-finalized-assets-{}.snapshot", std::process::id()));
        let _ = std::fs::remove_file(&path);
        snapshot.save_atomic(&path).unwrap();
        assert_eq!(FinalizedAssetLedgerSnapshot::load_verified(&path).unwrap(), snapshot);
        let mut corrupt = std::fs::read(&path).unwrap();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(FinalizedAssetLedgerSnapshot::load_verified(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(snapshot.save_atomic(&path).is_err());
        std::fs::remove_dir(&path).unwrap();

        let wrong_anchor = AssetLedgerAnchorV1::new(9, digest(99)).unwrap();
        let wrong_object = anchor_object(wrong_anchor);
        let wrong_objects = vec![wrong_object.clone()];
        let wrong_post = commit_objects(&wrong_objects).unwrap();
        let wrong_bundle = finality_bundle(wrong_post);
        assert!(
            FinalizedAssetLedgerSnapshot::new_verified(
                wrong_bundle.validator_genesis().genesis_commitment(),
                9,
                ledger,
                wrong_object.clone(),
                prove_object(&wrong_objects, wrong_object.object_id()).unwrap(),
                encode_envelope(&wrong_bundle).unwrap(),
            )
            .is_err()
        );
    }
}
