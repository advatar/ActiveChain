use super::*;
use activechain_cash_kernel::{
    CashLedger, GenesisAllocation, GenesisEconomy, NativeAssetDefinition,
};
use activechain_privacy_kernel::{ShieldIntent, UnshieldIntent};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn config() -> BillboardConfig {
    BillboardConfig::new(ChainId::new(digest(1)), AssetId::new(digest(2)), 100, 10, 3, 20, 5, 2, 7)
        .unwrap()
}

fn native_ledger() -> CashLedger {
    let definition = NativeAssetDefinition::new(
        ChainId::new(digest(1)),
        b"ACT".to_vec(),
        18,
        1_000,
        150,
        digest(21),
        digest(22),
        digest(23),
    )
    .unwrap();
    let economy = GenesisEconomy::new(
        definition,
        vec![
            GenesisAllocation::new(PrincipalId::new(digest(30)), 400, 0).unwrap(),
            GenesisAllocation::new(PrincipalId::new(digest(30)), 10, 0).unwrap(),
            GenesisAllocation::new(PrincipalId::new(digest(31)), 490, 0).unwrap(),
        ],
        100,
    )
    .unwrap();
    CashLedger::from_genesis(&economy).unwrap()
}

fn successor(
    prior: &BillboardPermit,
    content: &[u8],
    post_id: Digest384,
    height: u64,
    blinding: Digest384,
) -> BillboardPermit {
    let mut value = prior.clone();
    screen_matured(&mut value, &[], height, config().penalty_slots).unwrap();
    accrue_save_up(&mut value, config(), height).unwrap();
    value.amount -= config().post_fee;
    value.saved_posts -= 1;
    value.sequence += 1;
    value.next_allowed_height = height + config().cooldown(value.amount).unwrap();
    if !content.is_empty() {
        value
            .pending
            .push(PendingScreen { post_id, eligible_at: height + config().screening_window });
    }
    value.blinding = blinding;
    value
}

#[test]
fn complete_senderless_lifecycle_survives_restart_and_withdraws_once() {
    let config = config();
    let mut state = BillboardState::new(config);
    let permit = BillboardPermit::new(config, digest(3), 300, 10, digest(4)).unwrap();
    state.shield(&permit).unwrap();

    let mut wallet = BillboardWallet::from_seed([9; 64]);
    let encrypted = EncryptedPermit::seal(&permit, &wallet.public_key()).unwrap();
    wallet.discover(&encrypted).unwrap();
    assert_eq!(wallet.permits(), core::slice::from_ref(&permit));

    let post_id = digest(11);
    let next = successor(&permit, b"hello", post_id, 10, digest(5));
    let nullifier = permit.nullifier(digest(6)).unwrap();
    let public = PostPublicInputs {
        chain_id: config.chain_id,
        asset_id: config.asset_id,
        anchor: state.anchor(),
        nullifier,
        successor_commitment: next.commitment().unwrap(),
        post_id,
        content: b"hello".to_vec(),
        height: 10,
        fee: 2,
        dummy: false,
        policy_revision: 7,
    };
    let ordering_recipient = MlKem768Recipient::from_seed([12; 64]);
    let protected =
        EncryptedPostSubmission::seal(&public, &ordering_recipient.public_key()).unwrap();
    assert_eq!(protected.open(&ordering_recipient).unwrap(), public);
    let proof = BillboardVerifier::verify_post(
        config,
        &public,
        &PostWitness { prior: permit.clone(), successor: next.clone(), nullifier_key: digest(6) },
        &[],
    )
    .unwrap();
    let before = state.clone();
    state.apply_post(public.clone(), proof).unwrap();
    assert_eq!(state.posts()[0].content, b"hello");
    assert_eq!(state.apply_post(public, proof), Err(BillboardError::InvalidProof));
    assert_ne!(state, before);
    wallet.replace(permit.commitment().unwrap(), next.clone(), nullifier).unwrap();

    let successor_note = EncryptedPermit::seal(&next, &wallet.public_key()).unwrap();
    let mut recovered_wallet = BillboardWallet::from_seed([9; 64]);
    recovered_wallet.discover(&successor_note).unwrap();
    assert_eq!(recovered_wallet.permits(), core::slice::from_ref(&next));

    state.decide(ModerationDecision { post_id, policy_revision: 7, flagged: false }).unwrap();
    let restarted = state.clone();
    let withdrawal_nullifier = next.nullifier(digest(7)).unwrap();
    let withdrawal = WithdrawalPublicInputs {
        chain_id: config.chain_id,
        asset_id: config.asset_id,
        anchor: restarted.anchor(),
        nullifier: withdrawal_nullifier,
        recipient: PrincipalId::new(digest(8)),
        amount: 297,
        fee: 1,
        height: 15,
        policy_revision: 7,
    };
    let proof = BillboardVerifier::verify_withdrawal(
        config,
        withdrawal,
        &WithdrawalWitness { permit: next.clone(), nullifier_key: digest(7) },
        &restarted.decisions,
    )
    .unwrap();
    let mut resumed = restarted;
    resumed.apply_withdrawal(withdrawal, proof).unwrap();
    assert_eq!(resumed.withdrawals(), &[(PrincipalId::new(digest(8)), 297)]);
    assert_eq!(resumed.apply_withdrawal(withdrawal, proof), Err(BillboardError::InvalidProof));
    wallet.remove(next.commitment().unwrap(), withdrawal_nullifier).unwrap();
    assert!(wallet.permits().is_empty());
    recovered_wallet.remove(next.commitment().unwrap(), withdrawal_nullifier).unwrap();
    assert!(recovered_wallet.permits().is_empty());
}

#[test]
fn native_cash_and_billboard_commit_atomically_through_the_full_lifecycle() {
    let cash = native_ledger();
    let asset_id = cash.asset_id().unwrap();
    let config =
        BillboardConfig::new(ChainId::new(digest(1)), asset_id, 100, 10, 3, 20, 5, 2, 7).unwrap();
    let permit = BillboardPermit::new(config, digest(3), 300, 10, digest(4)).unwrap();
    let owner = PrincipalId::new(digest(30));
    let mut cells = cash
        .cells()
        .as_slice()
        .iter()
        .filter(|record| record.cell().owner() == owner)
        .map(|record| record.id())
        .collect::<Vec<_>>();
    cells.sort();
    let shield = ShieldIntent::new(
        config.chain_id,
        asset_id,
        owner,
        vec![cells[0]],
        cells[1],
        300,
        1,
        vec![permit.commitment().unwrap()],
        20,
    )
    .unwrap();
    let mut ledger = NativeBillboardLedger::new(cash, config);
    ledger.shield(&shield, &permit, 10).unwrap();
    assert_eq!(ledger.cash().shielded_state().pool_balance(), 300);

    let post_id = digest(11);
    let next = successor(&permit, b"native", post_id, 10, digest(5));
    let nullifier = permit.nullifier(digest(6)).unwrap();
    let public = PostPublicInputs {
        chain_id: config.chain_id,
        asset_id,
        anchor: ledger.billboard().anchor(),
        nullifier,
        successor_commitment: next.commitment().unwrap(),
        post_id,
        content: b"native".to_vec(),
        height: 10,
        fee: 2,
        dummy: false,
        policy_revision: 7,
    };
    let proof = BillboardVerifier::verify_post(
        config,
        &public,
        &PostWitness { prior: permit, successor: next.clone(), nullifier_key: digest(6) },
        &[],
    )
    .unwrap();
    let fee_intent = UnshieldIntent::new(
        config.chain_id,
        asset_id,
        ledger.cash().shielded_state().anchor(),
        PrincipalId::new(digest(40)),
        1,
        1,
        vec![nullifier],
        vec![next.commitment().unwrap()],
        20,
    )
    .unwrap();
    ledger.post(public, proof, &fee_intent).unwrap();
    assert_eq!(ledger.cash().shielded_state().pool_balance(), 298);

    ledger
        .billboard
        .decide(ModerationDecision { post_id, policy_revision: 7, flagged: false })
        .unwrap();
    let withdrawal_nullifier = next.nullifier(digest(7)).unwrap();
    let withdrawal = WithdrawalPublicInputs {
        chain_id: config.chain_id,
        asset_id,
        anchor: ledger.billboard().anchor(),
        nullifier: withdrawal_nullifier,
        recipient: PrincipalId::new(digest(31)),
        amount: 297,
        fee: 1,
        height: 15,
        policy_revision: 7,
    };
    let proof = BillboardVerifier::verify_withdrawal(
        config,
        withdrawal,
        &WithdrawalWitness { permit: next, nullifier_key: digest(7) },
        &ledger.billboard().decisions,
    )
    .unwrap();
    let unshield = UnshieldIntent::new(
        config.chain_id,
        asset_id,
        ledger.cash().shielded_state().anchor(),
        withdrawal.recipient,
        withdrawal.amount,
        withdrawal.fee,
        vec![withdrawal_nullifier],
        vec![],
        20,
    )
    .unwrap();
    ledger.withdraw(withdrawal, proof, &unshield).unwrap();
    assert_eq!(ledger.cash().shielded_state().pool_balance(), 0);
    assert_eq!(ledger.billboard().withdrawals()[0].1, 297);
    ledger.cash().verify_invariants().unwrap();
}

#[test]
fn premature_withdrawal_and_tampered_note_fail_closed() {
    let config = config();
    let permit = BillboardPermit::new(config, digest(3), 300, 10, digest(4)).unwrap();
    let next = successor(&permit, b"hello", digest(11), 10, digest(5));
    let public = WithdrawalPublicInputs {
        chain_id: config.chain_id,
        asset_id: config.asset_id,
        anchor: digest(10),
        nullifier: next.nullifier(digest(7)).unwrap(),
        recipient: PrincipalId::new(digest(8)),
        amount: 297,
        fee: 1,
        height: 11,
        policy_revision: 7,
    };
    assert_eq!(
        BillboardVerifier::verify_withdrawal(
            config,
            public,
            &WithdrawalWitness { permit: next, nullifier_key: digest(7) },
            &[],
        ),
        Err(BillboardError::WithdrawalNotReady)
    );

    let mut wallet = BillboardWallet::from_seed([9; 64]);
    let mut encrypted = EncryptedPermit::seal(&permit, &wallet.public_key()).unwrap();
    encrypted.envelope[100] ^= 1;
    assert_eq!(wallet.discover(&encrypted), Err(BillboardError::NoteDecryption));
    assert!(wallet.permits().is_empty());
}

#[test]
fn stale_anchor_wrong_policy_and_invalid_successor_are_atomic() {
    let config = config();
    let mut state = BillboardState::new(config);
    let permit = BillboardPermit::new(config, digest(3), 300, 10, digest(4)).unwrap();
    state.shield(&permit).unwrap();
    let mut next = successor(&permit, b"x", digest(11), 10, digest(5));
    next.amount -= 1;
    let public = PostPublicInputs {
        chain_id: config.chain_id,
        asset_id: config.asset_id,
        anchor: state.anchor(),
        nullifier: permit.nullifier(digest(6)).unwrap(),
        successor_commitment: next.commitment().unwrap(),
        post_id: digest(11),
        content: b"x".to_vec(),
        height: 10,
        fee: 2,
        dummy: false,
        policy_revision: 7,
    };
    let snapshot = state.clone();
    assert_eq!(
        BillboardVerifier::verify_post(
            config,
            &public,
            &PostWitness { prior: permit, successor: next, nullifier_key: digest(6) },
            &[],
        ),
        Err(BillboardError::WrongPermit)
    );
    assert_eq!(state, snapshot);
}

#[test]
fn flagged_screening_applies_exact_penalty() {
    let config = config();
    let permit = BillboardPermit::new(config, digest(3), 300, 10, digest(4)).unwrap();
    let posted = successor(&permit, b"x", digest(11), 10, digest(5));
    let mut screened = posted.clone();
    screen_matured(
        &mut screened,
        &[ModerationDecision { post_id: digest(11), policy_revision: 7, flagged: true }],
        15,
        20,
    )
    .unwrap();
    assert!(screened.pending.is_empty());
    assert_eq!(screened.next_allowed_height, posted.next_allowed_height + 20);
}

proptest::proptest! {
    #[test]
    fn cooldown_is_nonzero_and_decreases_with_deposit(multiplier in 1_u128..1_000) {
        let config = config();
        let amount = config.minimum_deposit.checked_mul(multiplier).unwrap();
        let cooldown = config.cooldown(amount).unwrap();
        proptest::prop_assert!(cooldown >= 1);
        proptest::prop_assert!(cooldown <= config.base_cooldown);
    }
}
