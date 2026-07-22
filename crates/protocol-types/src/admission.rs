//! Overflow-safe framing and replay admission shared by network and persistence boundaries.

#[must_use]
pub fn length_prefixed_range(
    available: usize,
    prefix: usize,
    declared: usize,
    maximum: usize,
) -> Option<(usize, usize)> {
    if declared > maximum {
        return None;
    }
    let end = prefix.checked_add(declared)?;
    (end <= available).then_some((prefix, end))
}

#[must_use]
pub fn exact_frame_layout(
    frame_len: usize,
    fixed_header: usize,
    signature_len: usize,
    body_header: usize,
    body_len: usize,
) -> bool {
    fixed_header
        .checked_add(signature_len)
        .and_then(|value| value.checked_add(body_header))
        .and_then(|value| value.checked_add(body_len))
        == Some(frame_len)
}

#[must_use]
pub const fn fresh_sequence(previous: Option<u64>, candidate: u64) -> bool {
    match previous {
        Some(previous) => candidate > previous,
        None => true,
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn admitted_ranges_are_in_bounds_and_exact() {
        let available = kani::any();
        let prefix = kani::any();
        let declared = kani::any();
        let maximum = kani::any();
        if let Some((start, end)) = length_prefixed_range(available, prefix, declared, maximum) {
            assert_eq!(start, prefix);
            assert_eq!(end - start, declared);
            assert!(end <= available);
            assert!(declared <= maximum);
        }
    }

    #[kani::proof]
    fn exact_layout_is_equivalent_to_checked_sum() {
        let frame: usize = kani::any();
        let fixed: usize = kani::any();
        let signature: usize = kani::any();
        let body_header: usize = kani::any();
        let body: usize = kani::any();
        let expected = fixed
            .checked_add(signature)
            .and_then(|x| x.checked_add(body_header))
            .and_then(|x| x.checked_add(body))
            == Some(frame);
        assert_eq!(exact_frame_layout(frame, fixed, signature, body_header, body), expected);
    }

    #[kani::proof]
    fn replay_admission_is_strictly_monotonic() {
        let previous: Option<u64> = kani::any();
        let candidate: u64 = kani::any();
        assert_eq!(fresh_sequence(previous, candidate), previous.is_none_or(|p| candidate > p));
    }
}
