//! Minimal host shell around the pure semantic-devnet kernel.

use activechain_action_kernel::ResourcePrices;
use activechain_devnet_kernel::{ChainState, DevnetBlock, apply_block};
use activechain_protocol_types::{ChainId, Digest384};
use activechain_state_tree::commit_objects;
use activechain_transition::ObjectState;

fn hexadecimal(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn empty_block_demo() {
    let chain_id = ChainId::new(Digest384::new([0x42; 48]));
    let objects = ObjectState::new(vec![]).expect("empty explicit state is canonical");
    let state =
        ChainState::genesis(chain_id, objects, vec![], ResourcePrices::new(1, 2, 3, 4, 5, 1))
            .expect("empty genesis is canonical");
    let pre_state = commit_objects(state.objects().objects()).expect("empty state commits");
    let block = DevnetBlock::new(chain_id, 1, Digest384::ZERO, pre_state, vec![])
        .expect("empty block is bounded");
    let output = apply_block(&state, &block).expect("empty deterministic block applies");
    println!("height={}", output.state().height());
    println!("actions={}", output.receipt().action_receipts().len());
    println!("block_id={}", hexadecimal(output.receipt().block_id().as_bytes()));
    println!("post_state_root={}", hexadecimal(output.receipt().post_state().root().as_bytes()));
    println!("receipt_root={}", hexadecimal(output.receipt_root().as_bytes()));
}

fn main() {
    match std::env::args().nth(1).as_deref().unwrap_or("empty-block") {
        "empty-block" => empty_block_demo(),
        unknown => {
            eprintln!("unknown command {unknown}; expected empty-block");
            std::process::exit(2);
        }
    }
}
