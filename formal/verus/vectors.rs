// Frozen arithmetic inputs and expected results for the ordinary-Rust
// production parity executable. The same values are asserted in the Verus
// target; the runner executes both gates.

pub const FEE_BASE: u128 = 3;
pub const FEE_UNITS: u64 = 4;
pub const FEE_PRICE: u128 = 5;
pub const FEE_CONGESTION: u128 = 2;
pub const FEE_TOTAL: u128 = 25;

pub const MARKET_BASE: u128 = 100;
pub const MARKET_TARGET: u64 = 10;
pub const MARKET_CHANGE_BPS: u16 = 1_000;
pub const MARKET_USED_HIGH: u64 = 20;
pub const MARKET_USED_LOW: u64 = 1;
pub const MARKET_NEXT_HIGH: u128 = 110;
pub const MARKET_NEXT_LOW: u128 = 90;

pub const QUORUM_TOTAL: u128 = 3;
pub const QUORUM_ACCEPTED_SIGNERS: u128 = 3;
pub const QUORUM_REJECTED_SIGNERS: u128 = 2;

pub const SUPPLY_PRE: u128 = 1_000;
pub const SUPPLY_ISSUANCE: u128 = 50;
pub const SUPPLY_BURN: u128 = 10;
pub const SUPPLY_POST: u128 = 1_040;

pub const PARTITION_CIRCULATING: u128 = 800;
pub const PARTITION_VESTING: u128 = 100;
pub const PARTITION_STAKED: u128 = 50;
pub const PARTITION_RESERVE: u128 = 90;

pub const SECURITY_TARGET: u128 = 100;
pub const SECURITY_FEES: u128 = 35;
pub const SECURITY_RESERVE: u128 = 15;
pub const SECURITY_CAP: u128 = 60;
pub const SECURITY_ISSUANCE: u128 = 50;
