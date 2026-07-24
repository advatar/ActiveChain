use activechain_payment_types::AssetAmountV1;
use activechain_protocol_types::{AssetId, Digest384};

const MAX_DECIMAL_DIGITS: usize = 38;

/// External units whose precision is explicit in the reviewed provider contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsExternalUnit {
    /// Integer Tanzanian-shilling units carried by `amountTzs` fields.
    Tzs,
    /// USDC decimal units; the reviewed contract states six decimals.
    Usdc,
}

impl NtzsExternalUnit {
    #[must_use]
    pub const fn maximum_scale(self) -> u8 {
        match self {
            Self::Tzs => 0,
            Self::Usdc => 6,
        }
    }
}

/// Positive base-10 value represented without binary floating point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactProviderAmount {
    coefficient: u128,
    scale: u8,
}

impl ExactProviderAmount {
    /// Parses an unsigned, non-exponent base-10 value with a syntactically bounded scale.
    pub fn parse(value: &str, maximum_scale: u8) -> Result<Self, AmountError> {
        if value.is_empty() || value.len() > MAX_DECIMAL_DIGITS + 1 {
            return Err(AmountError::InvalidSyntax);
        }
        let mut coefficient = 0_u128;
        let mut scale = 0_u8;
        let mut digits = 0_usize;
        let mut whole_digits = 0_usize;
        let mut decimal_seen = false;
        let mut first_whole = None;

        for byte in value.bytes() {
            match byte {
                b'0'..=b'9' => {
                    if !decimal_seen {
                        whole_digits += 1;
                        first_whole.get_or_insert(byte);
                    } else {
                        scale = scale.checked_add(1).ok_or(AmountError::Precision)?;
                    }
                    digits += 1;
                    if digits > MAX_DECIMAL_DIGITS {
                        return Err(AmountError::Overflow);
                    }
                    coefficient = coefficient
                        .checked_mul(10)
                        .and_then(|current| current.checked_add(u128::from(byte - b'0')))
                        .ok_or(AmountError::Overflow)?;
                }
                b'.' if !decimal_seen => decimal_seen = true,
                _ => return Err(AmountError::InvalidSyntax),
            }
        }
        if whole_digits == 0
            || (whole_digits > 1 && first_whole == Some(b'0'))
            || (decimal_seen && scale == 0)
        {
            return Err(AmountError::InvalidSyntax);
        }
        if scale > maximum_scale {
            return Err(AmountError::Precision);
        }
        if coefficient == 0 {
            return Err(AmountError::Zero);
        }

        while scale > 0 && coefficient.is_multiple_of(10) {
            coefficient /= 10;
            scale -= 1;
        }
        Ok(Self { coefficient, scale })
    }

    #[must_use]
    pub const fn coefficient(self) -> u128 {
        self.coefficient
    }

    #[must_use]
    pub const fn scale(self) -> u8 {
        self.scale
    }

    /// Converts exactly into registry-defined ActiveChain atomic units.
    pub fn to_atomic_units(self, asset_decimals: u8) -> Result<u128, AmountError> {
        if asset_decimals < self.scale || asset_decimals > MAX_DECIMAL_DIGITS as u8 {
            return Err(AmountError::Precision);
        }
        self.coefficient
            .checked_mul(checked_pow10(asset_decimals - self.scale)?)
            .ok_or(AmountError::Overflow)
    }
}

fn checked_pow10(exponent: u8) -> Result<u128, AmountError> {
    let mut value = 1_u128;
    for _ in 0..exponent {
        value = value.checked_mul(10).ok_or(AmountError::Overflow)?;
    }
    Ok(value)
}

/// One provider amount with a reviewed external unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtzsExternalAmount {
    unit: NtzsExternalUnit,
    value: ExactProviderAmount,
}

impl NtzsExternalAmount {
    pub fn parse(unit: NtzsExternalUnit, value: &str) -> Result<Self, AmountError> {
        Ok(Self { unit, value: ExactProviderAmount::parse(value, unit.maximum_scale())? })
    }

    #[must_use]
    pub const fn unit(self) -> NtzsExternalUnit {
        self.unit
    }

    #[must_use]
    pub const fn value(self) -> ExactProviderAmount {
        self.value
    }
}

/// Explicit mapping between one provider unit and one registered native asset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtzsAssetBinding {
    external_unit: NtzsExternalUnit,
    asset: AssetId,
    asset_decimals: u8,
}

impl NtzsAssetBinding {
    pub fn new(
        external_unit: NtzsExternalUnit,
        asset: AssetId,
        asset_decimals: u8,
    ) -> Result<Self, AmountError> {
        if asset.digest() == &Digest384::ZERO {
            return Err(AmountError::AssetMismatch);
        }
        if asset_decimals > MAX_DECIMAL_DIGITS as u8 {
            return Err(AmountError::Precision);
        }
        Ok(Self { external_unit, asset, asset_decimals })
    }

    /// Requires exact unit, asset identifier, and lossless atomic-unit equality.
    pub fn validate(
        self,
        provider: NtzsExternalAmount,
        expected: AssetAmountV1,
    ) -> Result<(), AmountError> {
        if provider.unit != self.external_unit || expected.asset() != self.asset {
            return Err(AmountError::AssetMismatch);
        }
        if provider.value.to_atomic_units(self.asset_decimals)? != expected.atomic_units() {
            return Err(AmountError::AmountMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmountError {
    AmountMismatch,
    AssetMismatch,
    InvalidSyntax,
    Overflow,
    Precision,
    Zero,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn published_decimal_vectors_are_lossless_and_fail_closed() {
        let vectors = include_str!("../../../testing/ntzs-amount-vectors-v1.tsv");
        for (line_number, line) in vectors.lines().enumerate().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 4, "malformed vector line {}", line_number + 1);
            let unit = match fields[0] {
                "tzs" => NtzsExternalUnit::Tzs,
                "usdc" => NtzsExternalUnit::Usdc,
                value => panic!("unknown unit {value}"),
            };
            let asset_decimals: u8 = fields[2].parse().unwrap();
            let result = NtzsExternalAmount::parse(unit, fields[1])
                .and_then(|amount| amount.value().to_atomic_units(asset_decimals));
            if fields[3] == "reject" {
                assert!(result.is_err(), "vector line {}", line_number + 1);
            } else {
                assert_eq!(
                    result.unwrap().to_string(),
                    fields[3],
                    "vector line {}",
                    line_number + 1
                );
            }
        }
    }

    #[test]
    fn asset_binding_requires_exact_identity_unit_and_quantity() {
        let asset = AssetId::new(digest(1));
        let binding = NtzsAssetBinding::new(NtzsExternalUnit::Tzs, asset, 2).unwrap();
        let provider = NtzsExternalAmount::parse(NtzsExternalUnit::Tzs, "10000").unwrap();
        assert_eq!(
            binding.validate(provider, AssetAmountV1::new(asset, 1_000_000).unwrap()),
            Ok(())
        );
        assert_eq!(
            binding.validate(provider, AssetAmountV1::new(asset, 999_999).unwrap()),
            Err(AmountError::AmountMismatch)
        );
        assert_eq!(
            binding.validate(
                NtzsExternalAmount::parse(NtzsExternalUnit::Usdc, "10000").unwrap(),
                AssetAmountV1::new(asset, 1_000_000).unwrap(),
            ),
            Err(AmountError::AssetMismatch)
        );
        assert_eq!(
            binding.validate(
                provider,
                AssetAmountV1::new(AssetId::new(digest(2)), 1_000_000).unwrap(),
            ),
            Err(AmountError::AssetMismatch)
        );
    }
}
