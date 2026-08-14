use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmountError {
    Invalid,
    Precision,
    Overflow,
}

/// Parses a Thunes JSON decimal without ever routing money through binary floating point.
pub fn parse_atomic_units(value: &Value, precision: u8) -> Result<u128, AmountError> {
    match value {
        Value::String(value) => parse_decimal(value, precision),
        Value::Number(value) => parse_decimal(&value.to_string(), precision),
        _ => Err(AmountError::Invalid),
    }
}

pub fn parse_decimal(text: &str, precision: u8) -> Result<u128, AmountError> {
    if text.is_empty()
        || text.starts_with('-')
        || text.starts_with('+')
        || text.contains('e')
        || text.contains('E')
    {
        return Err(AmountError::Invalid);
    }
    let mut parts = text.split('.');
    let whole = parts.next().ok_or(AmountError::Invalid)?;
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AmountError::Invalid);
    }
    let fraction = fraction.unwrap_or("");
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AmountError::Invalid);
    }
    let precision = usize::from(precision);
    if fraction.len() > precision && fraction[precision..].bytes().any(|byte| byte != b'0') {
        return Err(AmountError::Precision);
    }
    let kept = &fraction[..fraction.len().min(precision)];
    let scale = 10_u128
        .checked_pow(u32::try_from(precision).map_err(|_| AmountError::Overflow)?)
        .ok_or(AmountError::Overflow)?;
    let whole = whole.parse::<u128>().map_err(|_| AmountError::Overflow)?;
    let mut result = whole.checked_mul(scale).ok_or(AmountError::Overflow)?;
    if !kept.is_empty() {
        let fraction_value = kept.parse::<u128>().map_err(|_| AmountError::Overflow)?;
        let padding = precision.checked_sub(kept.len()).ok_or(AmountError::Precision)?;
        let fraction_scale = 10_u128
            .checked_pow(u32::try_from(padding).map_err(|_| AmountError::Overflow)?)
            .ok_or(AmountError::Overflow)?;
        result = result
            .checked_add(
                fraction_value
                    .checked_mul(fraction_scale)
                    .ok_or(AmountError::Overflow)?,
            )
            .ok_or(AmountError::Overflow)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_decimal_conversion_never_rounds() {
        assert_eq!(parse_atomic_units(&json!("10.69"), 2), Ok(1069));
        assert_eq!(parse_atomic_units(&json!(10.69), 2), Ok(1069));
        assert_eq!(parse_atomic_units(&json!("10.6"), 2), Ok(1060));
        assert_eq!(parse_atomic_units(&json!("10.6900"), 2), Ok(1069));
        assert_eq!(
            parse_atomic_units(&json!("10.691"), 2),
            Err(AmountError::Precision)
        );
        assert_eq!(
            parse_atomic_units(&json!("1e2"), 2),
            Err(AmountError::Invalid)
        );
    }
}
