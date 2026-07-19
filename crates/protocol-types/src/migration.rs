//! Height-bounded post-quantum suite migration policy.

use crate::{CryptoSuiteId, Height};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoMigrationWindow {
    suite: CryptoSuiteId,
    activation_height: Height,
    deprecation_height: Option<Height>,
}

impl CryptoMigrationWindow {
    pub const TYPE_TAG: u16 = 0x0063;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const ENCODED_LENGTH: usize = 6 + 8 + 1 + 8;

    pub fn new(
        suite: CryptoSuiteId,
        activation_height: Height,
        deprecation_height: Option<Height>,
    ) -> Result<Self, CryptoMigrationError> {
        suite.require_post_quantum().map_err(|_| CryptoMigrationError::NonPostQuantumSuite)?;
        if let Some(deprecation_height) = deprecation_height
            && deprecation_height <= activation_height
        {
            return Err(CryptoMigrationError::DeprecationNotAfterActivation);
        }
        Ok(Self { suite, activation_height, deprecation_height })
    }
    pub const fn suite(&self) -> CryptoSuiteId {
        self.suite
    }
    pub const fn activation_height(&self) -> Height {
        self.activation_height
    }
    pub const fn deprecation_height(&self) -> Option<Height> {
        self.deprecation_height
    }
    pub const fn is_active_at(&self, height: Height) -> bool {
        height >= self.activation_height
            && match self.deprecation_height {
                Some(end) => height < end,
                None => true,
            }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoMigrationError {
    NonPostQuantumSuite,
    DeprecationNotAfterActivation,
}

impl CanonicalEncode for CryptoMigrationWindow {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.suite.encode(e)?;
        self.activation_height.encode(e)?;
        self.deprecation_height.encode(e)
    }
}
impl CanonicalDecode for CryptoMigrationWindow {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(CryptoSuiteId::decode(d)?, u64::decode(d)?, Option::<u64>::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid post-quantum migration window"))
    }
}
impl CanonicalType for CryptoMigrationWindow {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    #[test]
    fn migration_window_has_explicit_activation_and_sunset() {
        let value = CryptoMigrationWindow::new(CryptoSuiteId::ML_DSA_65, 100, Some(200)).unwrap();
        assert!(!value.is_active_at(99));
        assert!(value.is_active_at(100));
        assert!(value.is_active_at(199));
        assert!(!value.is_active_at(200));
        assert_eq!(
            decode_envelope::<CryptoMigrationWindow>(&encode_envelope(&value).unwrap()),
            Ok(value)
        );
    }
    #[test]
    fn migration_window_rejects_invalid_sunset() {
        assert_eq!(
            CryptoMigrationWindow::new(CryptoSuiteId::ML_DSA_65, 100, Some(100)),
            Err(CryptoMigrationError::DeprecationNotAfterActivation)
        );
    }
}
