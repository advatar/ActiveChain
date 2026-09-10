//! Durable, single-writer replay admission for the real OpenID4VP receiving service.
//! No credential bytes, claims, wallet keys or identity numbers are written here.

use crate::openid4vp::{OpenId4VpRequest, verify_openid4vp_sd_jwt_once};
use crate::{SdJwtReplayCache, SdJwtVerificationContext, VerifiedExternalPresentation};
use activechain_protocol_types::Digest384;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8] = b"ACTIVECHAIN-OPENID4VP-CONSUMED-V1\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurablePresentationError {
    Storage,
    Rejected(crate::SdJwtRejection),
}

pub struct DurableOpenId4VpVerifier {
    directory: PathBuf,
    cache: Option<SdJwtReplayCache>,
    _lock: File,
}

impl DurableOpenId4VpVerifier {
    pub fn open(directory: &Path) -> Result<Self, DurablePresentationError> {
        let result = (|| -> std::io::Result<Self> {
            if !directory.exists() {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(directory)?;
            }
            require_private(directory, true)?;
            let lock_path = directory.join("requests.lock");
            if lock_path.exists() {
                require_private(&lock_path, false)?;
            }
            let lock = private_options().create(true).read(true).write(true).open(&lock_path)?;
            lock.try_lock().map_err(std::io::Error::other)?;
            let path = directory.join("requests.consumed");
            let entries = if path.exists() {
                require_private(&path, false)?;
                let mut bytes = Vec::new();
                let maximum = MAGIC.len() + 48 * crate::MAX_REPLAY_ENTRIES;
                File::open(&path)?.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
                if bytes.len() > maximum
                    || !bytes.starts_with(MAGIC)
                    || !(bytes.len() - MAGIC.len()).is_multiple_of(48)
                {
                    return Err(std::io::Error::other("invalid replay journal"));
                }
                bytes[MAGIC.len()..]
                    .chunks_exact(48)
                    .map(|chunk| {
                        let mut bytes = [0; 48];
                        bytes.copy_from_slice(chunk);
                        Digest384::new(bytes)
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let cache = SdJwtReplayCache::from_entries(entries)
                .map_err(|_| std::io::Error::other("invalid replay entries"))?;
            Ok(Self { directory: directory.to_path_buf(), cache: Some(cache), _lock: lock })
        })();
        result.map_err(|_| DurablePresentationError::Storage)
    }

    /// Verification may perform CPU work, but no successful evidence escapes until the consumed
    /// request is durable. A storage error disables this instance until it is reopened/reconciled.
    pub fn verify(
        &mut self,
        context: &SdJwtVerificationContext<'_>,
        request: &OpenId4VpRequest,
    ) -> Result<VerifiedExternalPresentation, DurablePresentationError> {
        let mut next = self.cache.clone().ok_or(DurablePresentationError::Storage)?;
        let verified = verify_openid4vp_sd_jwt_once(&mut next, context, request)
            .map_err(DurablePresentationError::Rejected)?;
        if self.persist(&next).is_err() {
            self.cache = None;
            return Err(DurablePresentationError::Storage);
        }
        self.cache = Some(next);
        Ok(verified)
    }

    fn persist(&self, cache: &SdJwtReplayCache) -> std::io::Result<()> {
        require_private(&self.directory, true)?;
        // The directory lock serializes writers; a leftover file is never overwritten implicitly.
        let temporary = self.directory.join(format!("requests.next.{}", std::process::id()));
        let mut file = private_options().create_new(true).write(true).open(&temporary)?;
        let result = (|| {
            file.write_all(MAGIC)?;
            for entry in cache.entries() {
                file.write_all(entry.as_bytes())?;
            }
            file.sync_all()?;
            fs::rename(&temporary, self.directory.join("requests.consumed"))?;
            File::open(&self.directory)?.sync_all()
        })();
        // Only this call's successfully created temporary file is disposable.
        let _ = fs::remove_file(&temporary);
        result
    }
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn require_private(path: &Path, directory: bool) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(std::io::Error::other("replay storage must be regular"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other("replay storage must be private"));
        }
    }
    Ok(())
}
