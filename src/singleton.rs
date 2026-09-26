//! Per-session advisory file lock guarding against concurrent connections
//! with the same Telegram auth key (which trips AUTH_KEY_DUPLICATED and can
//! invalidate the session for every holder). Lock files and digests match the
//! previous Python implementation so both cannot run side by side by accident.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs4::fs_std::FileExt;
use sha2::{Digest, Sha256};

pub const DEFAULT_GRACE_SECONDS: f64 = 20.0;
pub const DEFAULT_POLL_INTERVAL: f64 = 0.5;

pub fn default_lock_dir() -> PathBuf {
    std::env::temp_dir().join("telegram-mcp-locks")
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SessionLockError(pub String);

pub struct SessionLock {
    pub path: PathBuf,
    file: Option<File>,
}

pub fn try_lock_exclusive(file: &File) -> bool {
    matches!(FileExt::try_lock_exclusive(file), Ok(true))
}

pub fn try_lock_shared(file: &File) -> bool {
    matches!(FileExt::try_lock_shared(file), Ok(true))
}

pub fn unlock(file: &File) {
    let _ = FileExt::unlock(file);
}

impl SessionLock {
    pub fn new(label: &str, session_identity: &str) -> Self {
        Self::with_dir(label, session_identity, &default_lock_dir())
    }

    pub fn with_dir(label: &str, session_identity: &str, lock_dir: &Path) -> Self {
        let digest = hex::encode(&Sha256::digest(session_identity.as_bytes())[..8]);
        let _ = std::fs::create_dir_all(lock_dir);
        Self {
            path: lock_dir.join(format!("{label}-{digest}.lock")),
            file: None,
        }
    }

    /// Block up to `grace_seconds` until the lock is free, then take it.
    pub fn acquire(
        &mut self,
        grace_seconds: f64,
        poll_interval: f64,
        shared: bool,
    ) -> Result<(), SessionLockError> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&self.path)
            .map_err(|e| {
                SessionLockError(format!(
                    "cannot open lock file {}: {e}",
                    self.path.display()
                ))
            })?;
        let deadline = Instant::now() + Duration::from_secs_f64(grace_seconds.max(0.0));
        loop {
            let locked = if shared {
                try_lock_shared(&file)
            } else {
                try_lock_exclusive(&file)
            };
            if locked {
                self.file = Some(file);
                self.record_holder(shared);
                return Ok(());
            }
            if Instant::now() >= deadline {
                drop(file);
                let holder = self.holder_pid();
                let where_ = match holder {
                    Some(pid) => format!("lock {} held by PID {pid}", self.path.display()),
                    None => format!("lock held: {}", self.path.display()),
                };
                return Err(SessionLockError(format!(
                    "Another telegram-mcp process is already connected with this session ({where_}). Refusing to connect a second time to avoid Telegram's AuthKeyDuplicatedError. If that other process already exited, this lock will clear on its own -- retry."
                )));
            }
            std::thread::sleep(Duration::from_secs_f64(poll_interval.max(0.05)));
        }
    }

    pub fn release(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.set_len(0);
            unlock(&file);
        }
    }

    pub fn holder_pid(&self) -> Option<u32> {
        let mut text = String::new();
        File::open(&self.path)
            .ok()?
            .read_to_string(&mut text)
            .ok()?;
        text.trim().parse().ok()
    }

    fn record_holder(&mut self, shared: bool) {
        if let Some(file) = self.file.as_mut() {
            let _ = file.set_len(0);
            let _ = file.seek(SeekFrom::Start(0));
            if !shared {
                let _ = write!(file, "{}", std::process::id());
                let _ = file.flush();
            }
        }
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        self.release();
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_lock_blocks_second_holder() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = SessionLock::with_dir("default", "string:abc", dir.path());
        a.acquire(0.1, 0.05, false).unwrap();
        assert_eq!(a.holder_pid(), Some(std::process::id()));
        let mut b = SessionLock::with_dir("default", "string:abc", dir.path());
        assert!(b.acquire(0.2, 0.05, false).is_err());
        a.release();
        b.acquire(0.2, 0.05, false).unwrap();
    }

    #[test]
    fn shared_holders_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = SessionLock::with_dir("x", "s", dir.path());
        let mut b = SessionLock::with_dir("x", "s", dir.path());
        a.acquire(0.1, 0.05, true).unwrap();
        b.acquire(0.1, 0.05, true).unwrap();
        let mut c = SessionLock::with_dir("x", "s", dir.path());
        assert!(c.acquire(0.1, 0.05, false).is_err());
    }
}
