use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use rand::rngs::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

pub struct SSHKeyManager;

impl SSHKeyManager {
    /// Mengatur izin ketat pada kunci privat (`0600` di Unix, `icacls` di Windows — `SPEC.md` §3.3 #13).
    pub fn fix_permissions(key_path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(key_path, perms)?;
        }
        #[cfg(windows)]
        {
            use std::process::Command;
            if let Ok(user) = std::env::var("USERNAME") {
                let _ = Command::new("icacls")
                    .arg(key_path)
                    .args(["/inheritance:r", "/grant:r", &format!("{}:R", user)])
                    .output();
            }
        }
        Ok(())
    }

    /// Memeriksa keberadaan pasangan kunci RSA 2048-bit (`fastmile_key` & `fastmile_key.pub`);
    /// jika belum ada, membangkitkan pasangan kunci baru (`SPEC.md` §3.3 #14).
    pub fn ensure_keys(key_name: &str) -> io::Result<(PathBuf, String)> {
        let priv_path = PathBuf::from(key_name);
        let pub_path = PathBuf::from(format!("{}.pub", key_name));

        if priv_path.is_file() && pub_path.is_file() {
            Self::fix_permissions(&priv_path)?;
            let pub_str = fs::read_to_string(&pub_path)?.trim().to_string();
            return Ok((priv_path, pub_str));
        }

        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Gagal membuat kunci RSA: {}", e)))?;
        let public_key = private_key.public_key();

        let openssh_priv = private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let openssh_pub = public_key
            .to_openssh()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        fs::write(&priv_path, openssh_priv.as_bytes())?;
        fs::write(&pub_path, format!("{}\n", openssh_pub))?;
        Self::fix_permissions(&priv_path)?;

        Ok((priv_path, openssh_pub))
    }
}
