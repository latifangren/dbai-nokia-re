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

    pub fn default_key_comment() -> String {
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "nokia-pc".to_string());
        format!("dbai@{}", host)
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

        if priv_path.is_file() && !pub_path.is_file() {
            let priv_pem = fs::read_to_string(&priv_path)?;
            let private_key = PrivateKey::from_openssh(&priv_pem)
                .map_err(|e| io::Error::other(format!("Gagal membaca kunci privat: {}", e)))?;
            let openssh_pub = private_key
                .public_key()
                .to_openssh()
                .map_err(|e| io::Error::other(e.to_string()))?;
            let pub_str = format!("{} {}", openssh_pub.trim(), Self::default_key_comment());
            fs::write(&pub_path, format!("{}\n", pub_str))?;
            Self::fix_permissions(&priv_path)?;
            return Ok((priv_path, pub_str));
        }

        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None })
            .map_err(|e| io::Error::other(format!("Gagal membuat kunci RSA: {}", e)))?;
        let public_key = private_key.public_key();

        let openssh_priv = private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let openssh_pub = public_key
            .to_openssh()
            .map_err(|e| io::Error::other(e.to_string()))?;

        let pub_with_comment = format!("{} {}", openssh_pub.trim(), Self::default_key_comment());

        fs::write(&priv_path, openssh_priv.as_bytes())?;
        Self::fix_permissions(&priv_path)?;
        fs::write(&pub_path, format!("{}\n", pub_with_comment))?;

        Ok((priv_path, pub_with_comment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_keys_generation_and_pub_recovery() {
        let unique = format!("test_key_{}_{}", std::process::id(), rand::random::<u32>());
        let temp_dir = std::env::temp_dir().join(unique);
        let _ = fs::create_dir_all(&temp_dir);
        let key_base = temp_dir.join("id_rsa");
        let key_base_str = key_base.to_str().unwrap();

        // 1. Generate new keypair
        let (priv_path, pub_str) = SSHKeyManager::ensure_keys(key_base_str).expect("generate keys");
        assert!(priv_path.is_file());
        let pub_path = PathBuf::from(format!("{}.pub", key_base_str));
        assert!(pub_path.is_file());
        assert!(pub_str.contains("dbai@"));
        let original_priv = fs::read_to_string(&priv_path).unwrap();

        // 2. Remove pub key to test recovery
        fs::remove_file(&pub_path).expect("remove pub file");
        assert!(!pub_path.is_file());

        // 3. Call ensure_keys again
        let (priv_path2, pub_str2) = SSHKeyManager::ensure_keys(key_base_str).expect("recover pub key");
        assert_eq!(priv_path, priv_path2);
        assert!(pub_path.is_file());
        assert_eq!(pub_str, pub_str2);
        // Ensure private key was NOT overwritten
        let recovered_priv = fs::read_to_string(&priv_path).unwrap();
        assert_eq!(original_priv, recovered_priv);

        // Cleanup
        let _ = fs::remove_file(&priv_path);
        let _ = fs::remove_file(&pub_path);
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
