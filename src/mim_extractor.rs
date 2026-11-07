use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use base64::{engine::general_purpose::STANDARD as B64_STD, Engine as _};

/// Magic needle pada partisi `Factory_MIM` (`SPEC.md` §7.1 #1 `mod_consts[820]`).
pub const MIM_MAGIC_NEEDLE: &[u8] = b"5GGW2-OMNI-2\0";

/// Daftar 24 kunci kanonis pada `Factory_MIM` (`SPEC.md` §7.1 #1 `mod_consts[1535]`).
pub const KNOWN_KEYS: &[&str] = &[
    "Product",
    "Password",
    "ACSPassword",
    "ACSCRPassword",
    "RootPassword",
    "Format",
    "FactoryCode",
    "HWVersion",
    "ICS",
    "SN",
    "CLEI",
    "Mnemonic",
    "ProgDate",
    "MACAddress",
    "PartNbr",
    "PartNbrRev",
    "OperatorID",
    "CountryID",
    "IMEI",
    "PartNbr2",
    "PartNbrRev2",
    "PartNbr3",
    "PartNbrRev3",
    "WiFiPassword",
];

/// Hash shadow root bawaan pabrik (`SPEC.md` §8 baris 625).
pub const KNOWN_ROOT_HASH: &str = "$5$h9AY67gazvN9fEl5$4sI08TV8DiAV/3Lgv/QZnokbiM8MWabqQlXdM/BtySC";
/// Password plaintext root pabrik (`SPEC.md` §8 baris 625).
pub const KNOWN_ROOT_PASS: &str = "iHe,JtCJkCMetyXG";
/// Hash shadow root toolkit FastMile (`SPEC.md` §8 baris 626).
pub const DEFAULT_FASTMILE_HASH: &str = "$5$h9AY67gazvN9fEl5$QMQ00BPno6Bvbbr9Vxdw9M4qcB3cU759mjfTEvZp5H/";
/// Password plaintext root toolkit FastMile (`SPEC.md` §8 baris 626).
pub const DEFAULT_FASTMILE_PASS: &str = "FastMileR00t!";

pub struct FactoryMIMExtractor;

impl FactoryMIMExtractor {
    /// Mengekstrak pasangan key-value dari blok `Factory_MIM` selaras 128-byte (64B key + 64B value, `SPEC.md` §7.1 #1).
    pub fn parse_mim_block(raw_bytes: &[u8]) -> BTreeMap<String, String> {
        let mut entries = BTreeMap::new();
        let Some(idx) = raw_bytes
            .windows(MIM_MAGIC_NEEDLE.len())
            .position(|w| w == MIM_MAGIC_NEEDLE)
        else {
            return entries;
        };

        let start_pos = idx.saturating_sub(64);
        let end_limit = (start_pos + 8192).min(raw_bytes.len());
        let mut p = start_pos;

        while p + 128 <= end_limit {
            let k_slice = &raw_bytes[p..p + 64];
            let v_slice = &raw_bytes[p + 64..p + 128];

            let k_end = k_slice.iter().position(|&b| b == 0).unwrap_or(64);
            let v_end = v_slice.iter().position(|&b| b == 0).unwrap_or(64);

            let k_raw = String::from_utf8_lossy(&k_slice[..k_end]).trim().to_string();
            let v_raw = String::from_utf8_lossy(&v_slice[..v_end]).trim().to_string();

            if !k_raw.is_empty() && k_raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                if let Some(&canon) = KNOWN_KEYS.iter().find(|&&kk| kk.eq_ignore_ascii_case(&k_raw)) {
                    entries.insert(canon.to_string(), v_raw);
                } else {
                    entries.insert(k_raw, v_raw);
                }
            }
            p += 128;
        }

        entries
    }

    /// Memindai berkas partisi `.img` kecil maupun raw dump eMMC multi-GB (`SPEC.md` §7.1 #4 `scan_file_or_dump`).
    pub fn scan_file_or_dump(file_path: &Path) -> io::Result<(BTreeMap<String, String>, String)> {
        let mut f = File::open(file_path)?;
        let file_size = f.metadata()?.len();

        if file_size <= 5 * 1024 * 1024 {
            let mut data = Vec::with_capacity(file_size as usize);
            f.read_to_end(&mut data)?;
            let entries = Self::parse_mim_block(&data);
            let label = format!("File Partisi ({} KiB)", file_size / 1024);
            return Ok((entries, label));
        }

        let chunk_size: usize = 16 * 1024 * 1024;
        let overlap: usize = 1024 * 1024;
        let mut buf = vec![0u8; chunk_size];
        let mut pos = 0u64;

        while pos < file_size {
            f.seek(SeekFrom::Start(pos))?;
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let slice = &buf[..n];
            if let Some(idx) = slice
                .windows(MIM_MAGIC_NEEDLE.len())
                .position(|w| w == MIM_MAGIC_NEEDLE)
            {
                let abs_offset = pos + (idx as u64).saturating_sub(64);
                f.seek(SeekFrom::Start(abs_offset))?;
                let mut block = vec![0u8; 8192];
                let bn = f.read(&mut block)?;
                let entries = Self::parse_mim_block(&block[..bn]);
                if entries.contains_key("Product") {
                    let label = format!("Raw Disk Dump (@ offset 0x{:X})", abs_offset);
                    return Ok((entries, label));
                }
            }
            if n < chunk_size {
                break;
            }
            pos += (chunk_size - overlap) as u64;
        }

        Ok((
            BTreeMap::new(),
            "Header Factory_MIM tidak ditemukan".to_string(),
        ))
    }

    /// Menyusun ringkasan metadata identitas perangkat dari `Factory_MIM`.
    pub fn format_hardware_summary<'a>(
        entries: &'a BTreeMap<String, String>,
        source_label: &str,
    ) -> String {
        let get = |k: &str, def: &'a str| -> &'a str {
            entries.get(k).map(|s| s.as_str()).unwrap_or(def)
        };
        format!(
            "================================================================================\n\
             IDENTITAS PERANGKAT NOKIA FASTMILE (Sumber: {})\n\
             ================================================================================\n\
             Product         : {}\n\
             HWVersion       : {}\n\
             Serial Number   : {}\n\
             MACAddress      : {}\n\
             IMEI            : {}\n\
             OperatorID      : {}\n\
             CountryID       : {}\n\
             PartNbr / Rev   : {} / {}\n\
             ProgDate        : {}\n\
             ================================================================================\n",
            source_label,
            get("Product", "5GGW2-OMNI-2"),
            get("HWVersion", "Unknown"),
            get("SN", "Unknown"),
            get("MACAddress", "Unknown"),
            get("IMEI", "Unknown"),
            get("OperatorID", "Unknown"),
            get("CountryID", "Unknown"),
            get("PartNbr", "Unknown"),
            get("PartNbrRev", "Unknown"),
            get("ProgDate", "Unknown"),
        )
    }

    /// Mendekode field `Password` pada `Factory_MIM` dari Base64 (32 byte digest biner) menjadi 64 karakter hex SHA-256 (`SPEC.md` §7.1 #1).
    pub fn decode_mim_password_sha256_hex(b64_val: &str) -> Option<String> {
        let raw = B64_STD.decode(b64_val.trim().as_bytes()).ok()?;
        if raw.len() != 32 {
            return None;
        }
        Some(hex::encode(raw))
    }

    /// Mencari nilai hash heksadesimal pada berkas potfile Hashcat standar maupun jalur kustom (`SPEC.md` §7.1 #5 `lookup_potfile`).
    pub fn lookup_potfile(target_hex_hash: &str, extra_paths: &[&Path]) -> Option<String> {
        let needle = target_hex_hash.trim().to_lowercase();
        if needle.is_empty() {
            return None;
        }

        let mut candidates: Vec<PathBuf> = extra_paths.iter().map(|p| p.to_path_buf()).collect();
        candidates.push(PathBuf::from("potfile_nokia.txt"));
        candidates.push(PathBuf::from("tools/hashcat-8.0.0/hashcat.potfile"));
        if let Ok(home) = std::env::var("HOME") {
            let h = Path::new(&home);
            candidates.push(h.join(".hashcat/hashcat.potfile"));
            candidates.push(h.join(".local/share/hashcat/hashcat.potfile"));
        }

        for pot_path in candidates {
            let Ok(file) = File::open(&pot_path) else {
                continue;
            };
            let reader = io::BufReader::new(file);
            for line_res in reader.lines() {
                let Ok(line) = line_res else {
                    continue;
                };
                if let Some((hash_part, plain_part)) = line.split_once(':') {
                    if hash_part.trim().eq_ignore_ascii_case(&needle) {
                        return Some(plain_part.to_string());
                    }
                }
            }
        }
        None
    }

    /// Mengekstrak blok `Factory_MIM` secara otomatis dari direktori backup (`Factory_MIM.img` atau berkas `.img` lainnya, `SPEC.md` §7.1 #4).
    pub fn extract_from_folder(
        folder_path: &Path,
    ) -> io::Result<(BTreeMap<String, String>, String)> {
        let direct = folder_path.join("Factory_MIM.img");
        if direct.is_file() {
            let (entries, _) = Self::scan_file_or_dump(&direct)?;
            if !entries.is_empty() {
                return Ok((entries, format!("{}", direct.display())));
            }
        }
        if folder_path.is_dir() {
            for entry in fs::read_dir(folder_path)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_file() {
                    if let Ok((entries, label)) = Self::scan_file_or_dump(&p) {
                        if !entries.is_empty() {
                            return Ok((entries, label));
                        }
                    }
                }
            }
        }
        Ok((
            BTreeMap::new(),
            "Factory_MIM tidak ditemukan di folder".to_string(),
        ))
    }

    /// Mencocokkan hash root dari baris `/etc/shadow` ke daftar hash bawaan (`SPEC.md` §8).
    pub fn resolve_shadow_root_hash(shadow_line: &str) -> (String, Option<&'static str>) {
        let trimmed = shadow_line.trim();
        let hash = if trimmed.contains(':') {
            trimmed.split(':').nth(1).unwrap_or("").to_string()
        } else {
            trimmed.to_string()
        };
        let pass = match hash.as_str() {
            KNOWN_ROOT_HASH => Some(KNOWN_ROOT_PASS),
            DEFAULT_FASTMILE_HASH => Some(DEFAULT_FASTMILE_PASS),
            _ => None,
        };
        (hash, pass)
    }

    /// Mem-parsing keluaran `test_decrypt_node` menjadi pasangan `<label> -> <decrypted_64_hex_sha256>`.
    pub fn parse_test_decrypt_node_output(raw_out: &str) -> BTreeMap<String, String> {
        let mut results = BTreeMap::new();
        let mut current_label: Option<String> = None;

        for line in raw_out.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("[RESULT]") {
                let label = rest.trim().trim_end_matches(':').trim();
                if !label.is_empty() {
                    current_label = Some(label.to_string());
                }
            } else if let Some(rest) = trimmed.strip_prefix("DEC:") {
                if let Some(label) = &current_label {
                    let dec_val = rest.trim().to_string();
                    results.insert(label.clone(), dec_val);
                }
            }
        }

        results
    }

    /// Menyusun laporan lengkap kredensial perangkat (`SPEC.md` §7.1 #1-#5).
    pub fn format_credentials_report(
        entries: &BTreeMap<String, String>,
        source_label: &str,
        shadow_line: Option<&str>,
        decrypted_nodes: &BTreeMap<String, String>,
    ) -> String {
        let mut out = Self::format_hardware_summary(entries, source_label);

        out.push_str("================================================================================\n");
        out.push_str("AUDIT KREDENSIAL PABRIK (Factory_MIM)\n");
        out.push_str("================================================================================\n");
        if let Some(pwd_b64) = entries.get("Password") {
            out.push_str(&format!("Password (Base64)        : {}\n", pwd_b64));
            if let Some(sha_hex) = Self::decode_mim_password_sha256_hex(pwd_b64) {
                out.push_str(&format!("Password (SHA-256 Hex)   : {}\n", sha_hex));
                if let Some(plain) = Self::lookup_potfile(&sha_hex, &[]) {
                    out.push_str(&format!("Password (Plaintext)     : {} (cracked via potfile)\n", plain));
                } else {
                    out.push_str("Password (Plaintext)     : [Belum ter-crack di potfile]\n");
                }
            }
        }
        for key in &["ACSPassword", "ACSCRPassword", "RootPassword", "WiFiPassword"] {
            if let Some(val) = entries.get(*key) {
                out.push_str(&format!("{:<25}: {}\n", key, val));
            }
        }

        out.push_str("================================================================================\n");
        out.push_str("AUDIT KREDENSIAL ROOT (/etc/shadow)\n");
        out.push_str("================================================================================\n");
        if let Some(shadow) = shadow_line {
            let (hash, pass) = Self::resolve_shadow_root_hash(shadow);
            out.push_str(&format!("Shadow Root Hash         : {}\n", hash));
            if let Some(p) = pass {
                out.push_str(&format!("Status / Plaintext       : {} (Hardcoded / DBAI Known)\n", p));
            } else {
                out.push_str("Status / Plaintext       : [Hash tidak dikenal / Belum ter-crack]\n");
            }
        } else {
            out.push_str("Shadow Root Hash         : [Tidak tersedia / mode offline]\n");
        }

        out.push_str("================================================================================\n");
        out.push_str("HASIL DEKRIPSI KREDENSIAL (libcfgdb.so / test_decrypt_node)\n");
        out.push_str("================================================================================\n");
        if decrypted_nodes.is_empty() {
            out.push_str("[Tidak ada data node terdekripsi / biner tidak dijalankan]\n");
        } else {
            for (label, dec_val) in decrypted_nodes {
                out.push_str(&format!("[NODE] {}\n", label));
                out.push_str(&format!("  SHA-256   : {}\n", dec_val));
                if let Some(plain) = Self::lookup_potfile(dec_val, &[]) {
                    out.push_str(&format!("  Plaintext : {} (cracked via potfile)\n", plain));
                } else {
                    out.push_str("  Plaintext : [Belum ter-crack di potfile]\n");
                }
            }
        }
        out.push_str("================================================================================\n");

        out
    }

    /// Menyimpan laporan kredensial ke `<backup_dir>/credentials/info_<SN>.txt` (`SPEC.md` §2.3 line 156 & §7.1).
    pub fn save_credentials_report(
        backup_dir: &Path,
        entries: &BTreeMap<String, String>,
        report: &str,
    ) -> io::Result<PathBuf> {
        let creds_dir = backup_dir.join("credentials");
        fs::create_dir_all(&creds_dir)?;
        let raw_sn = entries.get("SN").map(|s| s.as_str()).unwrap_or("UNKNOWN");
        let safe_sn: String = raw_sn
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let filename = format!("info_{}.txt", if safe_sn.is_empty() { "UNKNOWN" } else { &safe_sn });
        let path = creds_dir.join(filename);
        fs::write(&path, report)?;
        Ok(path)
    }

    /// Melakukan ekstraksi kredensial langsung via SSH dari modem hidup (`SPEC.md` §7.1 #2).
    pub fn extract_live_credentials(
        ssh: &crate::sniper::SshSession,
        config: &crate::config::Config,
    ) -> Result<(BTreeMap<String, String>, String, PathBuf), String> {
        let upload_cmd = "mount -o remount,exec /tmp 2>/dev/null; cat > /tmp/test_decrypt_node && chmod 755 /tmp/test_decrypt_node && cp /tmp/test_decrypt_node /configs/test_decrypt_node 2>/dev/null || true";
        let _ = ssh.exec_with_stdin(upload_cmd, crate::servers::TEST_DECRYPT_NODE_BYTES, 15);

        let live_cmd = "((dd if=/dev/block/Factory_MIM bs=8192 count=1 2>/dev/null || head -c 8192 /dev/block/Factory_MIM 2>/dev/null) | (base64 2>/dev/null || /tmp/busybox base64 2>/dev/null)) ; echo '---SHADOW_SPLIT---' ; grep '^root:' /etc/shadow 2>/dev/null ; echo '---NODE_SPLIT---' ; mount -o remount,exec /tmp 2>/dev/null ; /tmp/test_decrypt_node 2>/dev/null";
        let (code, stdout, stderr) = ssh.exec_command(live_cmd, 25)?;
        if code != 0 && stdout.is_empty() {
            return Err(format!("Eksekusi ekstraksi live gagal (code {}): {}", code, stderr));
        }

        let (mim_raw, shadow_line, node_out) =
            if let Some((part_mim, rest1)) = stdout.split_once("---SHADOW_SPLIT---") {
                let clean_b64: String = part_mim.chars().filter(|c| !c.is_whitespace()).collect();
                let raw = B64_STD
                    .decode(&clean_b64)
                    .unwrap_or_else(|_| part_mim.as_bytes().to_vec());

                let (sh, node) =
                    if let Some((part_shadow, part_node)) = rest1.split_once("---NODE_SPLIT---") {
                        let s = part_shadow.trim();
                        (
                            if s.is_empty() {
                                None
                            } else {
                                Some(s.to_string())
                            },
                            part_node.to_string(),
                        )
                    } else {
                        let s = rest1.trim();
                        (
                            if s.is_empty() {
                                None
                            } else {
                                Some(s.to_string())
                            },
                            String::new(),
                        )
                    };
                (raw, sh, node)
            } else {
                (stdout.as_bytes().to_vec(), None, String::new())
            };

        let entries = Self::parse_mim_block(&mim_raw);
        let decrypted_nodes = Self::parse_test_decrypt_node_output(&node_out);
        let report = Self::format_credentials_report(
            &entries,
            "Live SSH (/dev/block/Factory_MIM)",
            shadow_line.as_deref(),
            &decrypted_nodes,
        );
        let saved_path = Self::save_credentials_report(
            Path::new(&config.backup_dir),
            &entries,
            &report,
        ).map_err(|e| format!("Gagal menyimpan laporan kredensial: {}", e))?;

        Ok((entries, report, saved_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mim_block_128b_aligned() {
        let mut block = vec![0u8; 256];
        block[0..7].copy_from_slice(b"Product");
        block[64..76].copy_from_slice(b"5GGW2-OMNI-2");
        block[128..130].copy_from_slice(b"SN");
        block[192..204].copy_from_slice(b"NK1234567890");

        let parsed = FactoryMIMExtractor::parse_mim_block(&block);
        assert_eq!(parsed.get("Product").map(|s| s.as_str()), Some("5GGW2-OMNI-2"));
        assert_eq!(parsed.get("SN").map(|s| s.as_str()), Some("NK1234567890"));
    }

    #[test]
    fn test_decode_mim_password_and_potfile_lookup() {
        let digest = [0xabu8; 32];
        let b64 = B64_STD.encode(digest);
        let hex_hash = FactoryMIMExtractor::decode_mim_password_sha256_hex(&b64).unwrap();
        assert_eq!(hex_hash, "ab".repeat(32));

        let tmp_pot = std::env::temp_dir().join("dbai_test_potfile.pot");
        fs::write(&tmp_pot, format!("{}:NokiaPass2026\n", hex_hash)).unwrap();
        let found = FactoryMIMExtractor::lookup_potfile(&hex_hash, &[tmp_pot.as_path()]);
        let _ = fs::remove_file(&tmp_pot);
        assert_eq!(found.as_deref(), Some("NokiaPass2026"));
    }

    #[test]
    fn test_resolve_shadow_root_hash() {
        let line_factory = format!("root:{}:19000:0:99999:7:::", KNOWN_ROOT_HASH);
        let (hash1, pass1) = FactoryMIMExtractor::resolve_shadow_root_hash(&line_factory);
        assert_eq!(hash1, KNOWN_ROOT_HASH);
        assert_eq!(pass1, Some(KNOWN_ROOT_PASS));

        let line_fastmile = format!("root:{}:19000:0:99999:7:::", DEFAULT_FASTMILE_HASH);
        let (hash2, pass2) = FactoryMIMExtractor::resolve_shadow_root_hash(&line_fastmile);
        assert_eq!(hash2, DEFAULT_FASTMILE_HASH);
        assert_eq!(pass2, Some(DEFAULT_FASTMILE_PASS));

        let (hash3, pass3) = FactoryMIMExtractor::resolve_shadow_root_hash("root:unknown_hash:123");
        assert_eq!(hash3, "unknown_hash");
        assert_eq!(pass3, None);
    }

    #[test]
    fn test_parse_test_decrypt_node_output() {
        let raw = r#"
[RESULT] admin (ground truth):
  ENC: WtWho5AllXU9LfBQqsFt01A4CVXr+ddzi/IK+WiQb0qI233VrgUOCepipbvd03F348dwx93NsSAMk06K9c0dZUC6atGR/m/vZiDf8JJr7gQ=
  DEC: c928c04ecf3da8faae0b0f4fd19aa14e7a2b9213bc540f2f3ff33e792e3d368e
[RESULT] superadmin (current/preset):
  ENC: +j/dPY1c7mbTcKwWk9iZaET6Kx9ysy9TJUpiEXFhj1TpB+uaVR+nE/0E2FdxVDTp17P5+x9GK8W/wsrA5ccLwbhPpvDGUAXhSkbekEj/8Dw=
  DEC: 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9
"#;
        let map = FactoryMIMExtractor::parse_test_decrypt_node_output(raw);
        assert_eq!(
            map.get("admin (ground truth)").map(|s| s.as_str()),
            Some("c928c04ecf3da8faae0b0f4fd19aa14e7a2b9213bc540f2f3ff33e792e3d368e")
        );
        assert_eq!(
            map.get("superadmin (current/preset)").map(|s| s.as_str()),
            Some("240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9")
        );
    }

    #[test]
    fn test_save_credentials_report() {
        let temp_dir = std::env::temp_dir().join(format!("test_creds_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let mut entries = BTreeMap::new();
        entries.insert("SN".to_string(), "ALCLB1234567".to_string());
        let report = "Sample Report";
        let path = FactoryMIMExtractor::save_credentials_report(&temp_dir, &entries, report).unwrap();
        assert_eq!(path.file_name().unwrap(), "info_ALCLB1234567.txt");
        assert_eq!(fs::read_to_string(&path).unwrap(), report);
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
