use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use md5::{Digest, Md5};

/// Daftar partisi RW yang dikecualikan (`WAJAR-RW`) saat verifikasi live dump (`SPEC.md` §3.2 #10 & §5.4).
pub const EXCLUDED_PARTITIONS: &[&str] = &[
    "swr.img",
    "userdata",
    "swr",
    "user_data.img",
    "user_data",
    "userdata.img",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    Valid,
    ExcludedRw,
    Corrupt { expected: String, actual: String },
    Missing { expected: String },
}

#[derive(Debug, Clone)]
pub struct PartitionVerifyResult {
    pub filename: String,
    pub status: VerifyStatus,
}

#[derive(Debug, Clone)]
pub struct VerifySummary {
    pub valid_count: usize,
    pub excluded_count: usize,
    pub corrupt_count: usize,
    pub missing_count: usize,
    pub entries: Vec<PartitionVerifyResult>,
}

pub struct MD5Validator;

impl MD5Validator {
    /// Menghitung hash MD5 heksadesimal huruf kecil dari berkas lokal (`SPEC.md` §5.4 `calculate_md5`).
    pub fn calculate_md5(filepath: &Path) -> io::Result<String> {
        let mut f = File::open(filepath)?;
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn is_excluded_rw(filename: &str) -> bool {
        let base = Path::new(filename)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(filename)
            .to_lowercase();
        EXCLUDED_PARTITIONS.iter().any(|&ex| ex == base)
    }

    /// Memverifikasi seluruh entri di `<target_dir>/md5sums.txt` dan menulis `<target_dir>/report.txt` (`SPEC.md` §5.4).
    pub fn verify(target_dir: &Path) -> io::Result<VerifySummary> {
        let md5_path = target_dir.join("md5sums.txt");
        let content = fs::read_to_string(&md5_path)?;

        let mut valid_count = 0usize;
        let mut excluded_count = 0usize;
        let mut corrupt_count = 0usize;
        let mut missing_count = 0usize;
        let mut entries = Vec::new();
        let mut report_lines = vec![
            "============================================================".to_string(),
            " Laporan Verifikasi MD5 Nokia FastMile 5G GW2 (v1.1-rs)".to_string(),
            format!(" Folder Target     : {}", target_dir.display()),
            "============================================================\n".to_string(),
        ];

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((expected_md5, rest)) = line.split_once(char::is_whitespace) else {
                continue;
            };
            let expected_md5 = expected_md5.trim();
            let rel_file = rest.trim().trim_start_matches('*');

            if expected_md5.len() != 32 || !expected_md5.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if rel_file.is_empty()
                || Path::new(rel_file)
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                continue;
            }

            let file_path = target_dir.join(rel_file);
            if !file_path.is_file() {
                missing_count += 1;
                report_lines.push(format!("[HILANG]     {} (Ekspektasi: {})", rel_file, expected_md5));
                entries.push(PartitionVerifyResult {
                    filename: rel_file.to_string(),
                    status: VerifyStatus::Missing {
                        expected: expected_md5.to_lowercase(),
                    },
                });
                continue;
            }

            let local_md5 = match Self::calculate_md5(&file_path) {
                Ok(hash) => hash,
                Err(e) => {
                    corrupt_count += 1;
                    let err_str = format!("io_error: {}", e);
                    report_lines.push(format!(
                        "[KORUP]      {} (Modem: {} | Lokal: {})",
                        rel_file, expected_md5, err_str
                    ));
                    entries.push(PartitionVerifyResult {
                        filename: rel_file.to_string(),
                        status: VerifyStatus::Corrupt {
                            expected: expected_md5.to_lowercase(),
                            actual: err_str,
                        },
                    });
                    continue;
                }
            };
            if local_md5.eq_ignore_ascii_case(expected_md5) {
                valid_count += 1;
                report_lines.push(format!("[VALID]      {} ({})", rel_file, local_md5));
                entries.push(PartitionVerifyResult {
                    filename: rel_file.to_string(),
                    status: VerifyStatus::Valid,
                });
            } else if Self::is_excluded_rw(rel_file) {
                excluded_count += 1;
                report_lines.push(format!(
                    "[WAJAR-RW]   {} (Modem: {} | Lokal: {})",
                    rel_file, expected_md5, local_md5
                ));
                entries.push(PartitionVerifyResult {
                    filename: rel_file.to_string(),
                    status: VerifyStatus::ExcludedRw,
                });
            } else {
                corrupt_count += 1;
                report_lines.push(format!(
                    "[KORUP]      {} (Modem: {} | Lokal: {})",
                    rel_file, expected_md5, local_md5
                ));
                entries.push(PartitionVerifyResult {
                    filename: rel_file.to_string(),
                    status: VerifyStatus::Corrupt {
                        expected: expected_md5.to_lowercase(),
                        actual: local_md5,
                    },
                });
            }
        }

        report_lines.push(format!(
            "\nRINGKASAN:\n- Valid (Aman)         : {}\n- Dikecualikan (RW)    : {} (user_data, swr)\n- Korup/Hash Beda      : {}\n- Hilang/Tidak Lengkap : {}\n",
            valid_count, excluded_count, corrupt_count, missing_count
        ));
        fs::write(target_dir.join("report.txt"), report_lines.join("\n"))?;

        Ok(VerifySummary {
            valid_count,
            excluded_count,
            corrupt_count,
            missing_count,
            entries,
        })
    }

    /// Memverifikasi MD5 dan secara otomatis memanggil `redump_fn` hingga `max_retries` (default 3) kali untuk partisi yang korup/hilang (`SPEC.md` §5.4).
    pub fn verify_with_auto_retry<F>(
        target_dir: &Path,
        max_retries: usize,
        mut redump_fn: F,
    ) -> io::Result<VerifySummary>
    where
        F: FnMut(&str) -> Result<(), String>,
    {
        let mut summary = Self::verify(target_dir)?;
        let mut attempt = 0usize;

        while (summary.corrupt_count > 0 || summary.missing_count > 0) && attempt < max_retries {
            attempt += 1;
            let failed_list: Vec<String> = summary
                .entries
                .iter()
                .filter(|e| {
                    matches!(
                        e.status,
                        VerifyStatus::Corrupt { .. } | VerifyStatus::Missing { .. }
                    )
                })
                .map(|e| e.filename.clone())
                .collect();

            if failed_list.is_empty() {
                break;
            }

            for rel_name in &failed_list {
                let _ = redump_fn(rel_name);
            }
            summary = Self::verify(target_dir)?;
        }

        Ok(summary)
    }
}

/// Mengekstrak status kesehatan eMMC dari register Extended CSD 512 byte.
/// Mengembalikan tuple `(life_a, life_b, pre_eol)` dari offset 268 (DEVICE_LIFE_TIME_EST_TYP_A),
/// 269 (DEVICE_LIFE_TIME_EST_TYP_B), dan 267 (PRE_EOL_INFO) (`SPEC.md` §5.3 #4).
pub fn parse_ext_csd_health(ext_csd: &[u8]) -> Option<(String, String, String)> {
    if ext_csd.len() < 270 {
        return None;
    }
    let pre_eol = ext_csd[267];
    let life_a = ext_csd[268];
    let life_b = ext_csd[269];

    let map_life = |v: u8| -> &'static str {
        match v {
            0x01 => "0% - 10% (Sangat Baik / Seperti Baru)",
            0x02 => "10% - 20% (Sangat Baik)",
            0x03 => "20% - 30% (Baik)",
            0x04 => "30% - 40% (Baik)",
            0x05 => "40% - 50% (Normal)",
            0x06 => "50% - 60% (Normal)",
            0x07 => "60% - 70% (Mulai Menua)",
            0x08 => "70% - 80% (Menua)",
            0x09 => "80% - 90% (Kritis)",
            0x0a => "90% - 100% (Habis Masa Pakai)",
            0x0b => ">100% (Melebihi Estimasi Usia)",
            _ => "Tidak Diketahui",
        }
    };
    let map_eol = |v: u8| -> &'static str {
        match v {
            0x01 => "Normal (Kondisi Prima / <80% blok cadangan terpakai)",
            0x02 => "Warning (80% blok cadangan terpakai)",
            0x03 => "Urgent (>90% blok cadangan terpakai)",
            _ => "Tidak Diketahui",
        }
    };

    Some((
        format!("0x{:02x} -> {}", life_a, map_life(life_a)),
        format!("0x{:02x} -> {}", life_b, map_life(life_b)),
        format!("0x{:02x} -> {}", pre_eol, map_eol(pre_eol)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_excluded_rw_check() {
        assert!(MD5Validator::is_excluded_rw("user_data.img"));
        assert!(MD5Validator::is_excluded_rw("swr.img"));
        assert!(!MD5Validator::is_excluded_rw("boot_a.img"));
    }

    #[test]
    fn test_parse_ext_csd_health() {
        let mut raw = vec![0u8; 512];
        raw[267] = 0x01;
        raw[268] = 0x01;
        raw[269] = 0x02;
        let (a, b, eol) = parse_ext_csd_health(&raw).unwrap();
        assert!(a.contains("0% - 10%"));
        assert!(b.contains("10% - 20%"));
        assert!(eol.contains("Normal"));
    }
    #[test]
    fn test_verify_spaces_and_path_traversal() {
        let temp_dir = std::env::temp_dir().join(format!("test_md5_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();

        let file1 = temp_dir.join("file with spaces.img");
        fs::write(&file1, b"hello world").unwrap();
        let hash1 = MD5Validator::calculate_md5(&file1).unwrap();

        let md5sums_content = format!(
            "{} *file with spaces.img\n{} ../escape.img\n{} normal.img\n",
            hash1, hash1, hash1
        );
        fs::write(temp_dir.join("md5sums.txt"), md5sums_content).unwrap();

        let summary = MD5Validator::verify(&temp_dir).unwrap();
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.missing_count, 1); // normal.img is missing
        // ../escape.img was skipped due to Component::ParentDir
        assert_eq!(summary.entries.len(), 2);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
