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
            let mut parts = line.split_whitespace();
            let Some(expected_md5) = parts.next() else {
                continue;
            };
            let Some(rel_file) = parts.next() else {
                continue;
            };
            if expected_md5.len() != 32 || !expected_md5.chars().all(|c| c.is_ascii_hexdigit()) {
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

            let local_md5 = Self::calculate_md5(&file_path)?;
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
}

/// Mengekstrak status kesehatan eMMC dari register Extended CSD 512 byte (`offset 267, 268, 269`, `SPEC.md` §5.3 #4).
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
}
