use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

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
}
