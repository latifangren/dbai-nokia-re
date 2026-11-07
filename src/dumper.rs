use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::config::Config;
use crate::md5_verifier::parse_ext_csd_health;
use crate::sniper::SshSession;

/// Batas ruang kosong minimum disk PC (`5.0` GB) sebelum memulai full dump eMMC (`SPEC.md` §5.3 #3).
pub const MIN_FREE_DISK_GB: f64 = 5.0;

/// Memetakan kode `manfid` sysfs eMMC ke nama pabrikan dan marking fisik (`SPEC.md` §5.3 #1).
pub fn lookup_emmc_vendor(manfid: &str) -> (&'static str, Option<&'static str>) {
    let norm = manfid.trim().to_lowercase();
    match norm.as_str() {
        "0x0000f4" | "0xf4" | "f4" => (
            "BIWIN (Shenzhen Biwin Storage Technology)",
            Some("BWCMAB811G04G 233254126 1258RD (BIWIN 4GB eMMC 5.1 BGA-153)"),
        ),
        "0x000015" | "0x15" | "15" => ("Samsung Electronics", None),
        "0x000090" | "0x90" | "90" => ("SK Hynix", None),
        "0x000013" | "0x13" | "13" => ("Micron Technology", None),
        "0x000011" | "0x11" | "11" => ("Toshiba / Kioxia", None),
        "0x000045" | "0x45" | "45" => ("SanDisk / Western Digital", None),
        "0x000070" | "0x70" | "70" => ("Kingston Technology", None),
        _ => ("Unknown eMMC Manufacturer", None),
    }
}

/// Memeriksa ketersediaan ruang bebas disk pada direktori target dalam satuan GiB (`SPEC.md` §5.3 #3).
pub fn check_free_disk_space_gb(target_dir: &Path) -> io::Result<f64> {
    let check_path = if target_dir.exists() {
        target_dir.to_path_buf()
    } else {
        std::env::current_dir()?
    };

    #[cfg(unix)]
    {
        if let Ok(out) = std::process::Command::new("df")
            .arg("-Pk")
            .arg(&check_path)
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Some(data_line) = text.lines().nth(1) {
                    let cols: Vec<&str> = data_line.split_whitespace().collect();
                    if cols.len() >= 4 {
                        if let Ok(avail_kib) = cols[3].parse::<u64>() {
                            return Ok((avail_kib as f64) / (1024.0 * 1024.0));
                        }
                    }
                }
            }
        }
    }

    Ok(100.0)
}

pub struct DumperEngine;

impl DumperEngine {
    /// Menghasilkan skrip shell untuk mengekstrak seluruh 50 partisi user-area + `boot0`/`boot1` + `ext_csd` (`SPEC.md` §5.3 #2).
    pub fn generate_dump_bash(pc_ip: &str, http_port: u16, tcp_port: u16) -> String {
        format!(
            r#"#!/bin/sh
mount -o remount,exec /tmp 2>/dev/null
if [ ! -x /tmp/busybox ]; then
    wget -qO /tmp/busybox http://{pc_ip}:{http_port}/busybox || curl -s http://{pc_ip}:{http_port}/busybox -o /tmp/busybox
    chmod 755 /tmp/busybox
fi
[ -x /tmp/busybox ] || {{ echo "Gagal mengunduh /tmp/busybox dari PC" >&2; exit 1; }}
rm -f /tmp/md5sums.txt
touch /tmp/md5sums.txt

# 1. Dump Boot Partition 0 & 1
for b in mmcblk0boot0 mmcblk0boot1; do
    if [ -b "/dev/$b" ]; then
        (printf "non-userarea/${{b}}.bin::::" ; cat "/dev/$b") | /tmp/busybox nc {pc_ip} {tcp_port}
        m=$(/tmp/busybox md5sum "/dev/$b" | /tmp/busybox awk '{{print $1}}')
        echo "$m  non-userarea/${{b}}.bin" >> /tmp/md5sums.txt
    fi
done

# 2. Dump Extended CSD (512 byte binary & text)
if [ -r /sys/kernel/debug/mmc0/mmc0:0001/ext_csd ]; then
    (printf "non-userarea/ext_csd.bin::::" ; /tmp/busybox xxd -r -p /sys/kernel/debug/mmc0/mmc0:0001/ext_csd 2>/dev/null || cat /sys/kernel/debug/mmc0/mmc0:0001/ext_csd) | /tmp/busybox nc {pc_ip} {tcp_port}
fi
if command -v mmc >/dev/null 2>&1; then
    (printf "non-userarea/ext_csd.txt::::" ; mmc extcsd read /dev/mmcblk0 2>/dev/null) | /tmp/busybox nc {pc_ip} {tcp_port}
fi

# 3. Iterasi seluruh 50 partisi /dev/mmcblk0p*
for part in /dev/mmcblk0p*; do
    [ -b "$part" ] || continue
    pname=$(basename "$part")
    label=$(grep '^PARTNAME=' "/sys/block/mmcblk0/$pname/uevent" 2>/dev/null | cut -d= -f2)
    [ -z "$label" ] && label="$pname"
    (printf "${{label}}.img::::" ; cat "$part") | /tmp/busybox nc {pc_ip} {tcp_port}
    m=$(/tmp/busybox md5sum "$part" | /tmp/busybox awk '{{print $1}}')
    echo "$m  ${{label}}.img" >> /tmp/md5sums.txt
done

# 4. Kirim manifest md5sums.txt paling akhir (sinyal selesai)
(printf "md5sums.txt::::" ; cat /tmp/md5sums.txt) | /tmp/busybox nc {pc_ip} {tcp_port}
"#,
            pc_ip = pc_ip,
            http_port = http_port,
            tcp_port = tcp_port
        )
    }

    /// Menghasilkan skrip shell untuk mengarsipkan `/data` dan `/rom/etc` menjadi `.tar.gz` via TCP 8888 (`SPEC.md` §6 S2).
    pub fn generate_tarball_bash(pc_ip: &str, http_port: u16, tcp_port: u16) -> String {
        format!(
            r#"#!/bin/sh
mount -o remount,exec /tmp 2>/dev/null
if [ ! -x /tmp/busybox ]; then
    wget -qO /tmp/busybox http://{pc_ip}:{http_port}/busybox || curl -s http://{pc_ip}:{http_port}/busybox -o /tmp/busybox
    chmod 755 /tmp/busybox
fi
[ -x /tmp/busybox ] || {{ echo "Gagal mengunduh /tmp/busybox dari PC" >&2; exit 1; }}
if [ -d /data ]; then
    (printf "user_data_dir.tar.gz::::" ; /tmp/busybox tar -czf - /data 2>/dev/null) | /tmp/busybox nc {pc_ip} {tcp_port}
fi
if [ -d /rom/etc ]; then
    (printf "rom_etc_dir.tar.gz::::" ; /tmp/busybox tar -czf - /rom/etc 2>/dev/null) | /tmp/busybox nc {pc_ip} {tcp_port}
fi
"#,
            pc_ip = pc_ip,
            http_port = http_port,
            tcp_port = tcp_port
        )
    }

    /// Menghasilkan skrip shell untuk mengunduh ulang satu partisi spesifik dan memperbarui `/tmp/md5sums.txt` (`SPEC.md` §5.3 #5).
    pub fn generate_redump_single_bash(
        pc_ip: &str,
        http_port: u16,
        tcp_port: u16,
        target_rel: &str,
    ) -> String {
        if target_rel.is_empty()
            || !target_rel
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '/' || c == '-')
        {
            return "#!/bin/sh\necho \"Target partisi tidak valid\" >&2\nexit 1\n".to_string();
        }

        let clean_label = target_rel
            .trim_start_matches("non-userarea/")
            .trim_end_matches(".img")
            .trim_end_matches(".bin");
        format!(
            r#"#!/bin/sh
mount -o remount,exec /tmp 2>/dev/null
if [ ! -x /tmp/busybox ]; then
    wget -qO /tmp/busybox http://{pc_ip}:{http_port}/busybox || curl -s http://{pc_ip}:{http_port}/busybox -o /tmp/busybox
    chmod 755 /tmp/busybox
fi
[ -x /tmp/busybox ] || {{ echo "Gagal mengunduh /tmp/busybox dari PC" >&2; exit 1; }}

if [ "{clean_label}" = "ext_csd" ]; then
    if [ -r /sys/kernel/debug/mmc0/mmc0:0001/ext_csd ]; then
        (printf "non-userarea/ext_csd.bin::::" ; /tmp/busybox xxd -r -p /sys/kernel/debug/mmc0/mmc0:0001/ext_csd 2>/dev/null || cat /sys/kernel/debug/mmc0/mmc0:0001/ext_csd) | /tmp/busybox nc {pc_ip} {tcp_port}
        exit 0
    else
        echo "Partisi {clean_label} tidak ditemukan" >&2
        exit 1
    fi
fi

target_dev=""
if [ "{clean_label}" = "mmcblk0boot0" ] || [ "{clean_label}" = "mmcblk0boot1" ]; then
    if [ -b "/dev/{clean_label}" ]; then
        target_dev="/dev/{clean_label}"
    fi
else
    for uev in /sys/block/mmcblk0/mmcblk0p*/uevent; do
        if grep -q "^PARTNAME={clean_label}$" "$uev" 2>/dev/null; then
            pdir=$(dirname "$uev")
            pname=$(basename "$pdir")
            target_dev="/dev/$pname"
            break
        fi
    done
    if [ -z "$target_dev" ] && [ -b "/dev/{clean_label}" ]; then
        target_dev="/dev/{clean_label}"
    fi
fi

if [ -n "$target_dev" ] && [ -b "$target_dev" ]; then
    (printf "{target_rel}::::" ; cat "$target_dev") | /tmp/busybox nc {pc_ip} {tcp_port}
    m=$(/tmp/busybox md5sum "$target_dev" | /tmp/busybox awk '{{print $1}}')
    /tmp/busybox sed -i "\|  {target_rel}$|d" /tmp/md5sums.txt 2>/dev/null
    echo "$m  {target_rel}" >> /tmp/md5sums.txt
    (printf "md5sums.txt::::" ; cat /tmp/md5sums.txt) | /tmp/busybox nc {pc_ip} {tcp_port}
else
    echo "Partisi {clean_label} tidak ditemukan" >&2
    exit 1
fi
"#,
            pc_ip = pc_ip,
            http_port = http_port,
            tcp_port = tcp_port,
            clean_label = clean_label,
            target_rel = target_rel
        )
    }

    /// Mem-parsing keluaran sysfs `/sys/block/mmcblk0` dan membentuk laporan `info_eMMC.txt` (`SPEC.md` §5.3 #1).
    pub fn format_emmc_info_report(attrs: &BTreeMap<String, String>) -> String {
        let get = |k: &str| attrs.get(k).map(|s| s.trim()).unwrap_or("N/A");
        let manfid = get("manfid");
        let (vendor_name, physical_marking) = lookup_emmc_vendor(manfid);
        let sectors = get("size").parse::<u64>().unwrap_or(0);
        let size_gib = (sectors as f64 * 512.0) / (1024.0 * 1024.0 * 1024.0);

        let mut lines = vec![
            "============================================================".to_string(),
            "         LAPORAN IDENTITAS & KESEHATAN CHIP eMMC            ".to_string(),
            "============================================================".to_string(),
            format!("Nama Chip (Product) : {}", get("name")),
            format!("Manufacturer ID     : {} -> {}", manfid, vendor_name),
        ];
        if let Some(mark) = physical_marking {
            lines.push(format!("Physical Marking    : {}", mark));
        }
        lines.push(format!("OEM ID              : {}", get("oemid")));
        lines.push(format!("Serial Number       : {}", get("serial")));
        lines.push(format!("Production Date     : {}", get("date")));
        lines.push(format!("Hardware Revision   : {}", get("prv")));
        lines.push(format!(
            "Kapasitas User Area : {} sektor ({:.2} GiB)",
            sectors, size_gib
        ));
        lines.push(format!("Sysfs Life Time     : {}", get("life_time")));
        lines.push(format!("Sysfs Pre-EOL Info  : {}", get("pre_eol_info")));
        lines.push("============================================================".to_string());
        lines.join("\n")
    }

    /// Mengambil atribut sysfs eMMC melalui SSH dan menyimpan `CID.txt`, `CSD.txt`, serta `info_eMMC.txt` (`SPEC.md` §5.3 #1).
    pub fn fetch_emmc_info(ssh: &SshSession, config: &Config) -> Result<String, String> {
        let sysfs_cmd = r#"
for f in cid csd name manfid oemid serial date prv type life_time pre_eol_info; do
    val=$(cat "/sys/block/mmcblk0/device/$f" 2>/dev/null | tr -d '\r\n')
    echo "$f=$val"
done
sz=$(cat /sys/block/mmcblk0/size 2>/dev/null | tr -d '\r\n')
echo "size=$sz"
"#;
        let (_, stdout, _) = ssh.exec_command(sysfs_cmd, 10)?;
        let mut attrs = BTreeMap::new();
        for line in stdout.lines() {
            if let Some((k, v)) = line.split_once('=') {
                attrs.insert(k.trim().to_string(), v.trim().to_string());
            }
        }

        let non_user_dir = Path::new(&config.backup_dir).join("non-userarea");
        fs::create_dir_all(&non_user_dir)
            .map_err(|e| format!("Gagal membuat direktori non-userarea: {}", e))?;

        if let Some(cid) = attrs.get("cid") {
            let _ = fs::write(non_user_dir.join("CID.txt"), format!("{}\n", cid));
        }
        if let Some(csd) = attrs.get("csd") {
            let _ = fs::write(non_user_dir.join("CSD.txt"), format!("{}\n", csd));
        }

        let report = Self::format_emmc_info_report(&attrs);
        fs::write(non_user_dir.join("info_eMMC.txt"), &report)
            .map_err(|e| format!("Gagal menulis info_eMMC.txt: {}", e))?;
        Ok(report)
    }

    /// Memperbarui bagian kesehatan eMMC pada `non-userarea/info_eMMC.txt` dari byte offset 267-269 `ext_csd.bin` (`SPEC.md` §5.3 #4).
    pub fn update_health_from_extcsd(backup_dir: &Path) -> io::Result<Option<String>> {
        let non_user_dir = backup_dir.join("non-userarea");
        let ext_bin_path = non_user_dir.join("ext_csd.bin");
        if !ext_bin_path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&ext_bin_path)?;
        let Some((life_a, life_b, pre_eol)) = parse_ext_csd_health(&raw) else {
            return Ok(None);
        };

        let health_section = format!(
            "\n[EXT_CSD HEALTH REPORT (JEDEC Offset 267-269)]\n\
             PRE_EOL_INFO (Offset 267)             : {}\n\
             DEVICE_LIFE_TIME_EST_TYP_A (Offset 268): {}\n\
             DEVICE_LIFE_TIME_EST_TYP_B (Offset 269): {}\n",
            pre_eol, life_a, life_b
        );

        let info_path = non_user_dir.join("info_eMMC.txt");
        let mut current = fs::read_to_string(&info_path).unwrap_or_default();
        if !current.contains("[EXT_CSD HEALTH REPORT") {
            current.push_str(&health_section);
            fs::write(&info_path, &current)?;
        }
        Ok(Some(health_section))
    }

    /// Menjalankan full dump 52 partisi eMMC melalui SSH (`SPEC.md` §5.3 #3).
    pub fn execute_dump_ssh(ssh: &SshSession, config: &Config) -> Result<(), String> {
        let _ = Self::fetch_emmc_info(ssh, config)?;
        let script = Self::generate_dump_bash(&config.pc_ip, config.http_port, config.tcp_port);
        let (code, _, stderr) = ssh.exec_with_stdin("/bin/sh", script.as_bytes(), 15)?;
        if code != 0 {
            return Err(format!(
                "Skrip dump eMMC berhenti dengan kode {}: {}",
                code,
                stderr.trim()
            ));
        }
        let _ = Self::update_health_from_extcsd(Path::new(&config.backup_dir));
        Ok(())
    }

    /// Menjalankan backup tarball direktori `/data` dan `/rom/etc` melalui SSH (`SPEC.md` §6 S2).
    pub fn execute_tarball_ssh(ssh: &SshSession, config: &Config) -> Result<(), String> {
        let script = Self::generate_tarball_bash(&config.pc_ip, config.http_port, config.tcp_port);
        let (code, _, stderr) = ssh.exec_with_stdin("/bin/sh", script.as_bytes(), 15)?;
        if code != 0 {
            return Err(format!(
                "Skrip tarball berhenti dengan kode {}: {}",
                code,
                stderr.trim()
            ));
        }
        Ok(())
    }

    /// Mengunduh ulang satu partisi yang gagal verifikasi MD5 (`SPEC.md` §5.3 #5).
    pub fn redump_single_partition(
        ssh: &SshSession,
        config: &Config,
        target_rel: &str,
    ) -> Result<(), String> {
        let script = Self::generate_redump_single_bash(
            &config.pc_ip,
            config.http_port,
            config.tcp_port,
            target_rel,
        );
        let (code, _, stderr) = ssh.exec_with_stdin("/bin/sh", script.as_bytes(), 15)?;
        if code != 0 {
            return Err(format!(
                "Redump partisi {} gagal (kode {}): {}",
                target_rel,
                code,
                stderr.trim()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biwin_vendor_lookup_and_report() {
        let (vendor, marking) = lookup_emmc_vendor("0x0000f4");
        assert_eq!(vendor, "BIWIN (Shenzhen Biwin Storage Technology)");
        assert_eq!(
            marking,
            Some("BWCMAB811G04G 233254126 1258RD (BIWIN 4GB eMMC 5.1 BGA-153)")
        );

        let mut attrs = BTreeMap::new();
        attrs.insert("name".to_string(), "BWCMAB".to_string());
        attrs.insert("manfid".to_string(), "0x0000f4".to_string());
        attrs.insert("size".to_string(), "7733248".to_string());
        let report = DumperEngine::format_emmc_info_report(&attrs);
        assert!(report.contains("BIWIN (Shenzhen Biwin Storage Technology)"));
        assert!(report.contains("BWCMAB811G04G"));
        assert!(report.contains("3.69 GiB"));
    }

    #[test]
    fn test_generate_dump_and_redump_scripts() {
        let dump_sh = DumperEngine::generate_dump_bash("192.168.1.2", 8081, 8888);
        assert!(dump_sh.contains("http://192.168.1.2:8081/busybox"));
        assert!(dump_sh.contains("non-userarea/${b}.bin::::"));
        assert!(dump_sh.contains("md5sums.txt::::"));

        let redump_sh =
            DumperEngine::generate_redump_single_bash("192.168.1.2", 8081, 8888, "boot.img");
        assert!(redump_sh.contains("^PARTNAME=boot$"));
        assert!(redump_sh.contains("boot.img::::"));
    }

    #[test]
    fn test_update_health_from_extcsd_jedec_offsets() {
        let temp_dir = std::env::temp_dir().join(format!("test_extcsd_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let non_user = temp_dir.join("non-userarea");
        fs::create_dir_all(&non_user).unwrap();

        let mut raw = vec![0u8; 512];
        raw[267] = 0x01; // Normal
        raw[268] = 0x02; // 10% - 20%
        raw[269] = 0x03; // 20% - 30%
        fs::write(non_user.join("ext_csd.bin"), &raw).unwrap();
        fs::write(non_user.join("info_eMMC.txt"), "Device: eMMC\n").unwrap();

        let res = DumperEngine::update_health_from_extcsd(&temp_dir).unwrap();
        assert!(res.is_some());
        let content = fs::read_to_string(non_user.join("info_eMMC.txt")).unwrap();
        let line_eol = content.lines().find(|l| l.contains("PRE_EOL_INFO (Offset 267)")).unwrap();
        assert!(line_eol.contains("Normal"));
        let line_a = content.lines().find(|l| l.contains("DEVICE_LIFE_TIME_EST_TYP_A (Offset 268)")).unwrap();
        assert!(line_a.contains("10% - 20%"));
        let line_b = content.lines().find(|l| l.contains("DEVICE_LIFE_TIME_EST_TYP_B (Offset 269)")).unwrap();
        assert!(line_b.contains("20% - 30%"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_generate_redump_single_bash_rejects_metachars() {
        let bad_targets = [
            "boot.img; rm -rf /",
            "test$(whoami).img",
            "`id`.bin",
            "foo|bar.img",
            "foo&bar.img",
            "",
            "part with spaces.img",
        ];
        for bad in bad_targets {
            let script = DumperEngine::generate_redump_single_bash("192.168.1.2", 8081, 8888, bad);
            assert!(script.contains("exit 1"));
            assert!(!script.contains("PARTNAME="));
        }
    }
}
