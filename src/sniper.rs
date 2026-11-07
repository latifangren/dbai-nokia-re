use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use sha2::{Digest, Sha256};

use crate::config::Config;

/// Daftar 4 port pemantauan siklus reboot (`SPEC.md` §5.2 `wait_for_shutdown`).
pub const DEFAULT_CHECK_PORTS: [u16; 4] = [443, 80, 53, 2222];

/// Batas maksimum uptime kernel (`detik`) agar sesi dianggap berasal dari boot baru (`SPEC.md` §5.2).
pub const MAX_FRESH_BOOT_UPTIME_SECS: f64 = 90.0;

/// Perintah Langkah 1 OTA: Membaca versi firmware aktif (`SPEC.md` §7.3).
pub const OTA_CMD_READ_VERSION: &str = "cat /etc/version 2>/dev/null || uname -a";

/// Perintah Langkah 2 OTA: Mengaktifkan modul Software Management di datamodel TR-069 (`SPEC.md` §7.3).
pub const OTA_CMD_ENABLE_SWMGNT: &str =
    "cfgcli -s InternetGatewayDevice.X_ALU-COM_Wifi.X_ALU-COM_SwMgnt.X_ALU-COM_Enable true 2>/dev/null && cfgcli --save-db 2>/dev/null";

/// Perintah Langkah 3 OTA: Me-restart daemon `swmgnt` (`SPEC.md` §7.3).
pub const OTA_CMD_RESTART_SWMGNT: &str = "killall -9 swmgnt 2>/dev/null ; /usr/bin/swmgnt &";

/// Perintah Langkah 4 OTA: Memicu sinyal D-Bus dan skrip OTA (`SPEC.md` §7.3).
pub const OTA_CMD_DBUS_TRIGGER: &str =
    "dbus-send --system --type=signal /nokia/swmgnt nokia.swmgnt.triggerOtaPollingFromPortal 2>/dev/null ; dbus-send --system --type=signal /nokia/swmgnt nokia.swmgnt.pollMatrixFromCloud 2>/dev/null ; sysevent set OTATrigger 1 2>/dev/null ; /bin/swm.sh OTATrigger 1 2>/dev/null";

/// Perintah Langkah 5 OTA: Membaca log unduhan FOTA (`SPEC.md` §7.3).
pub const OTA_CMD_READ_FOTA_LOG: &str =
    "cat /logs/download_data_From_clould.txt 2>/dev/null || cat /tmp/init_script.log 2>/dev/null | tail -n 20";

/// Memeriksa apakah minimal satu port pada `ports` menerima koneksi TCP dalam batas `per_port_timeout`.
pub fn is_any_port_open(ip: &str, ports: &[u16], per_port_timeout: Duration) -> bool {
    let Ok(addr_ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    for &port in ports {
        let sock = SocketAddr::new(addr_ip, port);
        if TcpStream::connect_timeout(&sock, per_port_timeout).is_ok() {
            return true;
        }
    }
    false
}

/// Memantau siklus reboot modem (`443, 80, 53, 2222`) hingga 2 kali berturut-turut offline setelah sempat online (`SPEC.md` §5.2).
pub fn wait_for_shutdown(ip: &str, check_ports: &[u16], timeout: Duration) -> bool {
    let start = Instant::now();
    let probe_timeout = Duration::from_millis(250);
    let mut saw_online = false;
    let mut consecutive_offline = 0u32;

    while start.elapsed() < timeout {
        if is_any_port_open(ip, check_ports, probe_timeout) {
            saw_online = true;
            consecutive_offline = 0;
        } else {
            consecutive_offline += 1;
            if saw_online && consecutive_offline >= 2 {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Mem-parsing angka pertama (detik uptime) dari isi `/proc/uptime` (`SPEC.md` §5.2).
pub fn parse_proc_uptime(raw: &str) -> Option<f64> {
    let first_token = raw.split_whitespace().next()?;
    first_token.parse::<f64>().ok()
}

/// Memeriksa apakah nilai `/proc/uptime` memenuhi syarat sesi boot baru (`<= 90.0` detik) (`SPEC.md` §5.2).
pub fn is_fresh_boot_uptime(uptime_secs: f64) -> bool {
    uptime_secs >= 0.0 && uptime_secs <= MAX_FRESH_BOOT_UPTIME_SECS
}

/// Memeriksa apakah port SSH target sudah merespons banner protokol `SSH-` (`SPEC.md` §5.2).
pub fn probe_ssh_banner(ip: &str, port: u16, timeout: Duration) -> bool {
    let Ok(addr_ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    let sock = SocketAddr::new(addr_ip, port);
    let Ok(mut stream) = TcpStream::connect_timeout(&sock, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let mut buf = [0u8; 32];
    match stream.read(&mut buf) {
        Ok(n) if n >= 4 => buf[..n].starts_with(b"SSH-"),
        _ => false,
    }
}

/// Menghitung digest SHA-256 huruf besar (`UPPERCASE`) untuk password SuperAdmin (`SPEC.md` §7.2).
pub fn format_superadmin_pwd_sha256_upper(new_pwd: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(new_pwd.as_bytes());
    hex::encode_upper(hasher.finalize())
}

/// Membentuk rangkaian perintah `cfgcli` untuk mengubah password SuperAdmin Web GUI (`SPEC.md` §7.2).
pub fn build_superadmin_cfgcli_cmd(new_pwd: &str) -> (String, String) {
    let sha_upper = format_superadmin_pwd_sha256_upper(new_pwd);
    let cmd = format!(
        "cfgcli -s InternetGatewayDevice.X_Authentication.WebAccount.Enable 1 && \
         cfgcli -s InternetGatewayDevice.X_Authentication.WebAccount.Password {} && \
         cfgcli --save-db",
        sha_upper
    );
    (sha_upper, cmd)
}

#[derive(Debug, Clone)]
pub struct OtaTriggerReport {
    pub active_version: String,
    pub swmgnt_enabled_out: String,
    pub dbus_trigger_out: String,
    pub fota_log_tail: String,
}

#[derive(Debug, Clone)]
pub struct SshSession {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key_path: PathBuf,
}

impl SshSession {
    pub fn new(host: &str, port: u16, user: &str, key_path: &Path) -> Self {
        Self {
            host: host.to_string(),
            port,
            user: user.to_string(),
            key_path: key_path.to_path_buf(),
        }
    }

    /// Melakukan polling port `(2222, 22)` hingga sesi SSH siap dan (opsional) memverifikasi `/proc/uptime <= 90.0` (`SPEC.md` §5.2).
    pub fn connect_or_poll(
        config: &Config,
        timeout_total: Duration,
        require_fresh_boot: bool,
    ) -> Result<(Self, f64), String> {
        let start = Instant::now();
        let key_path = PathBuf::from(&config.key_name);
        let banner_timeout = Duration::from_millis(800);

        while start.elapsed() < timeout_total {
            for &port in &config.ssh_ports {
                if !probe_ssh_banner(&config.modem_ip, port, banner_timeout) {
                    continue;
                }
                let candidate = Self::new(&config.modem_ip, port, &config.ssh_user, &key_path);
                if let Ok((0, stdout, _)) = candidate.exec_command("cat /proc/uptime", 3) {
                    if let Some(uptime) = parse_proc_uptime(&stdout) {
                        if require_fresh_boot && !is_fresh_boot_uptime(uptime) {
                            // Sesi lama sebelum reboot selesai (dying session)
                            std::thread::sleep(Duration::from_millis(400));
                            continue;
                        }
                        return Ok((candidate, uptime));
                    }
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            std::thread::sleep(Duration::from_millis(400));
        }

        Err(format!(
            "Timeout ({} detik) menunggu sesi SSH aktif di {}: {:?}",
            timeout_total.as_secs(),
            config.modem_ip,
            config.ssh_ports
        ))
    }

    fn base_ssh_args(&self, connect_timeout_secs: u64) -> Vec<String> {
        let mut args = vec![
            "-p".to_string(),
            self.port.to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(),
            "LogLevel=ERROR".to_string(),
            "-o".to_string(),
            format!("ConnectTimeout={}", connect_timeout_secs.max(1)),
        ];
        if self.key_path.exists() {
            args.push("-i".to_string());
            args.push(self.key_path.to_string_lossy().to_string());
        }
        args
    }

    /// Mengeksekusi satu perintah shell jarak jauh melalui SSH dan mengembalikan `(exit_code, stdout, stderr)`.
    pub fn exec_command(
        &self,
        remote_cmd: &str,
        connect_timeout_secs: u64,
    ) -> Result<(i32, String, String), String> {
        let mut cmd = Command::new("ssh");
        for arg in self.base_ssh_args(connect_timeout_secs) {
            cmd.arg(arg);
        }
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg(format!("{}@{}", self.user, self.host));
        cmd.arg(remote_cmd);

        let out = cmd
            .output()
            .map_err(|e| format!("Gagal menjalankan klien ssh sistem: {}", e))?;
        let code = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        Ok((code, stdout, stderr))
    }

    /// Mengeksekusi perintah jarak jauh sambil mengalirkan `stdin_bytes` (misal skrip dump atau biner helper dari RAM).
    pub fn exec_with_stdin(
        &self,
        remote_cmd: &str,
        stdin_bytes: &[u8],
        connect_timeout_secs: u64,
    ) -> Result<(i32, String, String), String> {
        let mut cmd = Command::new("ssh");
        for arg in self.base_ssh_args(connect_timeout_secs) {
            cmd.arg(arg);
        }
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg(format!("{}@{}", self.user, self.host));
        cmd.arg(remote_cmd);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Gagal menjalankan proses ssh: {}", e))?;
        if let Some(mut child_stdin) = child.stdin.take() {
            child_stdin
                .write_all(stdin_bytes)
                .map_err(|e| format!("Gagal menulis payload ke stdin ssh: {}", e))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("Gagal menunggu hasil proses ssh: {}", e))?;
        let code = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        Ok((code, stdout, stderr))
    }

    /// Membuka sesi terminal interaktif langsung ke modem menggunakan klien `ssh` OS (`SPEC.md` §7 `[4]`).
    pub fn open_interactive_shell(&self) -> io::Result<i32> {
        let mut cmd = Command::new("ssh");
        for arg in self.base_ssh_args(5) {
            cmd.arg(arg);
        }
        cmd.arg(format!("{}@{}", self.user, self.host));
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = cmd.status()?;
        Ok(status.code().unwrap_or(0))
    }

    /// Mengubah password SuperAdmin Web GUI melalui `cfgcli` (`SPEC.md` §7.2 Menu `[s]`).
    pub fn change_superadmin_password(&self, new_pwd: &str) -> Result<String, String> {
        let (sha_upper, cmd) = build_superadmin_cfgcli_cmd(new_pwd);
        let (code, stdout, stderr) = self.exec_command(&cmd, 15)?;
        if code != 0 {
            return Err(format!(
                "cfgcli keluar dengan kode {}: {} {}",
                code,
                stdout.trim(),
                stderr.trim()
            ));
        }
        Ok(sha_upper)
    }

    /// Menjalankan 5 langkah berurutan untuk memicu pembaruan firmware OTA (`SPEC.md` §7.3 Menu `[m]`).
    pub fn trigger_ota_update(&self) -> Result<OtaTriggerReport, String> {
        let (_, ver_out, _) = self.exec_command(OTA_CMD_READ_VERSION, 10)?;
        let (_, swm_out, _) = self.exec_command(OTA_CMD_ENABLE_SWMGNT, 15)?;
        let _ = self.exec_command(OTA_CMD_RESTART_SWMGNT, 10)?;
        let (_, dbus_out, _) = self.exec_command(OTA_CMD_DBUS_TRIGGER, 15)?;

        std::thread::sleep(Duration::from_secs(5));
        let (_, log_out, _) = self.exec_command(OTA_CMD_READ_FOTA_LOG, 10)?;

        Ok(OtaTriggerReport {
            active_version: ver_out.trim().to_string(),
            swmgnt_enabled_out: swm_out.trim().to_string(),
            dbus_trigger_out: dbus_out.trim().to_string(),
            fota_log_tail: log_out.trim().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_parse_and_check_proc_uptime() {
        assert_eq!(parse_proc_uptime("42.19 80.11\n"), Some(42.19));
        assert!(is_fresh_boot_uptime(42.19));
        assert!(is_fresh_boot_uptime(90.0));
        assert!(!is_fresh_boot_uptime(90.01));
        assert_eq!(parse_proc_uptime(""), None);
    }

    #[test]
    fn test_superadmin_cfgcli_sha256_uppercase() {
        let (sha, cmd) = build_superadmin_cfgcli_cmd("admin123");
        assert_eq!(
            sha,
            "240BE518FABD2724DDB6F04EEB1DA5967448D7E831C08C8FA822809F74C720A9"
        );
        assert!(cmd.contains("InternetGatewayDevice.X_Authentication.WebAccount.Enable 1"));
        assert!(cmd.contains(&format!(
            "InternetGatewayDevice.X_Authentication.WebAccount.Password {}",
            sha
        )));
        assert!(cmd.ends_with("cfgcli --save-db"));
    }

    #[test]
    fn test_probe_ssh_banner_and_port_open() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let _ = conn.write_all(b"SSH-2.0-OpenSSH_8.9\r\n");
            }
        });

        assert!(probe_ssh_banner(
            "127.0.0.1",
            port,
            Duration::from_millis(500)
        ));
    }
}
