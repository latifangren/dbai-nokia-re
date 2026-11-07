pub mod config;
pub mod dumper;
pub mod md5_verifier;
pub mod mim_extractor;
pub mod servers;
pub mod sniper;
pub mod ssh_keys;
pub mod ui;
pub mod web_cgi;

use std::path::{Path, PathBuf};
use std::time::Duration;
use config::Config;
use dumper::{check_free_disk_space_gb, DumperEngine, MIN_FREE_DISK_GB};
use md5_verifier::MD5Validator;
use mim_extractor::FactoryMIMExtractor;
use servers::{BackgroundServers, BUSYBOX_BYTES, TEST_DECRYPT_NODE_BYTES};
use sniper::{wait_for_shutdown, SshSession, DEFAULT_CHECK_PORTS};
use ssh_keys::SSHKeyManager;
use ui::{
    clear_screen, log_error, log_info, log_success, log_warn, pad_ansi, prompt_line, Colors,
};
use web_cgi::WebCgiClient;

pub struct DbaiNokiaApp {
    pub config: Config,
    pub servers: Option<BackgroundServers>,
    pub active_ssh: Option<SshSession>,
}

impl Default for DbaiNokiaApp {
    fn default() -> Self {
        Self {
            config: Config::default(),
            servers: None,
            active_ssh: None,
        }
    }
}

impl DbaiNokiaApp {
    pub fn print_header(&self) {
        clear_screen();
        let box_w = 76usize;
        let div = "═".repeat(box_w);
        println!("{}╔{}╗{}", Colors::CYAN, div, Colors::RESET);
        let title = format!(
            "  {}DBAI-NOKIA: Nokia FastMile 5G GW2 Native Toolkit (v1.1-rs){}",
            Colors::BOLD,
            Colors::RESET
        );
        println!(
            "{}║{}{}{}║{}",
            Colors::CYAN,
            Colors::RESET,
            pad_ansi(&title, box_w),
            Colors::CYAN,
            Colors::RESET
        );
        let status_line = format!(
            "  Modem IP: {}{}{} | PC LAN IP: {}{}{} | Output: {}{}{}",
            Colors::GREEN,
            self.config.modem_ip,
            Colors::RESET,
            if self.config.is_subnet_matched {
                Colors::GREEN
            } else {
                Colors::YELLOW
            },
            self.config.pc_ip,
            Colors::RESET,
            Colors::WHITE,
            self.config.backup_dir,
            Colors::RESET
        );
        println!(
            "{}║{}{}{}║{}",
            Colors::CYAN,
            Colors::RESET,
            pad_ansi(&status_line, box_w),
            Colors::CYAN,
            Colors::RESET
        );
        println!("{}╚{}╝{}", Colors::CYAN, div, Colors::RESET);
    }

    pub fn menu_ensure_keys(&self) {
        match SSHKeyManager::ensure_keys(&self.config.key_name) {
            Ok((priv_path, pub_str)) => {
                log_success(&format!(
                    "Pasangan kunci SSH siap: {} ({} byte pubkey)",
                    priv_path.display(),
                    pub_str.len()
                ));
            }
            Err(e) => log_error(&format!("Gagal menyiapkan kunci SSH: {}", e)),
        }
    }

    pub fn menu_web_login_and_reboot(&mut self, trigger_reboot: bool) {
        if self.config.web_pwd.is_empty() {
            if let Ok(pwd) = prompt_line("[?] Masukkan Password Web Admin: ") {
                self.config.web_pwd = pwd;
            }
        }
        let mut client = WebCgiClient::new(
            &self.config.modem_ip,
            &self.config.web_user,
            &self.config.web_pwd,
        );
        log_info(&format!("Menghubungi Web UI Nokia ({})...", client.base_url));
        match client.login() {
            Ok(token) => {
                self.config.is_web_authenticated = true;
                let _ = self.config.save_config();
                let preview: String = token.chars().take(14).collect();
                log_success(&format!("Login Web UI Berhasil! Token: {}...", preview));
                if trigger_reboot {
                    log_info("Mengirim sinyal reboot resmi ke /reboot_web_app.cgi...");
                    match client.reboot_modem() {
                        Ok(true) => {
                            log_success(
                                "Sinyal reboot resmi (/reboot_web_app.cgi) berhasil diterima modem!",
                            );
                            log_info(
                                "Memantau siklus restart hardware pada port (443, 80, 53, 2222)...",
                            );
                            if wait_for_shutdown(
                                &self.config.modem_ip,
                                &DEFAULT_CHECK_PORTS,
                                Duration::from_secs(35),
                            ) {
                                log_success(
                                    "Modem terkonfirmasi OFFLINE (memulai siklus restart hardware)!",
                                );
                            }
                        }
                        Ok(false) => {
                            log_warn("Modem merespons status non-200 saat permintaan reboot.")
                        }
                        Err(e) => log_error(&format!("Gagal mengirim sinyal reboot: {}", e)),
                    }
                }
            }
            Err(e) => log_error(&e),
        }
    }

    pub fn ensure_active_ssh(&mut self, require_fresh_boot: bool, timeout_secs: u64) -> Option<SshSession> {
        let _ = SSHKeyManager::ensure_keys(&self.config.key_name);
        if !require_fresh_boot {
            if let Some(existing) = &self.active_ssh {
                if let Ok((0, _, _)) = existing.exec_command("true", 3) {
                    return Some(existing.clone());
                }
            }
        }
        log_info(&format!(
            "Menghubungi port SSH {:?} di {} (fresh_boot={})...",
            self.config.ssh_ports, self.config.modem_ip, require_fresh_boot
        ));
        match SshSession::connect_or_poll(
            &self.config,
            Duration::from_secs(timeout_secs),
            require_fresh_boot,
        ) {
            Ok((session, uptime)) => {
                log_success(&format!(
                    "Sesi SSH terhubung di {}:{} (uptime kernel: {:.2} dtk)",
                    session.host, session.port, uptime
                ));
                self.active_ssh = Some(session.clone());
                Some(session)
            }
            Err(e) => {
                log_error(&e);
                None
            }
        }
    }

    pub fn menu_sniper_and_shell(&mut self) {
        let wait_choice = prompt_line(
            "[?] Apakah ingin memantau siklus boot baru (/proc/uptime <= 90s)? [y/N]: ",
        )
        .unwrap_or_default();
        let require_fresh = matches!(wait_choice.to_lowercase().as_str(), "y" | "yes" | "ya");
        if let Some(ssh) = self.ensure_active_ssh(require_fresh, 240) {
            log_info("Membuka terminal SSH interaktif (ketik 'exit' untuk kembali ke menu)...");
            match ssh.open_interactive_shell() {
                Ok(code) => log_info(&format!("Sesi terminal interaktif selesai (exit={}).", code)),
                Err(e) => log_error(&format!("Gagal membuka shell interaktif: {}", e)),
            }
        }
    }

    pub fn menu_start_servers(&mut self) {
        if self.servers.is_some() {
            log_warn("Background Server (HTTP + TCP Receiver) sudah berjalan di latar belakang.");
            return;
        }
        let dir = PathBuf::from(&self.config.backup_dir);
        match BackgroundServers::start(self.config.http_port, self.config.tcp_port, dir) {
            Ok(srv) => {
                log_success(&format!(
                    "HTTP In-Memory Server aktif di 0.0.0.0:{} (/busybox={} B, /test_decrypt_node={} B)",
                    srv.http.port,
                    BUSYBOX_BYTES.len(),
                    TEST_DECRYPT_NODE_BYTES.len()
                ));
                log_success(&format!(
                    "TCP Backup Receiver aktif di 0.0.0.0:{} (Folder: {})",
                    srv.tcp.port, self.config.backup_dir
                ));
                self.servers = Some(srv);
            }
            Err(e) => log_error(&format!("Gagal menjalankan Background Server: {}", e)),
        }
    }

    pub fn menu_dump_ssh(&mut self) {
        let dir = Path::new(&self.config.backup_dir);
        if let Ok(free_gb) = check_free_disk_space_gb(dir) {
            if free_gb < MIN_FREE_DISK_GB {
                log_warn(&format!(
                    "Sisa ruang disk hanya {:.2} GiB (< {:.1} GiB yang disarankan untuk full dump eMMC)!",
                    free_gb, MIN_FREE_DISK_GB
                ));
            }
        }
        if self.servers.is_none() {
            self.menu_start_servers();
        }
        let Some(ssh) = self.ensure_active_ssh(false, 25) else {
            return;
        };
        log_info("Mengambil identitas & kesehatan eMMC serta menjalankan streaming 52 partisi...");
        match DumperEngine::execute_dump_ssh(&ssh, &self.config) {
            Ok(()) => {
                log_success("Full dump partisi eMMC selesai! Menjalankan verifikasi MD5 otomatis...");
                self.menu_verify_md5();
            }
            Err(e) => log_error(&format!("Gagal menjalankan dump eMMC: {}", e)),
        }
    }

    pub fn menu_tarball_ssh(&mut self) {
        if self.servers.is_none() {
            self.menu_start_servers();
        }
        let Some(ssh) = self.ensure_active_ssh(false, 25) else {
            return;
        };
        log_info("Mengarsipkan /data (user_data_dir.tar.gz) & /rom/etc (rom_etc_dir.tar.gz)...");
        match DumperEngine::execute_tarball_ssh(&ssh, &self.config) {
            Ok(()) => log_success("Backup tarball selesai dikirim ke folder output!"),
            Err(e) => log_error(&format!("Gagal menjalankan backup tarball: {}", e)),
        }
    }

    pub fn menu_verify_md5(&mut self) {
        let dir = PathBuf::from(&self.config.backup_dir);
        log_info(&format!("Memverifikasi manifest MD5 di {}...", dir.display()));
        let cfg_clone = self.config.clone();
        let active_ssh_opt = self.active_ssh.clone();

        let res = if let Some(ssh) = active_ssh_opt {
            MD5Validator::verify_with_auto_retry(&dir, 3, |rel_name| {
                log_warn(&format!(
                    "Partisi {} korup/hilang, mencoba redump otomatis via SSH...",
                    rel_name
                ));
                DumperEngine::redump_single_partition(&ssh, &cfg_clone, rel_name)
            })
        } else {
            MD5Validator::verify(&dir)
        };

        match res {
            Ok(sum) => {
                log_success(&format!(
                    "Hasil: {} Valid | {} Excluded RW | {} Korup | {} Hilang",
                    sum.valid_count, sum.excluded_count, sum.corrupt_count, sum.missing_count
                ));
            }
            Err(e) => log_error(&format!("Gagal memverifikasi MD5: {}", e)),
        }
    }

    pub fn menu_change_superuser_pwd(&mut self) {
        let Ok(new_pwd) = prompt_line("[?] Masukkan Password SuperAdmin Web GUI baru: ") else {
            return;
        };
        if new_pwd.is_empty() {
            log_warn("Password baru tidak boleh kosong.");
            return;
        }
        let Some(ssh) = self.ensure_active_ssh(false, 20) else {
            return;
        };
        log_info("Menjalankan cfgcli untuk memperbarui InternetGatewayDevice.X_Authentication.WebAccount...");
        match ssh.change_superadmin_password(&new_pwd) {
            Ok(sha_upper) => {
                log_success(&format!(
                    "Password SuperAdmin berhasil diperbarui! (SHA-256: {})",
                    sha_upper
                ));
            }
            Err(e) => log_error(&format!("Gagal mengubah password SuperAdmin: {}", e)),
        }
    }

    pub fn menu_trigger_ota(&mut self) {
        let Some(ssh) = self.ensure_active_ssh(false, 20) else {
            return;
        };
        log_info("Menjalankan 5 langkah pemicu pembaruan OTA Nokia Cloud FOTA...");
        match ssh.trigger_ota_update() {
            Ok(rep) => {
                log_success(&format!(
                    "Versi Firmware Aktif : {}",
                    if rep.active_version.is_empty() {
                        "(tidak terdeteksi)"
                    } else {
                        &rep.active_version
                    }
                ));
                log_success("Daemon swmgnt & sinyal D-Bus OTA telah dipicu.");
                if !rep.fota_log_tail.is_empty() {
                    println!("\n--- [ LOG FOTA TERAKHIR ] ---\n{}", rep.fota_log_tail);
                }
            }
            Err(e) => log_error(&format!("Gagal memicu pembaruan OTA: {}", e)),
        }
    }

    pub fn menu_inspect_factory_mim(&self) {
        let prompt = format!(
            "[?] Masukkan path berkas/folder Factory_MIM [Enter = {}]: ",
            self.config.backup_dir
        );
        let Ok(raw_path) = prompt_line(&prompt) else {
            return;
        };
        let target_str = if raw_path.is_empty() {
            self.config.backup_dir.as_str()
        } else {
            raw_path.as_str()
        };
        let path = Path::new(target_str);
        let scan_res = if path.is_dir() {
            FactoryMIMExtractor::extract_from_folder(path)
        } else {
            FactoryMIMExtractor::scan_file_or_dump(path)
        };
        match scan_res {
            Ok((entries, label)) if !entries.is_empty() => {
                let report = FactoryMIMExtractor::format_hardware_summary(&entries, &label);
                println!("\n{}", report);
                if let Some(pwd_b64) = entries.get("Password") {
                    if let Some(hex_hash) =
                        FactoryMIMExtractor::decode_mim_password_sha256_hex(pwd_b64)
                    {
                        log_info(&format!("Factory Web Admin SHA-256 : {}", hex_hash));
                        if let Some(plain) = FactoryMIMExtractor::lookup_potfile(&hex_hash, &[]) {
                            log_success(&format!("Kecocokan Potfile Ditemukan: {}", plain));
                        }
                    }
                }
            }
            Ok((_, label)) => log_warn(&format!("Data Factory_MIM tidak ditemukan ({}).", label)),
            Err(e) => log_error(&format!("Gagal membaca berkas/folder dump: {}", e)),
        }
    }

    pub fn menu_config(&mut self) {
        println!("\n--- [ UBAH PENGATURAN KONFIGURASI ] ---");
        println!(" 1. IP Modem           : {}", self.config.modem_ip);
        println!(
            " 2. Password Web Admin : {}",
            if self.config.web_pwd.is_empty() {
                "(belum diatur)"
            } else {
                "********"
            }
        );
        println!(
            " 3. Password Root SSH  : {}",
            if self.config.ssh_pwd.is_empty() {
                "(belum diatur)"
            } else {
                "********"
            }
        );
        println!(" 4. Port HTTP Server   : {}", self.config.http_port);
        println!(" 5. Port TCP Receiver  : {}", self.config.tcp_port);
        println!(" 6. Folder Output      : {}", self.config.backup_dir);
        if let Ok(choice) = prompt_line("Pilih nomor pengaturan [1-6, Enter batal]: ") {
            match choice.as_str() {
                "1" => {
                    if let Ok(v) = prompt_line("IP Modem baru: ") {
                        if !v.is_empty() {
                            self.config.modem_ip = v;
                            let (ip, matched) = self.config.detect_pc_ip();
                            self.config.pc_ip = ip;
                            self.config.is_subnet_matched = matched;
                        }
                    }
                }
                "2" => {
                    if let Ok(v) = prompt_line("Password Web Admin baru: ") {
                        self.config.web_pwd = v;
                    }
                }
                "3" => {
                    if let Ok(v) = prompt_line("Password Root SSH baru: ") {
                        self.config.ssh_pwd = v;
                    }
                }
                "4" => {
                    if let Ok(v) = prompt_line("Port HTTP Server baru: ") {
                        if let Ok(p) = v.parse::<u16>() {
                            self.config.http_port = p;
                        }
                    }
                }
                "5" => {
                    if let Ok(v) = prompt_line("Port TCP Receiver baru: ") {
                        if let Ok(p) = v.parse::<u16>() {
                            self.config.tcp_port = p;
                        }
                    }
                }
                "6" => {
                    if let Ok(v) = prompt_line("Folder Output baru: ") {
                        if !v.is_empty() {
                            self.config.backup_dir = v;
                        }
                    }
                }
                _ => return,
            }
            let _ = self.config.save_config();
            log_success("Konfigurasi berhasil disimpan ke config_toolkit.json.");
        }
    }

    pub fn main_loop(&mut self) {
        loop {
            self.print_header();
            println!("\n  [1] Periksa / Generate Pasangan SSH Key (RSA 2048-bit)");
            println!("  [2] Uji Login Web CGI Nokia (Iterated SHA-256)");
            println!("  [3] Trigger Reboot Modem Resmi (/reboot_web_app.cgi)");
            println!("  [4] Koneksi SSH & Buka Terminal Interaktif");
            println!(
                "  [5] Jalankan Background Server (HTTP:{} In-Memory + TCP:{})",
                self.config.http_port, self.config.tcp_port
            );
            println!("  [6] Full Dump Partisi eMMC via SSH (50 Partisi + boot0/boot1 + ext_csd)");
            println!("  [7] Verifikasi Hash MD5 Checksum Hasil Backup (+ Auto-Retry <=3x)");
            println!("  [8] Backup Direktori (/data & /rom/etc) [.tar.gz]");
            println!("  [s] Ubah Password SuperAdmin (Web GUI via cfgcli)");
            println!("  [m] Trigger OTA Update (Nokia Cloud FOTA)");
            println!("  [i] Inspeksi Identitas Perangkat & Potfile (Factory_MIM)");
            println!("  [k] Ubah Konfigurasi (6 Opsi)");
            println!("  [0] Keluar\n");

            let Ok(choice) = prompt_line("Pilih opsi [1-8, s, m, i, k, 0]: ") else {
                break;
            };
            match choice.to_lowercase().as_str() {
                "1" => self.menu_ensure_keys(),
                "2" => self.menu_web_login_and_reboot(false),
                "3" => self.menu_web_login_and_reboot(true),
                "4" => self.menu_sniper_and_shell(),
                "5" => self.menu_start_servers(),
                "6" => self.menu_dump_ssh(),
                "7" => self.menu_verify_md5(),
                "8" => self.menu_tarball_ssh(),
                "s" => self.menu_change_superuser_pwd(),
                "m" | "o" | "u" | "ota" => self.menu_trigger_ota(),
                "i" => self.menu_inspect_factory_mim(),
                "k" => self.menu_config(),
                "0" => {
                    if let Some(srv) = &self.servers {
                        srv.stop();
                    }
                    log_info("Terima kasih telah menggunakan DBAI-NOKIA Rust Toolkit.");
                    break;
                }
                _ => log_warn("Opsi tidak dikenali."),
            }
            let _ = prompt_line("\nTekan [Enter] untuk kembali ke menu...");
        }
    }
}

fn main() {
    let mut app = DbaiNokiaApp::default();
    app.main_loop();
}
