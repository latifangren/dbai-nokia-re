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

#[derive(Default)]
pub struct DbaiNokiaApp {
    pub config: Config,
    pub servers: Option<BackgroundServers>,
    pub active_ssh: Option<SshSession>,
    pub web_client: Option<WebCgiClient>,
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
    pub fn run_full_pipeline(&mut self) {
        log_info("Memulai Full Automation Pipeline...");
        self.menu_ensure_keys();
        self.config.refresh_pc_ip();
        self.menu_start_servers();
        let Some(ssh) = self.ensure_active_ssh(false, 240) else {
            log_error("Gagal menghubungkan sesi SSH untuk Full Pipeline.");
            return;
        };
        self.menu_dump_ssh();
        log_info("Menjalankan ekstraksi kredensial live via SSH...");
        match FactoryMIMExtractor::extract_live_credentials(&ssh, &self.config) {
            Ok((_, report, path)) => {
                println!("\n{}", report);
                log_success(&format!(
                    "Laporan kredensial berhasil disimpan di: {}",
                    path.display()
                ));
            }
            Err(e) => log_error(&format!("Gagal ekstraksi kredensial live: {}", e)),
        }
        log_success("Full Pipeline selesai dijalankan!");
    }

    pub fn menu_root_exploit(&mut self) {
        self.menu_web_login_and_reboot(false);
    }

    pub fn menu_reboot(&mut self) {
        log_info("Memicu reboot modem...");
        let mut reboot_sent = false;
        if let Some(ref ssh) = self.active_ssh {
            if let Ok((code, _, _)) = ssh.exec_command("reboot", 5) {
                if code == 0 {
                    log_success("Perintah reboot berhasil dikirim via SSH!");
                    reboot_sent = true;
                }
            }
        }
        if !reboot_sent {
            let mut client = WebCgiClient::new(
                &self.config.modem_ip,
                &self.config.web_user,
                &self.config.web_pwd,
            );
            match client.login() {
                Ok(_) => {
                    match client.reboot_modem() {
                        Ok(true) => {
                            log_success(
                                "Sinyal reboot resmi (/reboot_web_app.cgi) berhasil dikirim via Web CGI!",
                            );
                            reboot_sent = true;
                        }
                        Ok(false) => {
                            log_warn("Modem merespons status non-200 saat permintaan reboot Web CGI.")
                        }
                        Err(e) => log_error(&format!("Gagal mengirim sinyal reboot via Web CGI: {}", e)),
                    }
                    self.web_client = Some(client);
                }
                Err(e) => log_error(&format!("Gagal login Web CGI untuk reboot: {}", e)),
            }
        }
        if reboot_sent {
            log_info("Memantau siklus restart hardware pada port (443, 80, 53, 2222)...");
            if wait_for_shutdown(
                &self.config.modem_ip,
                &DEFAULT_CHECK_PORTS,
                Duration::from_secs(35),
            ) {
                log_success("Modem terkonfirmasi OFFLINE (memulai siklus restart hardware)!");
            }
            self.active_ssh = None;
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
                self.web_client = Some(client);
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
        if self.config.pc_ip == "127.0.0.1" || !self.config.is_subnet_matched {
            self.config.refresh_pc_ip();
        }
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
        if self.config.pc_ip == "127.0.0.1" || !self.config.is_subnet_matched {
            self.config.refresh_pc_ip();
        }
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
        if self.config.pc_ip == "127.0.0.1" || !self.config.is_subnet_matched {
            self.config.refresh_pc_ip();
        }
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
        let Some(ssh) = self.ensure_active_ssh(false, 20) else {
            return;
        };
        let prompt = format!(
            "[?] Masukkan Password SuperAdmin Web GUI baru [Enter = {}]: ",
            sniper::DEFAULT_SUPERADMIN_NEW_PWD
        );
        let input_pwd = prompt_line(&prompt).unwrap_or_default();
        let new_pwd = if input_pwd.trim().is_empty() {
            sniper::DEFAULT_SUPERADMIN_NEW_PWD
        } else {
            input_pwd.trim()
        };
        match ssh.change_superadmin_password(new_pwd) {
            Ok(hash) => {
                log_success(&format!(
                    "Password SuperAdmin berhasil diubah ke '{}'!",
                    new_pwd
                ));
                log_info(&format!("Digest SHA-256 (UPPERCASE): {}", hash));
            }
            Err(e) => log_error(&format!("Gagal mengubah password SuperAdmin: {}", e)),
        }
    }

    pub fn menu_revoke_root(&mut self) {
        let ans = prompt_line(
            "[?] Anda yakin ingin menghapus akses root dan membersihkan artefak di modem? [y/N]: ",
        )
        .unwrap_or_default();
        if !matches!(ans.trim().to_lowercase().as_str(), "y" | "yes" | "ya") {
            log_info("Operasi unroot dibatalkan.");
            return;
        }

        let mut cleaned = false;
        if let Some(ssh) = self.ensure_active_ssh(false, 10) {
            log_info("Menjalankan pembersihan unroot via SSH...");
            match ssh.revoke_root() {
                Ok(()) => {
                    log_success(
                        "Akses root dan seluruh artefak toolkit berhasil dibersihkan dari modem!",
                    );
                    cleaned = true;
                }
                Err(e) => log_error(&format!("Gagal membersihkan artefak via SSH: {}", e)),
            }
        } else {
            log_error("Koneksi SSH tidak dapat dibuat untuk menjalankan revoke_root.");
        }

        if cleaned {
            let reb = prompt_line("[?] Reboot modem sekarang untuk menyelesaikan unroot? [y/N]: ")
                .unwrap_or_default();
            if matches!(reb.trim().to_lowercase().as_str(), "y" | "yes" | "ya") {
                self.menu_reboot();
            }
        }
    }

    pub fn menu_openwrt_troll(&self) {
        println!("\n{}", "=".repeat(80));
        println!("  SIMULASI FLASH CUSTOM FIRMWARE OPENWRT (COMMUNITY EASTER EGG)");
        println!("{}", "=".repeat(80));
        println!("  [!] Menyiapkan kernel OpenWrt untuk Nokia FastMile 5G GW2...");
        std::thread::sleep(Duration::from_millis(600));
        println!("  [!] Mem-bypass verifikasi tanda tangan RSA kernel bootloader...");
        std::thread::sleep(Duration::from_millis(600));
        println!("  [!] Mengunggah citra rootfs SquashFS ke partisi eMMC...");
        std::thread::sleep(Duration::from_millis(800));
        println!("  [!] Selesai! (Hanya simulasi / lelucon komunitas - TIDAK ADA penulisan ke flash).");
        println!("\n  [i] Tautan referensi komunitas:");
        println!("      - Repository: https://github.com/armarchindo/nokia-gateway-2");
        println!("      - Komunitas : https://web.facebook.com/groups/ihabt");
        println!("{}\n", "=".repeat(80));
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

    pub fn menu_inspect_factory_mim(&mut self) {
        println!("\n--- [ EKSTRAKSI IDENTITAS & KREDENSIAL PABRIK ] ---");
        println!(" [1] Live via SSH (Factory_MIM + /etc/shadow + test_decrypt_node)");
        println!(" [2] Offline dari berkas/folder lokal [Default]");
        let choice = prompt_line("Pilih mode [1/2, Enter = 2]: ").unwrap_or_default();

        if choice.trim() == "1" {
            let Some(ssh) = self.ensure_active_ssh(false, 20) else {
                return;
            };
            log_info("Menjalankan ekstraksi kredensial live via SSH...");
            match FactoryMIMExtractor::extract_live_credentials(&ssh, &self.config) {
                Ok((_, report, path)) => {
                    println!("\n{}", report);
                    log_success(&format!(
                        "Laporan kredensial berhasil disimpan di: {}",
                        path.display()
                    ));
                }
                Err(e) => log_error(&format!("Gagal ekstraksi live via SSH: {}", e)),
            }
        } else {
            let prompt = format!(
                "[?] Masukkan path berkas/folder Factory_MIM [Enter = {}]: ",
                self.config.backup_dir
            );
            let raw_path = prompt_line(&prompt).unwrap_or_default();
            let target_str = if raw_path.trim().is_empty() {
                self.config.backup_dir.as_str()
            } else {
                raw_path.trim()
            };
            let path = Path::new(target_str);
            let scan_res = if path.is_dir() {
                FactoryMIMExtractor::extract_from_folder(path)
            } else {
                FactoryMIMExtractor::scan_file_or_dump(path)
            };
            match scan_res {
                Ok((entries, label)) if !entries.is_empty() => {
                    let report = FactoryMIMExtractor::format_credentials_report(
                        &entries,
                        &label,
                        None,
                        &std::collections::BTreeMap::new(),
                    );
                    println!("\n{}", report);
                    match FactoryMIMExtractor::save_credentials_report(
                        Path::new(&self.config.backup_dir),
                        &entries,
                        &report,
                    ) {
                        Ok(p) => log_success(&format!(
                            "Laporan kredensial berhasil disimpan di: {}",
                            p.display()
                        )),
                        Err(e) => log_error(&format!("Gagal menyimpan laporan kredensial: {}", e)),
                    }
                }
                Ok((_, label)) => log_warn(&format!("Data Factory_MIM tidak ditemukan ({}).", label)),
                Err(e) => log_error(&format!("Gagal membaca berkas/folder dump: {}", e)),
            }
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
        println!(" 3. Password Root SSH  : {}", if self.config.ssh_pwd.is_empty() { "(belum diatur)" } else { "********" });
        println!(" 4. Port HTTP Server   : {}", self.config.http_port);
        println!(" 5. Port TCP Receiver  : {}", self.config.tcp_port);
        println!(" 6. Folder Output      : {}", self.config.backup_dir);
        println!(
            " 7. PC LAN IP (Auto/Manual) : {} (Subnet match: {})",
            self.config.pc_ip, self.config.is_subnet_matched
        );

        if let Ok(choice) = prompt_line("Pilih nomor pengaturan [1-7, Enter batal]: ") {
            let mut restart_servers_needed = false;
            match choice.trim() {
                "1" => {
                    if let Ok(v) = prompt_line("IP Modem baru: ") {
                        if !v.trim().is_empty() {
                            self.config.modem_ip = v.trim().to_string();
                            self.config.refresh_pc_ip();
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
                        if let Ok(p) = v.trim().parse::<u16>() {
                            self.config.http_port = p;
                            restart_servers_needed = true;
                        }
                    }
                }
                "5" => {
                    if let Ok(v) = prompt_line("Port TCP Receiver baru: ") {
                        if let Ok(p) = v.trim().parse::<u16>() {
                            self.config.tcp_port = p;
                            restart_servers_needed = true;
                        }
                    }
                }
                "6" => {
                    if let Ok(v) = prompt_line("Folder Output baru: ") {
                        if !v.trim().is_empty() {
                            self.config.backup_dir = v.trim().to_string();
                            restart_servers_needed = true;
                        }
                    }
                }
                "7" => {
                    if let Ok(v) = prompt_line("PC LAN IP baru [Enter = auto-detect ulang]: ") {
                        if v.trim().is_empty() {
                            self.config.refresh_pc_ip();
                            log_info(&format!(
                                "IP LAN terdeteksi otomatis: {} (Subnet match: {})",
                                self.config.pc_ip, self.config.is_subnet_matched
                            ));
                        } else {
                            self.config.pc_ip = v.trim().to_string();
                            let prefix = self.config.modem_ip.split('.').take(3).collect::<Vec<_>>().join(".");
                            self.config.is_subnet_matched = self.config.pc_ip.starts_with(&prefix);
                        }
                    }
                }
                _ => return,
            }
            let _ = self.config.save_config();
            log_success("Konfigurasi berhasil disimpan ke config_toolkit.json.");

            if restart_servers_needed && self.servers.is_some() {
                if let Some(s) = self.servers.take() {
                    s.stop();
                }
                let dir = PathBuf::from(&self.config.backup_dir);
                match BackgroundServers::start(self.config.http_port, self.config.tcp_port, dir) {
                    Ok(srv) => {
                        log_success("Background servers berhasil di-restart pada konfigurasi baru.");
                        self.servers = Some(srv);
                    }
                    Err(e) => log_error(&format!("Gagal me-restart server: {}", e)),
                }
            }
        }
    }

    pub fn main_loop(&mut self) {
        loop {
            self.print_header();
            println!("\n  [a] Full Pipeline (Auto: Keys -> Root -> Reboot -> Servers -> Dump -> MD5 -> Creds)");
            println!("  [1] Periksa / Generate Pasangan SSH Key (RSA 2048-bit)");
            println!("  [2] Uji Login Web CGI Nokia (Iterated SHA-256)");
            println!("  [3] Trigger Reboot Modem (/reboot_web_app.cgi atau SSH)");
            println!("  [4] Mulai SSH Sniper & Buka Terminal Interaktif");
            println!("  [5] Jalankan Background Server (HTTP:{} + TCP:{})", self.config.http_port, self.config.tcp_port);
            println!("  [6] Full Dump Partisi eMMC via SSH (52 Partisi + ext_csd)");
            println!("  [7] Verifikasi Hash MD5 Checksum (+ Auto-Retry <= 3x)");
            println!("  [8] Backup Direktori (/data & /rom/etc) [Opsional]");
            println!("  [n] Flash Custom Firmware OpenWrt (Community Easter Egg)");
            println!("  [s] Ubah Password SuperAdmin (Web GUI)");
            println!("  [i] Ekstrak Data Identitas & Kredensial Pabrik (Factory_MIM)");
            println!("  [r] Unroot / Revoke Akses Root & Bersihkan Artefak");
            println!("  [k] Ubah Pengaturan Konfigurasi");
            println!("  [m] Trigger OTA Update (Nokia Cloud FOTA)");
            println!("  [0] Keluar");

            let Ok(choice) = prompt_line("\nPilih opsi [a, 1-8, n, s, i, r, k, m, 0]: ") else {
                break;
            };

            match choice.trim() {
                "a" | "A" => self.run_full_pipeline(),
                "1" => self.menu_ensure_keys(),
                "2" => self.menu_root_exploit(),
                "3" => self.menu_reboot(),
                "4" => self.menu_sniper_and_shell(),
                "5" => self.menu_start_servers(),
                "6" => self.menu_dump_ssh(),
                "7" => self.menu_verify_md5(),
                "8" => self.menu_tarball_ssh(),
                "n" | "N" | "w" | "W" | "f" | "F" | "openwrt" => self.menu_openwrt_troll(),
                "s" | "S" => self.menu_change_superuser_pwd(),
                "i" | "I" => self.menu_inspect_factory_mim(),
                "r" | "R" => self.menu_revoke_root(),
                "k" | "K" => self.menu_config(),
                "m" | "M" | "o" | "O" | "u" | "U" | "ota" | "OTA" => self.menu_trigger_ota(),
                "0" | "q" | "Q" | "exit" => {
                    log_info("Menghentikan seluruh layanan latar belakang...");
                    if let Some(srv) = self.servers.take() {
                        srv.stop();
                    }
                    log_info("Sampai jumpa!");
                    break;
                }
                _ => {
                    log_warn("Opsi tidak dikenali.");
                }
            }
            let _ = prompt_line("\nTekan [Enter] untuk kembali ke menu...");
        }
    }
}

fn main() {
    let mut app = DbaiNokiaApp::default();
    app.main_loop();
}
