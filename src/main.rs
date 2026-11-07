pub mod config;
pub mod dumper;
pub mod md5_verifier;
pub mod mim_extractor;
pub mod servers;
pub mod sniper;
pub mod ssh_keys;
pub mod ui;
pub mod web_cgi;

use config::Config;
use dumper::{check_free_disk_space_gb, DumperEngine, MIN_FREE_DISK_GB};
use md5_verifier::MD5Validator;
use mim_extractor::FactoryMIMExtractor;
use servers::{BackgroundServers, BUSYBOX_BYTES, TEST_DECRYPT_NODE_BYTES};
use sniper::{wait_for_shutdown, SshSession, DEFAULT_CHECK_PORTS};
use ssh_keys::SSHKeyManager;
use std::path::{Path, PathBuf};
use std::time::Duration;
use ui::{
    clear_screen, init_terminal, log_error, log_info, log_success, log_warn, pad_ansi, prompt_line,
    Colors,
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
    /// Menjalankan wizard startup dan konfigurasi awal interaktif (`SPEC.md` §3.3 #54).
    pub fn startup_wizard(&mut self) {
        clear_screen();
        let box_w = 76usize;
        let div = "═".repeat(box_w);
        println!("{}╔{}╗{}", Colors::CYAN, div, Colors::RESET);
        let title = format!(
            "  {}STARTUP WIZARD & KONFIGURASI AWAL{}",
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
        println!("{}╚{}╝{}", Colors::CYAN, div, Colors::RESET);

        // Step 1: Prompt Modem IP
        let modem_prompt = format!("[?] Masukkan IP Modem [Enter = {}]: ", self.config.modem_ip);
        let modem_in = match prompt_line(&modem_prompt) {
            Ok(s) => s.trim().to_string(),
            Err(_) => return,
        };
        if modem_in == "0" || modem_in.eq_ignore_ascii_case("q") {
            return;
        }
        if !modem_in.is_empty() {
            self.config.modem_ip = modem_in;
        }

        // Step 2: Refresh PC LAN IP and check subnet
        self.config.refresh_pc_ip();
        if self.config.is_subnet_matched {
            log_success(&format!(
                "Adapter LAN PC terdeteksi satu subnet: {}",
                self.config.pc_ip
            ));
        } else {
            log_warn(&format!(
                "IP PC ({}) berbeda subnet dengan Modem ({})!",
                self.config.pc_ip, self.config.modem_ip
            ));
            let manual_prompt = format!(
                "[?] Masukkan IP LAN PC manual [Enter = tetap gunakan {}]: ",
                self.config.pc_ip
            );
            if let Ok(manual_in) = prompt_line(&manual_prompt) {
                let manual_in = manual_in.trim();
                if !manual_in.is_empty() {
                    self.config.pc_ip = manual_in.to_string();
                    let target_prefix = self
                        .config
                        .modem_ip
                        .rsplit_once('.')
                        .map(|(prefix, _)| format!("{}.", prefix))
                        .unwrap_or_else(|| "192.168.1.".to_string());
                    self.config.is_subnet_matched = self.config.pc_ip.starts_with(&target_prefix);
                }
            }
        }

        // Step 3: Web Admin password & login
        let pwd_prompt = if self.config.web_pwd.is_empty() {
            "[?] Masukkan Password Web Admin [Enter = lewati]: "
        } else {
            "[?] Tekan [Enter] untuk menggunakan Password Web Admin tersimpan (atau ketik baru / 's' lewati): "
        };
        if let Ok(pwd_in) = prompt_line(pwd_prompt) {
            let pwd_in = pwd_in.trim();
            if pwd_in.eq_ignore_ascii_case("s") {
                // Lewati
            } else if !pwd_in.is_empty() {
                self.config.web_pwd = pwd_in.to_string();
                let mut client = WebCgiClient::new(
                    &self.config.modem_ip,
                    &self.config.web_user,
                    &self.config.web_pwd,
                );
                match client.login() {
                    Ok(_) => {
                        log_success("Login Web CGI berhasil.");
                        self.config.is_web_authenticated = true;
                        self.web_client = Some(client);
                    }
                    Err(e) => {
                        log_warn(&format!(
                            "Login Web CGI gagal (melanjutkan tanpa sesi Web): {}",
                            e
                        ));
                    }
                }
            }
        }

        let _ = self.config.save_config();
    }

    pub fn is_ssh_connected(&self) -> bool {
        if let Some(ref ssh) = self.active_ssh {
            sniper::is_any_port_open(&ssh.host, &[ssh.port], Duration::from_millis(250))
        } else {
            false
        }
    }

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
        let ssh_alive = self.is_ssh_connected();
        let ssh_status = if ssh_alive {
            format!("{}Terkoneksi (OK){}", Colors::GREEN, Colors::RESET)
        } else {
            format!("{}Belum Terkoneksi (!){}", Colors::YELLOW, Colors::RESET)
        };
        let os_line = format!(
            "  Platform: {}{}{} | SSH Status: {}",
            Colors::WHITE,
            std::env::consts::OS,
            Colors::RESET,
            ssh_status
        );
        println!(
            "{}║{}{}{}║{}",
            Colors::CYAN,
            Colors::RESET,
            pad_ansi(&os_line, box_w),
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
        println!("\n--- [ FULL AUTOMATED PIPELINE ] ---");
        log_info("Alur: Buat Key -> Aktivasi SSH -> Sinyal Reboot -> SSH Sniper -> Auto-Backup -> Verifikasi MD5 -> Kredensial");
        self.config.refresh_pc_ip();
        if !self.config.is_subnet_matched {
            log_warn(&format!(
                "Subnet PC ({}) dan Modem ({}) tidak sama!",
                self.config.pc_ip, self.config.modem_ip
            ));
            let ans = prompt_line(
                "[?] Modem mungkin gagal mentransfer data ke PC. Tetap lanjut? [y/N]: ",
            )
            .unwrap_or_default();
            if !matches!(ans.trim().to_lowercase().as_str(), "y" | "yes" | "ya") {
                return;
            }
        }

        log_info("Tahap 1: Memeriksa pasangan SSH Key...");
        let pubkey = match SSHKeyManager::ensure_keys(&self.config.key_name) {
            Ok((priv_path, pub_str)) => {
                log_success(&format!(
                    "Pasangan kunci SSH siap: {} ({} byte pubkey)",
                    priv_path.display(),
                    pub_str.len()
                ));
                pub_str
            }
            Err(e) => {
                log_error(&format!("Gagal menyiapkan kunci SSH: {}", e));
                return;
            }
        };

        let mut ssh_already_open = false;
        if let Some(ref existing) = self.active_ssh {
            if let Ok((0, _, _)) = existing.exec_command("true", 3) {
                ssh_already_open = true;
            }
        }
        if !ssh_already_open
            && sniper::is_any_port_open(
                &self.config.modem_ip,
                &self.config.ssh_ports,
                Duration::from_millis(600),
            )
        {
            if let Ok((sess, up)) =
                SshSession::connect_or_poll(&self.config, Duration::from_secs(10), false)
            {
                log_success(&format!(
                    "Port SSH {}:{} sudah aktif (uptime {:.2}s)!",
                    sess.host, sess.port, up
                ));
                self.active_ssh = Some(sess);
                ssh_already_open = true;
            }
        }

        let mut need_fresh_boot_wait = false;
        if !ssh_already_open {
            log_info("Tahap 2: Menjalankan Web Auth & Aktivasi SSH (TR-369 RCE)...");
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
            match client.login() {
                Ok(_) => {
                    self.config.is_web_authenticated = true;
                    let _ = self.config.save_config();
                    log_info("Menginjeksi detector payload & hook aic_conf.json ke modem...");
                    if let Err(e) = client.deploy_detector(&pubkey) {
                        log_error(&format!("Gagal saat proses exploit TR-369: {}", e));
                        return;
                    }
                    log_success("Detector dan hook aic_conf.json berhasil terpasang di modem!");
                    self.web_client = Some(client);
                }
                Err(e) => {
                    log_error(&format!("Gagal saat proses exploit (Login Web CGI): {}", e));
                    return;
                }
            }
        }

        log_info("Tahap 3: Menyalakan background HTTP Server & TCP Receiver di PC...");
        self.menu_start_servers();

        if !ssh_already_open {
            let reb_ans =
                prompt_line("[?] Kirim sinyal reboot otomatis ke modem sekarang? [Y/n]: ")
                    .unwrap_or_default();
            let do_auto_reboot = !matches!(reb_ans.trim().to_lowercase().as_str(), "n" | "no");
            if do_auto_reboot {
                if let Some(ref client) = self.web_client {
                    match client.reboot_modem() {
                        Ok(true) => {
                            log_success("Sinyal reboot berhasil dikirimkan ke modem!");
                            log_info(
                                "Memantau siklus restart hardware pada port (443, 80, 53, 2222)...",
                            );
                            let _ = wait_for_shutdown(
                                &self.config.modem_ip,
                                &DEFAULT_CHECK_PORTS,
                                Duration::from_secs(35),
                            );
                            need_fresh_boot_wait = true;
                        }
                        _ => {
                            log_warn("Gagal mengirim sinyal reboot otomatis. Silakan reboot modem secara manual.");
                            let _ = prompt_line("Tekan [Enter] jika Anda sudah menekan reboot...");
                        }
                    }
                }
            } else {
                let _ = prompt_line(
                    "Silakan reboot modem secara manual lalu tekan [Enter] untuk melanjutkan...",
                );
            }
        }

        log_info("Tahap 4: Mengaktifkan SSH Sniper di PC...");
        let Some(ssh) = self.ensure_active_ssh(need_fresh_boot_wait, 240) else {
            log_error("Gagal mengunci koneksi SSH. Silakan ulangi.");
            return;
        };

        log_info("Tahap 5 & 6: Menjalankan proses backup 52 partisi eMMC & Verifikasi MD5...");
        self.menu_dump_ssh();

        log_info("Tahap 7: Mengekstrak Data Identitas & Kredensial Pabrik...");
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
        log_success("SELURUH ALUR PIPELINE BERHASIL DISELESAIKAN!");
    }

    pub fn menu_root_exploit(&mut self) {
        println!("\n--- [ AKTIVASI SSH (ROOT) VIA INJEKSI TR-369 ] ---");
        let pubkey = match SSHKeyManager::ensure_keys(&self.config.key_name) {
            Ok((_, pub_str)) => pub_str,
            Err(e) => {
                log_error(&format!("Gagal menyiapkan kunci SSH: {}", e));
                return;
            }
        };
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
        log_info(&format!(
            "Menghubungi Web UI Nokia ({})...",
            client.base_url
        ));
        match client.login() {
            Ok(token) => {
                self.config.is_web_authenticated = true;
                let _ = self.config.save_config();
                let preview: String = token.chars().take(14).collect();
                log_success(&format!("Login Web UI Berhasil! Token: {}...", preview));
                log_info("Menyiapkan /configs/nonpersistant & menginjeksi detector payload via TR-369...");
                match client.deploy_detector(&pubkey) {
                    Ok(()) => {
                        log_success("Aktivasi SSH root (detector & hook aic_conf.json) berhasil terpasang di modem!");
                        self.web_client = Some(client);
                        let reb = prompt_line(
                            "[?] Kirim sinyal reboot resmi sekarang untuk mengaktifkan SSH? [Y/n]: ",
                        )
                        .unwrap_or_default();
                        if !matches!(reb.trim().to_lowercase().as_str(), "n" | "no") {
                            self.menu_reboot();
                        }
                    }
                    Err(e) => {
                        log_error(&format!("Gagal mengaktifkan SSH via TR-369: {}", e));
                    }
                }
            }
            Err(e) => log_error(&format!("Gagal mengaktifkan SSH: {}", e)),
        }
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
                        Ok(false) => log_warn(
                            "Modem merespons status non-200 saat permintaan reboot Web CGI.",
                        ),
                        Err(e) => {
                            log_error(&format!("Gagal mengirim sinyal reboot via Web CGI: {}", e))
                        }
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
        log_info(&format!(
            "Menghubungi Web UI Nokia ({})...",
            client.base_url
        ));
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

    pub fn ensure_active_ssh(
        &mut self,
        require_fresh_boot: bool,
        timeout_secs: u64,
    ) -> Option<SshSession> {
        let _ = SSHKeyManager::ensure_keys(&self.config.key_name);
        if !require_fresh_boot {
            if let Some(existing) = &self.active_ssh {
                if let Ok((0, _, _)) = existing.exec_command("true", 3) {
                    return Some(existing.clone());
                }
            }
            if !sniper::is_any_port_open(
                &self.config.modem_ip,
                &self.config.ssh_ports,
                Duration::from_millis(400),
            ) && sniper::is_any_port_open(
                &self.config.modem_ip,
                &[80],
                Duration::from_millis(400),
            ) {
                log_warn("Port SSH [2222, 22] di modem saat ini TERTUTUP, namun Web Admin (Port 80) aktif!");
                println!("  [1] Kirim Sinyal Reboot Resmi & Injeksi SSH Root + Mulai SSH Sniper (Rekomendasi)");
                println!("  [2] Masuk ke mode SSH Sniper sekarang (jika modem sedang Anda reboot manual)");
                println!("  [0] Batal / Kembali ke Menu Utama");
                let act = prompt_line("Pilih tindakan [1/2/0, Enter = 1]: ").unwrap_or_default();
                match act.trim() {
                    "0" => return None,
                    "2" => {}
                    _ => {
                        if let Ok((_, pubkey)) = SSHKeyManager::ensure_keys(&self.config.key_name) {
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
                            if client.login().is_ok() {
                                let _ = client.deploy_detector(&pubkey);
                                if let Ok(true) = client.reboot_modem() {
                                    log_success("Sinyal reboot resmi berhasil dikirim! Memantau siklus restart...");
                                    let _ = wait_for_shutdown(
                                        &self.config.modem_ip,
                                        &DEFAULT_CHECK_PORTS,
                                        Duration::from_secs(35),
                                    );
                                }
                                self.web_client = Some(client);
                            }
                        }
                    }
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
                Ok(code) => log_info(&format!(
                    "Sesi terminal interaktif selesai (exit={}).",
                    code
                )),
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
                let cont = prompt_line("[?] Tetap paksa lanjutkan dump sekarang? [y/N]: ")
                    .unwrap_or_default();
                if !matches!(cont.trim().to_lowercase().as_str(), "y" | "yes" | "ya") {
                    log_info("Proses dump dibatalkan untuk mencegah kerusakan file.");
                    return;
                }
            }
        }
        if self.servers.is_none() {
            self.menu_start_servers();
        }
        if let Some(ref srv) = self.servers {
            srv.tcp.reset_done();
        }
        let Some(ssh) = self.ensure_active_ssh(false, 25) else {
            return;
        };
        log_info("Mengambil identitas & kesehatan eMMC serta menjalankan streaming 52 partisi...");
        match DumperEngine::execute_dump_ssh(&ssh, &self.config) {
            Ok(()) => {
                if let Some(ref srv) = self.servers {
                    let _ = srv.tcp.wait_until_done(Duration::from_secs(10));
                }
                log_success(
                    "Full dump partisi eMMC selesai! Menjalankan verifikasi MD5 otomatis...",
                );
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
        if let Some(ref srv) = self.servers {
            srv.tcp.reset_done();
        }
        let Some(ssh) = self.ensure_active_ssh(false, 25) else {
            return;
        };
        log_info("Mengarsipkan /data (user_data_dir.tar.gz) & /rom/etc (rom_etc_dir.tar.gz)...");
        match DumperEngine::execute_tarball_ssh(&ssh, &self.config) {
            Ok(()) => {
                if let Some(ref srv) = self.servers {
                    let _ = srv.tcp.wait_until_done(Duration::from_secs(10));
                }
                log_success("Backup tarball selesai dikirim ke folder output!");
            }
            Err(e) => log_error(&format!("Gagal menjalankan backup tarball: {}", e)),
        }
    }

    pub fn menu_verify_md5(&mut self) {
        let dir = PathBuf::from(&self.config.backup_dir);
        log_info(&format!(
            "Memverifikasi manifest MD5 di {}...",
            dir.display()
        ));
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
        println!("\n--- [ UNROOT / REVOKE AKSES ROOT ] ---");
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
            log_info("Mengeksekusi pembersihan hook via sesi SSH aktif...");
            match ssh.revoke_root() {
                Ok(()) => {
                    log_success("File hook root di /configs berhasil dibersihkan via SSH!");
                    cleaned = true;
                }
                Err(e) => {
                    log_warn(&format!(
                        "Gagal via SSH: {}. Mencoba jalur alternatif via Web API...",
                        e
                    ));
                }
            }
        } else {
            log_warn("Sesi SSH tidak aktif. Mencoba jalur alternatif via Web Management API...");
        }

        if !cleaned {
            log_info("Mengeksekusi pembersihan hook via Web Management API...");
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
            match client.login() {
                Ok(_) => match client.execute_rce(sniper::UNROOT_CLEANUP_CMD, 1.0) {
                    Ok(_) => {
                        log_success(
                            "File hook root di /configs berhasil dibersihkan via Web Management API!",
                        );
                        cleaned = true;
                        self.web_client = Some(client);
                    }
                    Err(e) => {
                        log_error(&format!("Gagal mencabut akses root via Web API: {}", e));
                    }
                },
                Err(e) => {
                    log_error(&format!("Gagal login Web API untuk unroot: {}", e));
                }
            }
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
        println!(
            "  [!] Selesai! (Hanya simulasi / lelucon komunitas - TIDAK ADA penulisan ke flash)."
        );
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
            let norm_path = FactoryMIMExtractor::normalize_path(target_str);
            let path = norm_path.as_path();
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
                        Some(&self.config.web_pwd),
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
                Ok((_, label)) => {
                    log_warn(&format!("Data Factory_MIM tidak ditemukan ({}).", label))
                }
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
                            let prefix = self
                                .config
                                .modem_ip
                                .split('.')
                                .take(3)
                                .collect::<Vec<_>>()
                                .join(".");
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
                        log_success(
                            "Background servers berhasil di-restart pada konfigurasi baru.",
                        );
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
            println!("  [2] Aktivasi SSH (ROOT) via Injeksi TR-369");
            println!("  [3] Trigger Reboot Modem (/reboot_web_app.cgi atau SSH)");
            println!("  [4] Mulai SSH Sniper & Buka Terminal Interaktif");
            println!(
                "  [5] Jalankan Background Server (HTTP:{} + TCP:{})",
                self.config.http_port, self.config.tcp_port
            );
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
    init_terminal();
    let mut app = DbaiNokiaApp::default();
    app.startup_wizard();
    app.main_loop();
}
