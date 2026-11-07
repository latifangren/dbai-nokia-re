pub mod config;
pub mod md5_verifier;
pub mod mim_extractor;
pub mod servers;
pub mod ssh_keys;
pub mod ui;
pub mod web_cgi;

use std::path::{Path, PathBuf};
use config::Config;
use md5_verifier::MD5Validator;
use mim_extractor::FactoryMIMExtractor;
use servers::TcpBackupReceiver;
use ssh_keys::SSHKeyManager;
use ui::{
    clear_screen, log_error, log_info, log_success, log_warn, pad_ansi, prompt_line, Colors,
};
use web_cgi::WebCgiClient;

pub struct DbaiNokiaApp {
    pub config: Config,
    pub receiver: Option<TcpBackupReceiver>,
}

impl Default for DbaiNokiaApp {
    fn default() -> Self {
        Self {
            config: Config::default(),
            receiver: None,
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
                        Ok(true) => log_success(
                            "Sinyal reboot resmi (/reboot_web_app.cgi) berhasil diterima modem!",
                        ),
                        Ok(false) => log_warn("Modem merespons status non-200 saat permintaan reboot."),
                        Err(e) => log_error(&format!("Gagal mengirim sinyal reboot: {}", e)),
                    }
                }
            }
            Err(e) => log_error(&e),
        }
    }

    pub fn menu_start_receiver(&mut self) {
        if self.receiver.is_some() {
            log_warn("TCP Backup Receiver sudah berjalan di latar belakang.");
            return;
        }
        let dir = PathBuf::from(&self.config.backup_dir);
        match TcpBackupReceiver::start(self.config.tcp_port, dir) {
            Ok(rx) => {
                log_success(&format!(
                    "TCP Backup Receiver aktif di 0.0.0.0:{} (Folder: {})",
                    self.config.tcp_port, self.config.backup_dir
                ));
                self.receiver = Some(rx);
            }
            Err(e) => log_error(&format!("Gagal menjalankan TCP Receiver: {}", e)),
        }
    }

    pub fn menu_verify_md5(&self) {
        let dir = Path::new(&self.config.backup_dir);
        log_info(&format!("Memverifikasi manifest MD5 di {}...", dir.display()));
        match MD5Validator::verify(dir) {
            Ok(sum) => {
                log_success(&format!(
                    "Hasil: {} Valid | {} Excluded RW | {} Korup | {} Hilang",
                    sum.valid_count, sum.excluded_count, sum.corrupt_count, sum.missing_count
                ));
            }
            Err(e) => log_error(&format!("Gagal memverifikasi MD5: {}", e)),
        }
    }

    pub fn menu_inspect_factory_mim(&self) {
        let Ok(raw_path) = prompt_line("[?] Masukkan path berkas Factory_MIM.img atau raw dump: ") else {
            return;
        };
        if raw_path.is_empty() {
            log_warn("Path tidak boleh kosong.");
            return;
        }
        let path = Path::new(&raw_path);
        match FactoryMIMExtractor::scan_file_or_dump(path) {
            Ok((entries, label)) if !entries.is_empty() => {
                let report = FactoryMIMExtractor::format_hardware_summary(&entries, &label);
                println!("\n{}", report);
            }
            Ok((_, label)) => log_warn(&format!("Data Factory_MIM tidak ditemukan ({}).", label)),
            Err(e) => log_error(&format!("Gagal membaca berkas dump: {}", e)),
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
        println!(" 3. Port HTTP Server   : {}", self.config.http_port);
        println!(" 4. Port TCP Receiver  : {}", self.config.tcp_port);
        println!(" 5. Folder Output      : {}", self.config.backup_dir);
        if let Ok(choice) = prompt_line("Pilih nomor pengaturan [1-5, Enter batal]: ") {
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
                    if let Ok(v) = prompt_line("Port HTTP Server baru: ") {
                        if let Ok(p) = v.parse::<u16>() {
                            self.config.http_port = p;
                        }
                    }
                }
                "4" => {
                    if let Ok(v) = prompt_line("Port TCP Receiver baru: ") {
                        if let Ok(p) = v.parse::<u16>() {
                            self.config.tcp_port = p;
                        }
                    }
                }
                "5" => {
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
            println!("  [5] Jalankan Background TCP Backup Receiver (:{})", self.config.tcp_port);
            println!("  [7] Verifikasi Hash MD5 Checksum Hasil Backup");
            println!("  [i] Inspeksi Offline Identitas Perangkat (Factory_MIM)");
            println!("  [k] Ubah Konfigurasi");
            println!("  [0] Keluar\n");

            let Ok(choice) = prompt_line("Pilih opsi [1, 2, 3, 5, 7, i, k, 0]: ") else {
                break;
            };
            match choice.to_lowercase().as_str() {
                "1" => self.menu_ensure_keys(),
                "2" => self.menu_web_login_and_reboot(false),
                "3" => self.menu_web_login_and_reboot(true),
                "5" => self.menu_start_receiver(),
                "7" => self.menu_verify_md5(),
                "i" => self.menu_inspect_factory_mim(),
                "k" => self.menu_config(),
                "0" => {
                    if let Some(rx) = &self.receiver {
                        rx.stop();
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
