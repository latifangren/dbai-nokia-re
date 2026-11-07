use std::fs;
use std::io;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

pub const CONFIG_FILENAME: &str = "config_toolkit.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedConfig {
    pub modem_ip: Option<String>,
    pub web_pwd: Option<String>,
    pub ssh_pwd: Option<String>,
    pub backup_dir: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub modem_ip: String,
    pub web_user: String,
    pub web_pwd: String,
    pub ssh_user: String,
    pub ssh_pwd: String,
    pub ssh_ports: [u16; 2],
    pub key_name: String,
    pub http_port: u16,
    pub tcp_port: u16,
    pub backup_dir: String,
    pub pc_ip: String,
    pub is_subnet_matched: bool,
    pub is_web_authenticated: bool,
}

impl Default for Config {
    fn default() -> Self {
        let mut cfg = Self {
            modem_ip: "192.168.1.1".to_string(),
            web_user: "admin".to_string(),
            web_pwd: String::new(),
            ssh_user: "root".to_string(),
            ssh_pwd: String::new(),
            ssh_ports: [2222, 22],
            key_name: "fastmile_key".to_string(),
            http_port: 8081,
            tcp_port: 8888,
            backup_dir: "image_backup".to_string(),
            pc_ip: "127.0.0.1".to_string(),
            is_subnet_matched: false,
            is_web_authenticated: false,
        };
        cfg.load_saved_config();
        let (ip, matched) = cfg.detect_pc_ip();
        cfg.pc_ip = ip;
        cfg.is_subnet_matched = matched;
        cfg
    }
}

impl Config {
    pub fn config_path() -> PathBuf {
        Path::new(CONFIG_FILENAME).to_path_buf()
    }

    /// Memuat konfigurasi tersimpan dari `config_toolkit.json` (`SPEC.md` §3.3 #9).
    pub fn load_saved_config(&mut self) {
        let path = Self::config_path();
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(saved) = serde_json::from_str::<SavedConfig>(&content) {
                if let Some(ip) = saved.modem_ip.filter(|s| !s.is_empty()) {
                    self.modem_ip = ip;
                }
                if let Some(wp) = saved.web_pwd {
                    self.web_pwd = wp;
                }
                if let Some(sp) = saved.ssh_pwd {
                    self.ssh_pwd = sp;
                }
                if let Some(bd) = saved.backup_dir.filter(|s| !s.is_empty()) {
                    self.backup_dir = bd;
                }
            }
        }
    }

    /// Menyimpan konfigurasi ke `config_toolkit.json` (`SPEC.md` §3.3 #10).
    pub fn save_config(&self) -> io::Result<()> {
        let saved = SavedConfig {
            modem_ip: Some(self.modem_ip.clone()),
            web_pwd: Some(self.web_pwd.clone()),
            ssh_pwd: Some(self.ssh_pwd.clone()),
            backup_dir: Some(self.backup_dir.clone()),
        };
        let json = serde_json::to_string_pretty(&saved)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(Self::config_path(), json)
    }

    /// Mendeteksi IP lokal PC yang menghadap ke subnet `/24` modem (`SPEC.md` §3.3 #12).
    pub fn detect_pc_ip(&self) -> (String, bool) {
        let target_prefix = self
            .modem_ip
            .rsplit_once('.')
            .map(|(prefix, _)| format!("{}.", prefix))
            .unwrap_or_else(|| "192.168.1.".to_string());

        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect((self.modem_ip.as_str(), 80)).is_ok() {
                if let Ok(local_addr) = sock.local_addr() {
                    let ip_str = local_addr.ip().to_string();
                    let matched = ip_str.starts_with(&target_prefix);
                    return (ip_str, matched);
                }
            }
        }
        ("127.0.0.1".to_string(), false)
    }
}
