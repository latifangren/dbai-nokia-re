use std::collections::HashMap;
use std::time::Duration;
use aes::Aes128;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use cbc::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
use rand::RngCore;
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
            if let Ok(sr) = serde_json::from_str::<SaltResponse>(&salt_resp) {
                alati = sr.alati;
            }
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
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(&padded);

        let q = format!("{} {}", Self::b64(&key), Self::b64(&iv));
        let pubkey = RsaPublicKey::from_public_key_pem(&self.session.pubkey)
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
}
