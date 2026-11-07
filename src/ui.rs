use std::io::{self, Write};
use std::sync::OnceLock;
use regex::Regex;

pub struct Colors;

impl Colors {
    pub const RESET: &'static str = "\x1b[0m";
    pub const BOLD: &'static str = "\x1b[1m";
    pub const DIM: &'static str = "\x1b[2m";
    pub const WHITE: &'static str = "\x1b[1;37m";
    pub const MAGENTA: &'static str = "\x1b[1;38;2;255;42;133m";
    pub const CYAN: &'static str = "\x1b[1;38;2;56;189;248m";
    pub const BLUE: &'static str = "\x1b[38;2;168;85;247m";
    pub const GREEN: &'static str = "\x1b[1;38;2;52;211;153m";
    pub const GRAY: &'static str = "\x1b[38;2;148;163;184m";
    pub const YELLOW: &'static str = "\x1b[1;38;2;251;191;36m";
    pub const RED: &'static str = "\x1b[1;38;2;248;113;113m";
}

/// Menghapus urutan escape ANSI untuk perhitungan panjang karakter visual yang akurat (`SPEC.md` §3.3 #0).
pub fn strip_ansi(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("valid ANSI regex"));
    re.replace_all(s, "").into_owned()
}

/// Menambahkan spasi ke teks hingga mencapai lebar visual `width` (`SPEC.md` §3.3 #1).
pub fn pad_ansi(text: &str, width: usize) -> String {
    let vis_len = strip_ansi(text).chars().count();
    let pad = width.saturating_sub(vis_len);
    format!("{}{}", text, " ".repeat(pad))
}

/// Menginisialisasi mode konsol terminal agar mendukung sekuens warna ANSI (`SPEC.md` §3.3 #2 `init_terminal`).
pub fn init_terminal() {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd").args(["/c", ""]).status();
    }
    let _ = io::stdout().flush();
}
pub fn clear_screen() {
    print!("\x1b[2J\x1b[H");
    let _ = io::stdout().flush();
}

pub fn log_info(msg: &str) {
    println!("{}[*]{} {}", Colors::CYAN, Colors::RESET, msg);
}

pub fn log_success(msg: &str) {
    println!("{}[+]{} {}", Colors::GREEN, Colors::RESET, msg);
}

pub fn log_warn(msg: &str) {
    println!("{}[!]{} {}", Colors::YELLOW, Colors::RESET, msg);
}

pub fn log_error(msg: &str) {
    eprintln!("{}[-]{} {}", Colors::RED, Colors::RESET, msg);
}

pub fn prompt_line(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_and_pad_ansi() {
        let colored = format!("{}Halo{}", Colors::GREEN, Colors::RESET);
        assert_eq!(strip_ansi(&colored), "Halo");
        let padded = pad_ansi(&colored, 10);
        assert_eq!(strip_ansi(&padded).len(), 10);
    }

    #[test]
    fn test_init_terminal() {
        init_terminal();
    }
}
