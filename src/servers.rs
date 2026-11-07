use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

/// Pembatas 4 titik dua antara nama berkas dan isi partisi pada stream TCP port 8888 (`SPEC.md` §5.1).
pub const STREAM_HEADER_DELIMITER: &[u8] = b"::::";

/// Memisahkan buffer awal stream menjadi `(nama_berkas_relatif, sisa_byte_awal_payload)` (`SPEC.md` §5.1).
pub fn split_stream_header(buf: &[u8]) -> Option<(String, &[u8])> {
    let pos = buf
        .windows(STREAM_HEADER_DELIMITER.len())
        .position(|w| w == STREAM_HEADER_DELIMITER)?;
    let name_bytes = &buf[..pos];
    let rest = &buf[pos + STREAM_HEADER_DELIMITER.len()..];
    let filename = String::from_utf8_lossy(name_bytes).trim().to_string();
    if filename.is_empty() {
        return None;
    }
    Some((filename, rest))
}

/// Menangani satu koneksi TCP streaming dari `busybox nc` dan menyimpannya ke dalam `backup_dir`.
pub fn handle_tcp_stream_connection(mut conn: TcpStream, backup_dir: &Path) -> io::Result<(String, u64)> {
    conn.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut header_buf = Vec::with_capacity(256);
    let mut one_byte = [0u8; 1];

    while header_buf.len() < 4096 {
        let n = conn.read(&mut one_byte)?;
        if n == 0 {
            break;
        }
        header_buf.push(one_byte[0]);
        if header_buf.ends_with(STREAM_HEADER_DELIMITER) {
            break;
        }
    }

    let (rel_name, initial_rest) = split_stream_header(&header_buf).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Header stream TCP tidak memiliki pembatas '::::'",
        )
    })?;

    // Cegah path traversal di luar backup_dir
    let clean_rel: PathBuf = Path::new(&rel_name)
        .components()
        .filter(|c| matches!(c, std::path::Component::Normal(_)))
        .collect();
    let dest_path = backup_dir.join(&clean_rel);
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = File::create(&dest_path)?;
    let mut total_written = 0u64;
    if !initial_rest.is_empty() {
        file.write_all(initial_rest)?;
        total_written += initial_rest.len() as u64;
    }

    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = conn.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        total_written += n as u64;
    }
    file.flush()?;
    Ok((rel_name, total_written))
}

pub struct TcpBackupReceiver {
    pub running: Arc<AtomicBool>,
    pub backup_done: Arc<AtomicBool>,
}

impl TcpBackupReceiver {
    pub fn start(port: u16, backup_dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&backup_dir)?;
        let listener = TcpListener::bind(("0.0.0.0", port))?;
        listener.set_nonblocking(true)?;

        let running = Arc::new(AtomicBool::new(true));
        let backup_done = Arc::new(AtomicBool::new(false));
        let run_flag = Arc::clone(&running);
        let done_flag = Arc::clone(&backup_done);

        std::thread::spawn(move || {
            while run_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_nonblocking(false);
                        if let Ok((filename, _bytes)) = handle_tcp_stream_connection(stream, &backup_dir) {
                            if filename == "md5sums.txt" || filename.ends_with(".tar.gz") {
                                done_flag.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            running,
            backup_done,
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_stream_header() {
        let sample = b"non-userarea/mmcblk0boot0.bin::::\x01\x02\x03\x04";
        let (name, rest) = split_stream_header(sample).unwrap();
        assert_eq!(name, "non-userarea/mmcblk0boot0.bin");
        assert_eq!(rest, &[1, 2, 3, 4]);
    }
}
