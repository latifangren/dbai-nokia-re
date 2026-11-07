use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

/// Biner BusyBox ARM32 statis (`1.148.524` byte, entri KAX #25 di `0x210f439`) disematkan langsung di `.rodata`.
pub const BUSYBOX_BYTES: &[u8] = include_bytes!("../assets/busybox");

/// Biner helper `test_decrypt_node` AArch64 (`131.593` byte, entri KAX #32 di `0x2233d12`) disematkan langsung di `.rodata`.
pub const TEST_DECRYPT_NODE_BYTES: &[u8] = include_bytes!("../assets/test_decrypt_node");

/// Ukuran blok pengiriman HTTP `/busybox` (64 KiB sesuai `BusyBoxHandler.do_GET` di `SPEC.md` §5.1).
pub const HTTP_CHUNK_SIZE: usize = 65_536;

/// Pembatas 4 titik dua antara nama berkas dan isi partisi pada stream TCP port 8888 (`SPEC.md` §5.1).
pub const STREAM_HEADER_DELIMITER: &[u8] = b"::::";

/// Mem-parsing baris pertama request HTTP (`GET /busybox HTTP/1.1`) menjadi `(method, clean_path)`.
pub fn parse_http_request_target(req: &[u8]) -> Option<(&str, &str)> {
    let text = std::str::from_utf8(req).ok()?;
    let first_line = text.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let raw_target = parts.next()?;
    let clean_path = raw_target.split('?').next().unwrap_or(raw_target);
    Some((method, clean_path))
}

/// Menangani satu koneksi HTTP pada port 8081 langsung dari memori `.rodata` tanpa menyentuh disk (`SPEC.md` §5.1).
pub fn handle_http_connection(mut conn: TcpStream) -> io::Result<Option<String>> {
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;
    conn.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut req_buf = [0u8; 4096];
    let n = conn.read(&mut req_buf)?;
    if n == 0 {
        return Ok(None);
    }

    let Some((method, path)) = parse_http_request_target(&req_buf[..n]) else {
        let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        conn.write_all(resp)?;
        return Ok(None);
    };

    if method != "GET" && method != "HEAD" {
        let resp = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        conn.write_all(resp)?;
        return Ok(None);
    }

    let payload: Option<(&str, &[u8])> = match path {
        "/busybox" | "/bin/busybox" => Some(("busybox", BUSYBOX_BYTES)),
        "/test_decrypt_node" | "/bin/test_decrypt_node" => {
            Some(("test_decrypt_node", TEST_DECRYPT_NODE_BYTES))
        }
        _ => None,
    };

    if let Some((served_name, bytes)) = payload {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        );
        conn.write_all(header.as_bytes())?;
        if method == "GET" {
            for chunk in bytes.chunks(HTTP_CHUNK_SIZE) {
                conn.write_all(chunk)?;
            }
        }
        conn.flush()?;
        Ok(Some(served_name.to_string()))
    } else {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        conn.write_all(resp)?;
        conn.flush()?;
        Ok(None)
    }
}

/// Server HTTP in-memory untuk menyajikan `/busybox` (dan `/test_decrypt_node`) pada port 8081 (`SPEC.md` §5.1).
pub struct InMemoryHttpServer {
    pub port: u16,
    pub running: Arc<AtomicBool>,
    pub requests_served: Arc<AtomicU64>,
}

impl InMemoryHttpServer {
    pub fn start(port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port))?;
        let local_port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let running = Arc::new(AtomicBool::new(true));
        let requests_served = Arc::new(AtomicU64::new(0));
        let run_flag = Arc::clone(&running);
        let counter = Arc::clone(&requests_served);

        std::thread::spawn(move || {
            while run_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_nonblocking(false);
                        let counter_clone = Arc::clone(&counter);
                        std::thread::spawn(move || {
                            if let Ok(Some(_served)) = handle_http_connection(stream) {
                                counter_clone.fetch_add(1, Ordering::Relaxed);
                            }
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            port: local_port,
            running,
            requests_served,
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for InMemoryHttpServer {
    fn drop(&mut self) {
        self.stop();
    }
}

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

/// Menangani satu koneksi TCP streaming dari `busybox nc` dan menyimpannya ke dalam `backup_dir` (`SPEC.md` §5.1).
pub fn handle_tcp_stream_connection(
    mut conn: TcpStream,
    backup_dir: &Path,
) -> io::Result<(String, u64)> {
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
    if clean_rel.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Header stream TCP menghasilkan nama berkas kosong atau tidak valid",
        ));
    }
    let dest_path = backup_dir.join(&clean_rel);
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = File::create(&dest_path)?;
    let mut total_written = 0u64;
    if !initial_rest.is_empty() {
        file.write_all(initial_rest).map_err(map_enospc_error)?;
        total_written += initial_rest.len() as u64;
    }

    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = conn.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).map_err(map_enospc_error)?;
        total_written += n as u64;
    }
    file.flush().map_err(map_enospc_error)?;
    Ok((rel_name, total_written))
}

fn map_enospc_error(err: io::Error) -> io::Error {
    if err.raw_os_error() == Some(28) {
        io::Error::new(
            err.kind(),
            "ENOSPC (errno 28): Ruang penyimpanan disk PC penuh saat menerima stream partisi!",
        )
    } else {
        err
    }
}

pub struct TcpBackupReceiver {
    pub port: u16,
    pub running: Arc<AtomicBool>,
    pub backup_done: Arc<AtomicBool>,
    pub files_received: Arc<AtomicU64>,
}

impl TcpBackupReceiver {
    pub fn start(port: u16, backup_dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&backup_dir)?;
        let listener = TcpListener::bind(("0.0.0.0", port))?;
        let local_port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let running = Arc::new(AtomicBool::new(true));
        let backup_done = Arc::new(AtomicBool::new(false));
        let files_received = Arc::new(AtomicU64::new(0));
        let run_flag = Arc::clone(&running);
        let done_flag = Arc::clone(&backup_done);
        let count_flag = Arc::clone(&files_received);
        let backup_dir = Arc::new(backup_dir);

        std::thread::spawn(move || {
            while run_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_nonblocking(false);
                        let done_clone = Arc::clone(&done_flag);
                        let count_clone = Arc::clone(&count_flag);
                        let dir_clone = Arc::clone(&backup_dir);
                        std::thread::spawn(move || {
                            if let Ok((filename, bytes)) =
                                handle_tcp_stream_connection(stream, &dir_clone)
                            {
                                count_clone.fetch_add(1, Ordering::Relaxed);
                                println!(
                                    "{}[TCP SAVED]{} Selesai: {} ({} bytes)",
                                    crate::ui::Colors::GREEN,
                                    crate::ui::Colors::RESET,
                                    filename,
                                    bytes
                                );
                                if filename == "md5sums.txt" || filename.ends_with(".tar.gz") {
                                    done_clone.store(true, Ordering::Relaxed);
                                }
                            }
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            port: local_port,
            running,
            backup_done,
            files_received,
        })
    }

    pub fn reset_done(&self) {
        self.backup_done.store(false, Ordering::Relaxed);
    }

    pub fn wait_until_done(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.backup_done.load(Ordering::Relaxed) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.backup_done.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for TcpBackupReceiver {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Gabungan server latar belakang (`HTTP:8081` in-memory + `TCP:8888` receiver) sesuai `BackgroundServers` (`SPEC.md` §5.1).
pub struct BackgroundServers {
    pub http: InMemoryHttpServer,
    pub tcp: TcpBackupReceiver,
}

impl BackgroundServers {
    pub fn start(http_port: u16, tcp_port: u16, backup_dir: PathBuf) -> io::Result<Self> {
        let http = InMemoryHttpServer::start(http_port)?;
        let tcp = match TcpBackupReceiver::start(tcp_port, backup_dir) {
            Ok(t) => t,
            Err(e) => {
                http.stop();
                return Err(e);
            }
        };
        Ok(Self { http, tcp })
    }

    pub fn stop(&self) {
        self.http.stop();
        self.tcp.stop();
    }
}

impl Drop for BackgroundServers {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_assets_integrity() {
        // Verifikasi ukuran & header ELF32 ARM untuk busybox (KAX #25)
        assert_eq!(BUSYBOX_BYTES.len(), 1_148_524);
        assert_eq!(&BUSYBOX_BYTES[0..4], b"\x7fELF");
        assert_eq!(BUSYBOX_BYTES[4], 1); // ELFCLASS32
        assert_eq!(
            u16::from_le_bytes([BUSYBOX_BYTES[18], BUSYBOX_BYTES[19]]),
            0x28 // EM_ARM
        );

        // Verifikasi ukuran & header ELF64 AArch64 untuk test_decrypt_node (KAX #32)
        assert_eq!(TEST_DECRYPT_NODE_BYTES.len(), 131_593);
        assert_eq!(&TEST_DECRYPT_NODE_BYTES[0..4], b"\x7fELF");
        assert_eq!(TEST_DECRYPT_NODE_BYTES[4], 2); // ELFCLASS64
        assert_eq!(
            u16::from_le_bytes([TEST_DECRYPT_NODE_BYTES[18], TEST_DECRYPT_NODE_BYTES[19]]),
            0xb7 // EM_AARCH64
        );
    }

    #[test]
    fn test_in_memory_http_server_serves_busybox_and_404() {
        let srv = InMemoryHttpServer::start(0).expect("bind ephemeral port");
        let addr = format!("127.0.0.1:{}", srv.port);

        // 1. Uji GET /busybox
        let mut client = TcpStream::connect(&addr).unwrap();
        client
            .write_all(b"GET /busybox HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();

        let header_end = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("HTTP header delimiter")
            + 4;
        let header_str = std::str::from_utf8(&resp[..header_end]).unwrap();
        assert!(header_str.starts_with("HTTP/1.1 200 OK"));
        assert!(header_str.contains("Content-Length: 1148524"));
        let body = &resp[header_end..];
        assert_eq!(body.len(), BUSYBOX_BYTES.len());
        assert_eq!(body, BUSYBOX_BYTES);

        // 2. Uji GET /notfound -> 404
        let mut client404 = TcpStream::connect(&addr).unwrap();
        client404
            .write_all(b"GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut resp404 = Vec::new();
        client404.read_to_end(&mut resp404).unwrap();
        let resp404_str = String::from_utf8_lossy(&resp404);
        assert!(resp404_str.starts_with("HTTP/1.1 404 Not Found"));

        srv.stop();
    }

    #[test]
    fn test_split_stream_header() {
        let sample = b"non-userarea/mmcblk0boot0.bin::::\x01\x02\x03\x04";
        let (name, rest) = split_stream_header(sample).unwrap();
        assert_eq!(name, "non-userarea/mmcblk0boot0.bin");
        assert_eq!(rest, &[1, 2, 3, 4]);
    }
    #[test]
    fn test_handle_tcp_stream_connection_rejects_parent_dir() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (server_conn, _) = listener.accept().unwrap();
            let temp_dir = std::env::temp_dir().join(format!("test_reject_{}", rand::random::<u32>()));
            let _ = fs::create_dir_all(&temp_dir);
            let res = handle_tcp_stream_connection(server_conn, &temp_dir);
            let _ = fs::remove_dir_all(&temp_dir);
            res
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"..::::data").unwrap();
        drop(client);

        let res = handle.join().unwrap();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
