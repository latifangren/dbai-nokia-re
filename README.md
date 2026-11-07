# DBAI-NOKIA-RS (`v1.1.0`)

> **Clean-Room Native Rust Toolkit for Nokia FastMile 5G Gateway 2 (`5GGW2-OMNI-2`)**  
> Manajemen Perangkat, eMMC Backup & Restore Dumper, Verifikasi Integritas MD5, dan Ekstraksi Metadata Kredensial Pabrik.

[![Rust Edition](https://img.shields.io/badge/Rust-2021_Edition-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Target Platform](https://img.shields.io/badge/Hardware-Nokia_FastMile_5GGW2--OMNI--2-blueviolet.svg)](#)
[![Binary Size](https://img.shields.io/badge/Binary_Size-4.4_MB_Native-success.svg)](#perbandingan-arsitektur-why)

---

## Daftar Isi
1. [Judul & Deskripsi Singkat](#1-judul--deskripsi-singkat)
   - [Deskripsi Fungsional (What)](#deskripsi-fungsional-what)
   - [Perbandingan Arsitektur (Why)](#perbandingan-arsitektur-why)
2. [Fitur Utama](#2-fitur-utama)
   - [Protokol Web CGI Nokia (`src/web_cgi.rs`)](#protokol-web-cgi-nokia-srcweb_cgirs)
   - [In-Memory Background Servers (`src/servers.rs`)](#in-memory-background-servers-srcserversrs)
   - [SSH Sniper & Guardian (`src/sniper.rs`)](#ssh-sniper--guardian-srcsniperrs)
   - [Full eMMC Dumper & JEDEC EXT_CSD Health (`src/dumper.rs`)](#full-emmc-dumper--jedec-ext_csd-health-srcdumperrs)
   - [Verifikasi Integritas MD5 & Auto-Retry (`src/md5_verifier.rs`)](#verifikasi-integritas-md5--auto-retry-srcmd5_verifierrs)
   - [Ekstraksi Identitas & Kredensial Pabrik (`src/mim_extractor.rs`)](#ekstraksi-identitas--kredensial-pabrik-srcmim_extractorrs)
3. [Struktur Direktori & Modul](#3-struktur-direktori--modul)
4. [Prasyarat & Cara Kompilasi / Menjalankan (How)](#4-prasyarat--cara-kompilasi--menjalankan-how)
5. [Panduan Menu Interaktif CLI](#5-panduan-menu-interaktif-cli)
   - [Struktur Direktori Hasil Backup (`image_backup/`)](#struktur-direktori-hasil-backup-image_backup)

---

## 1. Judul & Deskripsi Singkat

### Deskripsi Fungsional (What)
**`dbai-nokia-rs` (v1.1.0)** adalah rekonstruksi *clean-room* berbasis bahasa pemrograman **Rust native** dari toolkit manajemen perangkat, backup partisi eMMC tingkat rendah, verifikasi integritas citra firmware, serta ekstraksi metadata identitas perangkat keras untuk modem/gateway **Nokia FastMile 5G Gateway 2 (`5GGW2-OMNI-2`)**.

Perangkat lunak ini dirancang untuk beroperasi secara mandiri tanpa memerlukan instalasi interpreter bahasa tingkat tinggi (seperti Python) atau runtime eksternal. Seluruh interaksi jaringan dengan modem (protokol Web CGI, handshaking SSH, HTTP binary serving, dan TCP stream receiving) diimplementasikan secara murni dengan performa tinggi, keamanan memori (*memory safety*), dan konkurensi native.

### Perbandingan Arsitektur (Why)
Biner orisinal alat ini (`dbai-nokia-win64.exe`) dibangun menggunakan kompilator Nuitka Onefile yang membundel interpreter CPython 3.13 beserta berbagai ekstensi dinamis. Arsitektur tersebut memiliki sejumlah kelemahan operasional signifikan:

1. **Overhead Ukuran Biner:** Biner lama berukuran **~46,3 MB** (`46.329.344` byte) karena menyertakan seluruh runtime CPython (`python313.dll`), OpenSSL (`libcrypto-3.dll`), serta modul ekstensi kriptografi (`cryptography_rust.dll`).
2. **Ekstraksi Berkas Sementara ke Disk (%TEMP% Pollution):** Setiap kali biner lama dieksekusi, lapisan *bootloader* Nuitka mengekstrak **36 berkas pustaka** ke dalam subdirektori acak `%TEMP%\onefile_{PID}_{TIME}_{RANDOM}`. Hal ini memicu latensi startup yang tinggi, keausan storage pada PC pengguna, dan meninggalkan sampah berkas jika aplikasi dimatikan secara mendadak.
3. **Ketergantungan Ekstraksi Aset Modem:** Komponen biner ARM pembantu (`bin/busybox` dan `bin/test_decrypt_node`) diekstrak terlebih dahulu ke media penyimpanan PC sebelum disajikan ke modem.

Implementasi **`dbai-nokia-rs`** mengatasi seluruh kelemahan tersebut:
- **Ukuran Sangat Ramping (~4,4 MB):** Dibuat sebagai *single static binary* murni yang dioptimasi dengan Link-Time Optimization (`lto = true`), `opt-level = "z"`, dan penghapusan simbol debug (`strip = true`).
- **Aset Tertanam Langsung di `.rodata`:** Berkas pembantu arsitektur target—yaitu `assets/busybox` (ELF32 ARM static, 1.148.524 byte) dan `assets/test_decrypt_node` (ELF64 AArch64, 131.593 byte)—disematkan langsung ke dalam segmen memori baca-saja (`.rodata`) biner executable melalui makro `include_bytes!`.
- **Nol Ekstraksi Disk PC:** Server HTTP internal melayani berkas langsung dari irisan memori RAM (`&[u8]`). Tidak ada berkas sementara yang pernah dibuat di disk PC host selama siklus serving aset.
- **Startup Instan & Aman:** Menghilangkan overhead ekstraksi arsip `KAX` dan inisialisasi runtime Python, menghasilkan waktu respons instan (< 10 ms).

| Parameter Arsitektural | Biner Lama (Nuitka / CPython 3.13) | `dbai-nokia-rs` v1.1.0 (Rust Native) |
|---|---|---|
| **Ukuran Executable** | ~46,3 MB (`46.329.344` B) | **~4,4 MB** (`4.613.736` B) |
| **Penyajian Aset (`busybox`)** | Ekstrak ke `%TEMP%` disk PC lalu baca file | **Tertanam di `.rodata` RAM (In-Memory HTTP)** |
| **Startup Latency** | 1.500 – 3.000 ms (I/O unpacking) | **< 15 ms (Native initialization)** |
| **Dependensi Eksternal PC** | Visual C++ Redistributable, Python DLLs | **Nol dependensi (Hanya OpenSSH `ssh` di PATH)** |
| **Manajemen Memori** | Garbage Collection CPython + Reference Count | **Compile-Time RAII & Zero-Cost Abstractions** |
| **Keamanan Thread** | Global Interpreter Lock (GIL) | **Multi-threading sejati (std::thread / Arc / Atomics)** |

---

## 2. Fitur Utama

```
                     +---------------------------------------+
                     |    dbai-nokia-rs CLI (Port 8081/8888)  |
                     +-------------------+-------------------+
                                         |
            [1] Auth CGI (Iterated SHA256| [2] SSH Guardian / Sniper
                + AES-CBC/RSA + CSRF)    |     (Port Polling & Keeper)
                                         v
                     +---------------------------------------+
                     |  Nokia FastMile 5GGW2-OMNI-2 Gateway  |
                     +-------------------+-------------------+
                                         |
            [3] HTTP In-Memory Download  | [4] TCP Raw Stream Backup
                (busybox / test_decrypt) |     (50 Partisi + ext_csd + boot)
                                         v
                     +---------------------------------------+
                     |  image_backup/ (MD5 Verification &    |
                     |  Auto-Retry 3x + Factory_MIM Decrypt) |
                     +---------------------------------------+
```

### Protokol Web CGI Nokia (`src/web_cgi.rs`)
Menyediakan modul komunikasi client HTTP terhadap endpoint CGI bawaan modem Nokia FastMile dengan implementasi kriptografi spesifik vendor:
1. **Autentikasi 4 Langkah Vendor-Spesifik:**
   - **Langkah 1 (Handshake Nonce):** Mengirim request `GET /login_web_app.cgi?nonce` untuk memperoleh parameter `nonce`, `randomKey`, jumlah iterasi dinamis (`iterations`, misal: 1000x), serta kunci publik RSA modem (`pubkey`).
   - **Langkah 2 (Secret Hash Iterasi):** Menghitung hash awal `H_0 = SHA256(user + ":" + alati + ":" + password)`, kemudian melakukan hashing berulang (*iterated SHA-256*) sebanyak `iterations` kali: `H_i = SHA256(H_{i-1})`. Hasil akhirnya dikombinasikan dengan `nonce` dan `randomKey`.
   - **Langkah 3 (Substitusi Base64 Proprietary Nokia):** Mengonversi string Base64 standar ke dialek URL-safe khusus Nokia:
     $$\text{'+'} \longrightarrow \text{'-'}, \quad \text{'/'} \longrightarrow \text{'_'}, \quad \text{'='} \longrightarrow \text{'.'}$$
   - **Langkah 4 (Enkripsi Payload Hibrida):** Mengenkripsi muatan data login menggunakan kombinasi `AES-128-CBC` (padding PKCS#7) dengan kunci acak dan IV acak. Kunci simetris tersebut dienkripsi menggunakan `RSA-PKCS1v15` dengan kunci publik modem.
2. **Proteksi Token Sesi & CSRF:** Menangani session cookie dan mem-parsing parameter `csrf_token` dari respons server web untuk mengamankan panggilan POST administratif lanjutan (seperti `/reboot_web_app.cgi`).

### In-Memory Background Servers (`src/servers.rs`)
Menyediakan dua layanan server latar belakang multi-thread independen yang dirancang khusus untuk meminimalkan beban I/O pada storage PC:
1. **Server HTTP In-Memory (Port default: `8081`):**
   - Berjalan pada thread terisolasi menggunakan `TcpListener`.
   - Melayani endpoint `GET /busybox` dan `GET /test_decrypt_node`.
   - Seluruh payload disajikan langsung dari referensi memori `.rodata` menggunakan chunking 64 KiB (`HTTP_CHUNK_SIZE`), memastikan modem dapat mengunduh biner helper ke direktori `/tmp` modem tanpa PC menulis berkas temporer ke disk.
2. **Receiver TCP Streaming (Port default: `8888`):**
   - Menerima aliran biner dari pipa streaming modem: `(printf "<filename>::::" ; cat /dev/mmcblk0pX) | /tmp/busybox nc <PC_IP> 8888`.
   - **Framing Protokol `::::`:** Memisahkan header nama berkas dari payload biner secara deterministik.
   - **Proteksi Path Traversal:** Memeriksa dan membersihkan setiap nama berkas yang diterima; secara tegas menolak komponen direktori berbahaya (`..`), karakter kendali ASCII, serta menormalkan penyimpanan di dalam direktori `image_backup/`.
   - **Deteksi Kapasitas Penyimpanan (ENOSPC):** Memeriksa ketersediaan ruang disk PC sebelum dan selama transfer (batas aman minimum: **5.0 GB**). Jika media penyimpanan PC penuh, receiver mendeteksi error `ENOSPC`, mencatat peringatan secara elegan, dan memutus aliran tanpa merusak berkas yang sudah tersimpan.

### SSH Sniper & Guardian (`src/sniper.rs`)
Mengelola otomatisasi siklus hidup koneksi SSH tingkat rendah pada port `2222` dan `22`:
1. **Pemantauan Siklus Shutdown 4 Port:**
   - Memantau port layanan inti modem secara konkuren: port `(443, 80, 53, 2222)`.
   - Mendeteksi kondisi saat sistem modem benar-benar mati (*shutdown confirmation* saat seluruh port menolak koneksi/timeout), kemudian mendeteksi momen presisi saat sistem hidup kembali (*sniper interception*).
2. **Validasi Boot Baru (*Fresh Boot Verification*):**
   - Membaca nilai dari `/proc/uptime` modem dan memastikan `uptime <= 90.0` detik. Ini menjamin sesi eksekusi berjalan pada siklus boot yang bersih, menghindari benturan proses yang tersisa dari sesi sebelumnya.
3. **Watchdog In-Memory (`/tmp/ssh_keeper.sh`):**
   - Menginjeksi dan mengeksekusi skrip penjaga di RAM modem untuk mencegah *watchdog daemon* bawaan firmware mematikan service Dropbear/SSH.
4. **Pengubahan Password SuperAdmin Web GUI:**
   - Menghitung nilai hash `SHA-256 UPPERCASE` dari kata sandi SuperAdmin baru (default: `DBAI2K27`) dan menyuntikkannya ke datamodel TR-069 melalui CLI internal modem:
     ```sh
     cfgcli -s InternetGatewayDevice.X_Authentication.WebAccount.Enable 1 && cfgcli -s InternetGatewayDevice.X_Authentication.WebAccount.Password <HASH_UPPERCASE> && cfgcli --save-db
     ```
5. **Pemicu 5 Langkah Pembaruan OTA (Nokia Cloud FOTA):**
   - **Langkah 1:** Membaca versi firmware yang sedang aktif (`cat /etc/version || uname -a`).
   - **Langkah 2:** Mengaktifkan entri Software Management pada konfigurasi datamodel TR-069 via `cfgcli`.
   - **Langkah 3:** Mematikan dan me-restart daemon `swmgnt`.
   - **Langkah 4:** Mengirim sinyal D-Bus sistem untuk memicu proses pengecekan firmware ke cloud Nokia.
   - **Langkah 5:** Memantau ekor log FOTA pada modem (`/tmp/fota.log` atau `/data/fota.log`).
6. **Unroot & Pembersihan Artefak (*System Cleanup*):**
   - Menghentikan proses pengawas PID (`/tmp/fastmile_keeper.pid`), mematikan daemon `ssh_keeper.sh`, menghapus seluruh berkas sementara dan injeksi konfigurasi (`/configs/aic_conf.json`, `/configs/init_action.sh`, `/tmp/busybox`, `/tmp/test_decrypt_node`, `/configs/nonpersistant/*`), lalu menjalankan sinkronisasi disk (`sync`).

### Full eMMC Dumper & JEDEC EXT_CSD Health (`src/dumper.rs`)
Menyediakan mesin pencadangan menyeluruh untuk seluruh chip penyimpanan flash eMMC:
1. **Streaming 50 Partisi User-Area:**
   - Mengekstrak `/dev/mmcblk0p1` hingga `/dev/mmcblk0p50` secara berurutan dan mengalirkannya ke PC sebagai berkas `.img` mentah.
2. **Pencadangan Partisi Non-User Area & Register:**
   - Partisi bootloader perangkat keras: `mmcblk0boot0.bin` dan `mmcblk0boot1.bin`.
   - Register biner Extended CSD 512-byte: `ext_csd.bin` (diekstrak dari debugfs kernel).
   - Metadata perangkat keras sysfs: `CID.txt` (Card Identification Register) dan `CSD.txt` (Card Specific Data).
3. **Identifikasi Vendor eMMC & Marking IC Fisik:**
   - Memetakan ID pabrikan (`manfid`) ke database vendor semikonduktor resmi, termasuk identifikasi khusus chip **BIWIN (`0x0000f4`)** dengan penandaan fisik:
     `BWCMAB811G04G 233254126 1258RD (BIWIN 4GB eMMC 5.1 BGA-153)`
   - Mendukung vendor besar lainnya: Samsung (`0x15`), SK Hynix (`0x90`), Micron (`0x13`), Kioxia/Toshiba (`0x11`), SanDisk/WD (`0x45`), dan Kingston (`0x70`).
4. **Laporan Kesehatan Standar JEDEC eMMC (EXT_CSD):**
   - **Offset 267 (`PRE_EOL_INFO`):** Estimasi masa pakai perangkat secara umum (`0x01`: Normal < 80%, `0x02`: Peringatan 80–90%, `0x03`: Kritis > 90%).
   - **Offset 268 (`DEVICE_LIFE_TIME_EST_TYP_A`):** Estimasi persentase keausan endurance pada blok SLC cache (resolusi per 10%).
   - **Offset 269 (`DEVICE_LIFE_TIME_EST_TYP_B`):** Estimasi persentase keausan endurance pada blok array memori utama MLC/TLC (resolusi per 10%).
   - Data diformat dan disimpan ke `image_backup/non-userarea/info_eMMC.txt`.
5. **Backup Tarball Konfigurasi:**
   - Mengompresi dan mentransfer arsip direktori sistem `/data` (`user_data_dir.tar.gz`) dan `/rom/etc` (`rom_etc_dir.tar.gz`).

### Verifikasi Integritas MD5 & Auto-Retry (`src/md5_verifier.rs`)
Menjamin keabsahan berkas dump melalui mekanisme kriptografis otomatis:
1. **Validasi Hash Komprehensif:**
   - Modem menghitung nilai MD5 dari setiap partisi langsung dari blok `/dev/` dan mencatatnya ke `/tmp/md5sums.txt`.
   - Modul `MD5Validator` pada PC membaca `md5sums.txt` dan menghitung ulang hash MD5 dari setiap berkas `.img` dan `.bin` lokal menggunakan algoritma MD5 streaming ber-buffer (blok 256 KiB).
2. **Pengecualian Partisi Dinamis (`WAJAR-RW`):**
   - Partisi yang berstatus read-write aktif dan secara rutin diperbarui oleh kernel saat modem menyala (`user_data.img`, `user_data`, `userdata`, `swr.img`, `swr`) ditandai secara otomatis sebagai `WAJAR-RW` (bukan kegagalan integritas), menghindari alarm palsu (*false positive*).
3. **Mekanisme Auto-Redump Presisi (Hingga 3x Percobaan):**
   - Apabila terdapat partisi penting yang korup (*hash mismatch*) atau terputus saat transfer (*missing partition*), sistem **tidak perlu mengulang seluruh dump 4 GB**.
   - Sistem secara presisi hanya memicu pembacaan ulang pada partisi yang bermasalah, mengalirkannya kembali ke PC, memperbarui entri hash, dan memvalidasi ulang hingga maksimal 3 kali iterasi per partisi.

### Ekstraksi Identitas & Kredensial Pabrik (`src/mim_extractor.rs`)
Menyediakan modul investigasi metadata pabrik (*hardware identity & credentials*):
1. **Spesifikasi Blok Struktur `Factory_MIM`:**
   - Blok memori diawali dengan *magic identifier* `5GGW2-OMNI-2\0`.
   - Struktur data selaras 128-byte (*128-byte aligned block*), di mana setiap entri terdiri atas 64 byte nama kunci (*Key*) dan 64 byte nilai data (*Value*).
   - Membaca 24 atribut resmi pabrikan:
     `Product`, `Password`, `ACSPassword`, `ACSCRPassword`, `RootPassword`, `Format`, `FactoryCode`, `HWVersion`, `ICS`, `SN`, `CLEI`, `Mnemonic`, `ProgDate`, `MACAddress`, `PartNbr`, `PartNbrRev`, `OperatorID`, `CountryID`, `IMEI`, `PartNbr2`, `PartNbrRev2`, `PartNbr3`, `PartNbrRev3`, `WiFiPassword`.
2. **Dua Mode Operasi Ekstraksi:**
   - **Mode 1: Live via SSH:**
     - Mengunggah biner `test_decrypt_node` (ELF64 AArch64) ke `/tmp/test_decrypt_node` modem.
     - Membaca partisi `/dev/block/Factory_MIM`.
     - Mengambil baris root dari `/etc/shadow`.
     - Mengeksekusi `test_decrypt_node` terhadap basis data terenkripsi modem (`libcfgdb.so`).
     - Melakukan pencocokan otomatis terhadap kamus potfile Hashcat bawaan untuk mengetahui kata sandi *plaintext*.
     - Menyusun laporan komprehensif dan menyimpannya ke `image_backup/credentials/info_<SN>.txt`.
   - **Mode 2: Offline Carving:**
     - Mampu membaca langsung berkas dump partisi tunggal (`Factory_MIM.img`) maupun berkas dump fisik eMMC mentah berukuran besar (*multi-gigabyte raw image*).
     - Menggunakan pemindaian *sliding window* untuk menemukan *magic needle*, mem-parsing blok selaras 128-byte, dan menghasilkan laporan identitas tanpa memerlukan modem yang hidup.

---

## 3. Struktur Direktori & Modul

### Pohon Direktori Proyek
```
dbai-nokia-re/
├── Cargo.toml               # Konfigurasi dependensi, metadata & build profile release
├── .gitignore               # Aturan pengabaian Git (target, backup, kunci lokal)
├── assets/                  # Biner arsitektur target disematkan ke .rodata
│   ├── busybox              # ELF 32-bit ARM static executable (1.148.524 byte)
│   └── test_decrypt_node    # ELF 64-bit AArch64 executable (131.593 byte)
├── refrence/
│   └── SPEC.md              # Spesifikasi audit teknis & hasil reverse engineering v2
└── src/
    ├── main.rs              # Entry point CLI, orkestrasi full pipeline & menu loop
    ├── config.rs            # Manajemen konfigurasi runtime (config_toolkit.json)
    ├── dumper.rs            # Mesin dump eMMC, skrip streaming modem & info JEDEC
    ├── md5_verifier.rs      # Validasi MD5, pengecualian WAJAR-RW & auto-redump
    ├── mim_extractor.rs     # Parser Factory_MIM, live/offline decrypt & hashcat
    ├── servers.rs           # HTTP server (port 8081) & TCP receiver (port 8888)
    ├── sniper.rs            # SSH sniper, port shutdown polling, keeper & OTA
    ├── ssh_keys.rs          # Generator kunci RSA 2048-bit & perbaikan izin OpenSSH
    └── ui.rs                # Utilitas rendering terminal ANSI, banner & input prompt
```

### Tanggung Jawab Modul (`src/*.rs`)

| Modul | Berkas Sumber | Tanggung Jawab & Implementasi Teknis |
|---|---|---|
| **App Entry & Menu** | `src/main.rs` | Mengatur loop menu interaktif antarmuka baris perintah, mengelola state aplikasi (`DbaiNokiaApp`), serta menjalankan *Full Automation Pipeline* (`[a]`). |
| **Konfigurasi** | `src/config.rs` | Memuat dan menyimpan preferensi ke `config_toolkit.json`, mendeteksi IP lokal PC melalui socket probe UDP, dan memvalidasi subnet matching terhadap modem. |
| **Web CGI Client** | `src/web_cgi.rs` | Mengatur autentikasi 4 tahap web GUI Nokia (iterated SHA-256, Base64 khusus Nokia, AES-128-CBC + RSA-PKCS1v15), serta eksekusi reboot via HTTP. |
| **In-Memory Servers** | `src/servers.rs` | Menyajikan `assets/busybox` dan `assets/test_decrypt_node` melalui HTTP port 8081 langsung dari RAM; menerima aliran TCP port 8888 dengan proteksi traversal dan deteksi `ENOSPC`. |
| **SSH Sniper** | `src/sniper.rs` | Memantau siklus reboot pada 4 port `(443, 80, 53, 2222)`, memverifikasi `/proc/uptime <= 90.0s`, memasang `ssh_keeper.sh`, mengganti kata sandi SuperAdmin, memicu OTA 5-langkah, dan melakukan unroot cleanup. |
| **eMMC Dumper** | `src/dumper.rs` | Mengonstruksi skrip streaming modem untuk 50 partisi user-area, `boot0`/`boot1`, `ext_csd`, membaca register sysfs (`CID`/`CSD`), memetakan vendor eMMC (termasuk BIWIN `0x0000f4`), dan mem-parsing kesehatan JEDEC. |
| **MD5 Validator** | `src/md5_verifier.rs` | Memvalidasi integritas hash MD5 berkas lokal terhadap `/tmp/md5sums.txt`, mengecualikan partisi dinamis (`WAJAR-RW`), dan mengeksekusi logika *auto-redump* hingga 3x. |
| **MIM Extractor** | `src/mim_extractor.rs` | Memindai dan mem-parsing blok selaras 128-byte `Factory_MIM`, mengekstrak 24 atribut pabrik, mendekripsi node `libcfgdb.so`, mencocokkan potfile Hashcat, dan mengekspor laporan ke `credentials/info_<SN>.txt`. |
| **SSH Key Manager** | `src/ssh_keys.rs` | Membangkitkan pasangan kunci RSA 2048-bit (`fastmile_key` & `fastmile_key.pub`), memformat OpenSSH pubkey, serta mengatur izin ketat berkas (`0600` di Unix atau `icacls` di Windows). |
| **Terminal UI** | `src/ui.rs` | Menyediakan helper visual ANSI: pewarnaan teks, pembersihan layar, perhitungan lebar string dengan escape codes (`pad_ansi`), serta fungsi logging terstandarisasi. |

---

## 4. Prasyarat & Cara Kompilasi / Menjalankan (How)

### Prasyarat Sistem
1. **Rust Toolchain:**
   - Compiler `rustc` dan package manager `cargo` edisi 2021 (versi 1.75.0 atau lebih baru).
   - Dapat diinstal melalui [rustup.rs](https://rustup.rs):
     ```bash
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     ```
2. **Klien OpenSSH:**
   - Perintah `ssh` harus tersedia di variabel lingkungan `$PATH` sistem operasi (Linux, macOS, atau Windows OpenSSH Client).
3. **Konektivitas Jaringan:**
   - PC terhubung langsung ke port LAN modem Nokia FastMile 5G Gateway 2 (biasanya subnet `192.168.1.0/24` dengan IP modem default `192.168.1.1`).

### Kompilasi Biner (Release Build)
Untuk menghasilkan biner bereksekusi mandiri yang telah dioptimalkan secara maksimal:

```bash
cargo build --release
```

Berkas biner hasil kompilasi akan berada di:
- **Linux / macOS:** `target/release/dbai-nokia-rs` (~4,4 MB)
- **Windows:** `target\release\dbai-nokia-rs.exe`

### Menjalankan Pengujian Otomatis (Testing)
Proyek ini dilengkapi dengan rangkaian unit test untuk memastikan integritas logika kriptografi, parsing sysfs, protokol server, dan format blok data:

```bash
cargo test
```

*Contoh output pengujian sukses:*
```text
test config::tests::test_saved_config_round_trip ... ok
test dumper::tests::test_biwin_vendor_lookup_and_report ... ok
test dumper::tests::test_update_health_from_extcsd_jedec_offsets ... ok
test md5_verifier::tests::test_excluded_rw_check ... ok
test md5_verifier::tests::test_parse_ext_csd_health ... ok
test mim_extractor::tests::test_parse_mim_block_128b_aligned ... ok
test mim_extractor::tests::test_mim_extractor_sliding_window_carve ... ok
test servers::tests::test_in_memory_assets_integrity ... ok
test servers::tests::test_tcp_receiver_path_traversal_protection ... ok
test web_cgi::tests::test_nokia_base64_variant ... ok
test web_cgi::tests::test_iterated_sha256 ... ok

test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Menjalankan Linter (Clippy)
Pastikan kode bebas dari peringatan standar Rust:

```bash
cargo clippy -- -D warnings
```

### Menjalankan Aplikasi
Jalankan biner langsung dari terminal:

```bash
# Menjalankan biner release di Linux/macOS
./target/release/dbai-nokia-rs

# Menjalankan biner release di Windows Command Prompt / PowerShell
.\target\release\dbai-nokia-rs.exe
```

---

## 5. Panduan Menu Interaktif CLI

Saat aplikasi dijalankan, layar utama akan menampilkan banner status koneksi jaringan serta menu operasi interaktif:

```text
╔════════════════════════════════════════════════════════════════════════════╗
║  DBAI-NOKIA: Nokia FastMile 5G GW2 Native Toolkit (v1.1-rs)                ║
║  Modem IP: 192.168.1.1 | PC LAN IP: 192.168.1.2 | Output: image_backup     ║
╚════════════════════════════════════════════════════════════════════════════╝

  [a] Full Pipeline (Auto: Keys -> Root -> Reboot -> Servers -> Dump -> MD5 -> Creds)
  [1] Periksa / Generate Pasangan SSH Key (RSA 2048-bit)
  [2] Uji Login Web CGI Nokia (Iterated SHA-256)
  [3] Trigger Reboot Modem (/reboot_web_app.cgi atau SSH)
  [4] Mulai SSH Sniper & Buka Terminal Interaktif
  [5] Jalankan Background Server (HTTP:8081 + TCP:8888)
  [6] Full Dump Partisi eMMC via SSH (52 Partisi + ext_csd)
  [7] Verifikasi Hash MD5 Checksum (+ Auto-Retry <= 3x)
  [8] Backup Direktori (/data & /rom/etc) [Opsional]
  [n] Flash Custom Firmware OpenWrt (Community Easter Egg)
  [s] Ubah Password SuperAdmin (Web GUI)
  [i] Ekstrak Data Identitas & Kredensial Pabrik (Factory_MIM)
  [r] Unroot / Revoke Akses Root & Bersihkan Artefak
  [k] Ubah Pengaturan Konfigurasi
  [m] Trigger OTA Update (Nokia Cloud FOTA)
  [0] Keluar
```

### Tabel Rincian Menu Operasi

| Tombol Menu | Fungsi & Alur Operasi | Keterangan & Detail Teknis |
|:---:|---|---|
| **`[a]`** | **Full Automation Pipeline** | Menjalankan seluruh proses otomatis dari awal hingga akhir: pembuatan SSH key $\to$ verifikasi root $\to$ reboot $\to$ peluncuran background server $\to$ streaming dump 52 partisi $\to$ validasi MD5 dengan auto-redump $\to$ ekstraksi kredensial pabrik. |
| **`[1]`** | **Periksa / Generate SSH Key** | Memeriksa keberadaan `fastmile_key` dan `fastmile_key.pub`. Jika belum ada, membangkitkan pasangan kunci RSA 2048-bit baru dan menerapkan permission aman (`0600`/`icacls`). |
| **`[2]`** | **Uji Login Web CGI Nokia** | Menjalankan protokol autentikasi 4 langkah terhadap `/login_web_app.cgi` menggunakan iterated SHA-256 dan enkripsi AES-CBC + RSA untuk memvalidasi kredensial Web GUI modem. |
| **`[3]`** | **Trigger Reboot Modem** | Mengirimkan sinyal reboot ke modem secara elegan, baik melalui command SSH (`reboot`) jika sesi aktif tersedia, atau melalui request Web CGI terotentikasi (`/reboot_web_app.cgi`). |
| **`[4]`** | **Mulai SSH Sniper & Terminal** | Mengaktifkan pemantauan siklus shutdown 4 port, menunggu modem menyelesaikan booting baru (`uptime <= 90s`), memasang watchdog in-memory, dan membuka shell interaktif langsung ke konsol root modem. |
| **`[5]`** | **Jalankan Background Server** | Menjalankan server HTTP port `8081` (in-memory `.rodata` serving) dan server TCP receiver port `8888` pada background thread secara manual. |
| **`[6]`** | **Full Dump Partisi eMMC** | Memulai proses streaming 50 partisi user-area, partisi bootloader (`boot0`/`boot1`), serta register biner `ext_csd.bin`, `CID.txt`, dan `CSD.txt` melalui pipa jaringan TCP port 8888. |
| **`[7]`** | **Verifikasi Hash MD5 Checksum** | Membandingkan hash MD5 berkas hasil dump lokal dengan catatan resmi modem (`/tmp/md5sums.txt`). Otomatis mengecualikan partisi `WAJAR-RW` dan memicu *auto-redump* hingga 3x jika ditemukan kegagalan. |
| **`[8]`** | **Backup Direktori Tarball** | Membuat arsip tar terkompresi dari direktori dinamis sistem `/data` dan konfigurasi bawaan `/rom/etc`, lalu mengalirkannya langsung ke folder backup PC. |
| **`[n]`** | **Flash OpenWrt (Easter Egg)** | Simulasi interaktif lelucon komunitas (*community easter egg*) yang menampilkan animasi flashing tanpa menyentuh atau menulis apa pun ke media penyimpanan modem. |
| **`[s]`** | **Ubah Password SuperAdmin** | Menghitung hash `SHA-256 UPPERCASE` dari kata sandi baru (default: `DBAI2K27`) dan memperbarui entri akun SuperAdmin Web GUI via `cfgcli`. |
| **`[i]`** | **Ekstraksi Kredensial Pabrik** | Menawarkan 2 mode ekstraksi: **[1] Live via SSH** (membaca blok `Factory_MIM`, bayangan `/etc/shadow`, dan mengeksekusi `test_decrypt_node`) atau **[2] Offline** (memindai berkas `.img` atau full dump disk mentah). |
| **`[r]`** | **Unroot & Cleanup Artefak** | Menghentikan skrip watchdog penjaga root, menghapus seluruh payload sementara dari `/tmp` dan `/configs/`, membersihkan jejak modifikasi, dan menawarkan opsi reboot bersih. |
| **`[k]`** | **Ubah Pengaturan Konfigurasi** | Menu konfigurasi interaktif untuk mengubah IP modem, port server HTTP/TCP, password, direktori backup, dan menyimpannya secara permanen ke `config_toolkit.json`. |
| **`[m]`** | **Trigger Nokia Cloud FOTA** | Menjalankan prosedur 5 langkah untuk mengaktifkan modul software management TR-069, me-restart service `swmgnt`, dan memicu sinyal D-Bus untuk pembaruan OTA resmi. |
| **`[0]`** | **Keluar** | Menghentikan seluruh background server secara aman dan menutup aplikasi CLI. |

### Struktur Direktori Hasil Backup (`image_backup/`)
Setelah proses Full Dump (`[6]`) atau Full Pipeline (`[a]`) selesai, folder keluaran akan terstruktur sebagai berikut:

```text
image_backup/
├── md5sums.txt                         # Daftar checksum MD5 resmi dari sisi modem
├── report.txt                          # Laporan hasil verifikasi MD5 lokal & audit hash
│
├── non-userarea/                       # Register hardware & area non-user
│   ├── mmcblk0boot0.bin                # Hardware boot partition 0
│   ├── mmcblk0boot1.bin                # Hardware boot partition 1
│   ├── ext_csd.bin                     # Raw binary 512-byte JEDEC Extended CSD
│   ├── CID.txt                         # Card Identification Register (sysfs)
│   ├── CSD.txt                         # Card Specific Data Register (sysfs)
│   └── info_eMMC.txt                   # Laporan detail vendor chip & JEDEC health
│
├── credentials/                        # Hasil ekstraksi kredensial pabrik
│   └── info_<SERIAL_NUMBER>.txt        # 24 entri Factory_MIM + decrypted keys + root pass
│
├── user_data_dir.tar.gz                # Cadangan direktori /data
├── rom_etc_dir.tar.gz                  # Cadangan direktori /rom/etc
├── boot.img                            # Partisi kernel boot
├── rootfs.img                          # Partisi sistem utama
├── Factory_MIM.img                     # Partisi metadata pabrik (128 KB)
├── user_data.img                       # Partisi data pengguna (dinamis / WAJAR-RW)
├── swr.img                             # Partisi software staging (dinamis / WAJAR-RW)
└── ... (seluruh 50 partisi eMMC user-area lainnya)
```

---
*Dibuat untuk komunitas riset perangkat keras dan interoperabilitas jaringan.*
