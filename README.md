# Key Distribution Scenario (KDC) dan Komunikasi AES

Tugas Keamanan Informasi kelas B (EF234502), Teknik Informatika ITS.

## 1. Deskripsi

Program ini mengimplementasikan skenario distribusi key dengan **Key Distribution Center (KDC)** yang melibatkan tiga entitas, yaitu **KDC**, **Alice**, dan **Bob**, yang berjalan pada tiga IP address berbeda. KDC berbagi master key dengan setiap user. Setelah lima langkah distribusi key selesai, Alice dan Bob memegang session key `Ks` yang sama lalu berkomunikasi dua arah menggunakan **AES**.

AES dan protokol KDC diimplementasikan manual. Library yang dipakai hanya standard library Python untuk kebutuhan non-kriptografi: `socket`, `threading`, `json`, `argparse`, `string`, dan `secrets` (hanya sebagai sumber bilangan acak untuk nonce, IV, dan session key).

## 2. Arsitektur

```
                 +---------------------+
                 |         KDC         |
                 |   IP_KDC : 5000     |
                 |  Ka (alice), Kb (bob)|
                 +---------------------+
                    ^              |
       (1) IDA||IDB||N1            |  (2) E(Ka, [Ks||IDA||IDB||N1||E(Kb,[Ks||IDA])])
                    |              v
+---------------------+   (3) E(Kb, [Ks||IDA])    +---------------------+
|        ALICE        | ------------------------> |         BOB         |
|  IP_ALICE (client)  |   (4) E(Ks, N2)           |   IP_BOB : 6000     |
|      memegang Ka    | <------------------------ |      memegang Kb    |
|                     |   (5) E(Ks, f(N2))        |                     |
|                     | ------------------------> |                     |
|                     |                           |                     |
|                     | <=== chat AES dua arah ==> |                     |
+---------------------+     dengan session key Ks +---------------------+
```

| Entitas | Peran jaringan | Port | Key yang diketahui |
|---|---|---|---|
| KDC | Server | 5000 | Master key semua user (Ka, Kb) |
| Bob | Server | 6000 | Kb, lalu Ks setelah langkah 3 |
| Alice | Client (initiator) | acak | Ka, lalu Ks setelah langkah 2 |

Bob tidak pernah menghubungi KDC. Bob memperoleh `Ks` dari ticket yang diteruskan Alice dan hanya dapat dibuka dengan `Kb`.

## 3. Skenario Distribusi Key

| Langkah | Arah | Isi | Keterangan |
|---|---|---|---|
| 1 | Alice ke KDC | `IDA \|\| IDB \|\| N1` | Request session key, dikirim polos. N1 adalah nonce acak 32 bit |
| 2 | KDC ke Alice | `E(Ka, [Ks \|\| IDA \|\| IDB \|\| N1 \|\| E(Kb, [Ks \|\| IDA])])` | Hanya Alice yang bisa membuka. Alice memeriksa IDA, IDB, dan N1 agar respons bukan replay |
| 3 | Alice ke Bob | `E(Kb, [Ks \|\| IDA])` | Ticket. Alice tidak bisa membukanya, Bob membukanya dengan Kb |
| 4 | Bob ke Alice | `E(Ks, N2)` | Bob menantang Alice dengan nonce N2 |
| 5 | Alice ke Bob | `E(Ks, f(N2))` dengan `f(N2) = N2 + 1` | Bukti Alice memegang Ks yang sama dan pesan langkah 3 bukan replay |

Seluruh fungsi `E(...)` pada langkah 2 sampai 5 memakai AES manual dalam mode CBC. Setelah langkah 5, pesan chat dienkripsi dengan `Ks`.

## 4. Implementasi AES

File `aes.py` berisi AES sesuai FIPS-197 tanpa library:

| Komponen | Fungsi | Keterangan |
|---|---|---|
| Aritmetika GF(2^8) | `xtime`, `gf_multiply`, `gf_inverse` | Polinomial reduksi `x^8 + x^4 + x^3 + x + 1` (0x11B) |
| S-box | `S_BOX`, `INV_S_BOX` | Dibangkitkan dari invers perkalian GF(2^8) lalu transformasi affine, bukan tabel salinan |
| SubBytes | `sub_bytes` | Substitusi byte dengan S-box (confusion) |
| ShiftRows | `shift_rows` | Baris ke-r digeser r posisi (diffusion) |
| MixColumns | `mix_columns` | Perkalian matriks kolom di GF(2^8) (diffusion) |
| AddRoundKey | `add_round_key` | XOR state dengan round key |
| Key expansion | `expand_key` | Mendukung key 16, 24, 32 byte (10, 12, 14 round) |
| Padding | `pad`, `unpad` | PKCS#7, setiap byte padding berisi jumlah byte padding |
| Mode | `encrypt_ecb`, `encrypt_cbc`, dan pasangannya | ECB dan CBC (`Ci = E(K, Pi XOR Ci-1)`) |

File `cipher.py` menyiapkan format data sesuai ketentuan:

- **Key dan plaintext dalam ASCII.** Key harus 16, 24, atau 32 karakter ASCII yang dapat dicetak, sehingga panjang key menentukan AES-128, AES-192, atau AES-256. Plaintext non-ASCII ditolak.
- **Ciphertext dalam hexadecimal.** Hex hanya representasi byte agar mudah dibaca dan dikirim, bukan bagian dari enkripsi.
- **Mode CBC** memakai IV acak 16 byte untuk setiap pesan. IV dienkripsi dengan ECB dan ditempatkan sebagai blok pertama ciphertext, mengikuti saran KI 04 agar IV tidak dikirim polos.
- **Mode ECB** tersedia untuk pengujian, karena hasilnya dapat dicocokkan langsung dengan AES calculator online (AES ECB, PKCS#7/PKCS5, key teks, output hex).

## 5. Struktur Program

```
kdc-aes/
├── aes.py        AES manual (GF(2^8), S-box, round, key expansion, ECB, CBC, PKCS#7)
├── cipher.py     Validasi key ASCII, encrypt/decrypt teks ke hex, mode CBC/ECB
├── protocol.py   Format "||", nonce, f(N), session key, dekripsi pesan protokol
├── net.py        Socket TCP, framing JSON per baris, parsing alamat IP:PORT
├── console.py    Tampilan terminal dan input key
├── peer.py       Sesi chat aman dan perintah interaktif yang dipakai Alice dan Bob
├── kdc.py        KDC: registry master key dan penerbitan session key (langkah 1-2)
├── alice.py      Initiator: langkah 1, 2, 3, 5 lalu chat
├── bob.py        Responder: langkah 3, 4, 5 lalu chat
└── tests.py      Pengujian AES (FIPS-197, NIST SP 800-38A, OpenSSL) dan KDC
```

## 6. Cara Menjalankan

Butuh Python 3.8 atau lebih baru. Tidak ada dependensi eksternal.

Urutan menjalankan: **KDC, lalu Bob, lalu Alice**, karena KDC dan Bob adalah server.

### A. Tiga perangkat dalam satu jaringan (Wi-Fi atau hotspot)

Cek IP tiap perangkat dengan `ipconfig` (Windows) atau `ip a` (Linux). Contoh: KDC `192.168.1.20`, Bob `192.168.1.30`, Alice `192.168.1.10`.

```bash
# Perangkat KDC
python kdc.py
/set alice masterkeyalice01
/set bob masterkey-bob-02

# Perangkat Bob
python bob.py
# lalu masukkan master key: masterkey-bob-02

# Perangkat Alice
python alice.py --kdc 192.168.1.20:5000 --bob 192.168.1.30:6000
# lalu masukkan master key: masterkeyalice01, kemudian ketik /connect
```

Jika Windows Firewall menampilkan izin akses, pilih **Allow** untuk Python pada jaringan private.

Jika hanya ada dua laptop, perangkat ketiga dapat berupa ponsel (Termux), laptop teman, atau satu laptop yang memiliki dua IP (misalnya Wi-Fi dan Ethernet, atau KDC dijalankan di WSL yang memiliki IP sendiri). Yang penting KDC dapat dijangkau Alice, dan Bob dapat dijangkau Alice.

### B. Satu perangkat dengan tiga IP loopback (Windows dan Linux)

Seluruh alamat `127.0.0.x` adalah loopback sehingga dapat dipakai sebagai tiga IP berbeda.

```bash
python kdc.py --host 127.0.0.2
python bob.py --host 127.0.0.3
python alice.py --bind 127.0.0.1 --kdc 127.0.0.2:5000 --bob 127.0.0.3:6000
```

Opsi `--bind` membuat Alice mengirim dari IP tertentu, sehingga di Wireshark terlihat tiga IP yang berbeda.

## 7. Perintah Interaktif

Key dapat diubah kapan saja tanpa menjalankan ulang program.

**KDC**

| Perintah | Fungsi |
|---|---|
| `/set <id> <key>` | Mendaftarkan atau mengganti master key user |
| `/del <id>` | Menghapus master key user |
| `/list` | Menampilkan master key terdaftar |
| `/session auto` | Session key dibangkitkan acak 16 karakter (default) |
| `/session <key>` | Request berikutnya memakai session key tertentu (16, 24, atau 32 karakter) |
| `/exit` | Mematikan KDC |

**Alice dan Bob**

| Perintah | Fungsi |
|---|---|
| teks biasa | Dienkripsi dengan Ks lalu dikirim ke peer |
| `/connect` | Khusus Alice: menjalankan langkah 1 sampai 5. Dijalankan lagi untuk mendapatkan session key baru |
| `/mode cbc` atau `/mode ecb` | Mengganti mode AES untuk pesan yang dikirim berikutnya |
| `/key` | Mengganti master key sendiri |
| `/status` | Menampilkan ID, master key, session key, mode, dan peer |
| `/exit` | Menutup sesi dan keluar |

Mode dicantumkan di setiap pesan, sehingga penerima selalu mendekripsi dengan mode yang benar walaupun kedua pihak memakai mode berbeda.

## 8. Format Transmisi

TCP adalah byte stream, sehingga setiap pesan dikirim sebagai satu baris JSON yang diakhiri newline, dan penerima membaca per baris dengan `readline()`.

```
{"type": "step1", "data": "alice||bob||1614551246"}
{"type": "step2", "data": "48592baf7296374a..."}
{"type": "step3", "data": "be99c1a87a29a632..."}
{"type": "step4", "data": "28f02b0a060907d3..."}
{"type": "step5", "data": "0cbbe3b4ed86ccd8..."}
{"type": "chat", "mode": "CBC", "data": "fdf62bbedf11d85d..."}
{"type": "bye"}
{"type": "error", "data": "Ticket tidak dapat didekripsi, key tidak cocok"}
```

Hanya langkah 1 yang polos sesuai skenario. Master key dan session key tidak pernah dikirim dalam bentuk polos.

## 9. Wireshark

1. **Interface.** Untuk setup tiga perangkat pilih interface **Wi-Fi** atau **Ethernet** yang terhubung ke jaringan yang sama. Untuk setup loopback di Windows pilih **Adapter for loopback traffic capture** (Npcap), di Linux pilih **lo**.
2. **Filter capture atau display:**
   ```
   tcp.port == 5000 || tcp.port == 6000
   ```
   Filter tambahan:
   ```
   ip.addr == <IP_KDC> && tcp.port == 5000      lalu lintas Alice dan KDC (langkah 1-2)
   ip.addr == <IP_BOB> && tcp.port == 6000      lalu lintas Alice dan Bob (langkah 3-5 dan chat)
   tcp.len > 0                                  hanya paket yang membawa data
   ```
3. **Melihat isi.** Klik kanan paket, pilih **Follow > TCP Stream**. Langkah 1 terlihat polos, sedangkan langkah 2 sampai 5 dan chat hanya berupa hex.
4. **Pembuktian.** Gunakan **Edit > Find Packet**, pilih String dan Packet bytes, lalu cari master key, session key, atau plaintext chat. Hasilnya tidak ditemukan.

## 10. Skenario Uji Saat Demo

| No | Skenario | Langkah | Hasil yang diharapkan |
|---|---|---|---|
| 1 | Distribusi key normal | Alice `/connect` | Langkah 1 sampai 5 tampil di ketiga terminal, sesi terbentuk |
| 2 | Komunikasi dua arah | Alice dan Bob bergantian mengetik | Ciphertext hex terkirim, peer menampilkan plaintext |
| 3 | Cocokkan dengan AES online | KDC `/session abcdefghijklmnop`, Alice `/connect`, `/mode ecb`, kirim `halo` | Ciphertext `95eeb89f84facc9afe32ee7c685210c6`, sama dengan AES-128-ECB online |
| 4 | Ganti session key | Alice `/connect` lagi | Ks baru, ciphertext untuk pesan yang sama berubah |
| 5 | AES-192 atau AES-256 | KDC `/session <24 atau 32 karakter>`, Alice `/connect` | Label berubah menjadi AES-192 atau AES-256 |
| 6 | Master key Alice tidak cocok | KDC `/set alice <key lain>`, Alice `/connect` | Alice gagal di langkah 2: respons KDC tidak dapat didekripsi |
| 7 | Master key Bob tidak cocok | Bob `/key` dengan key lain, Alice `/connect` | Bob menolak di langkah 3: ticket tidak dapat didekripsi |
| 8 | User tidak terdaftar | KDC `/del bob`, Alice `/connect` | KDC menolak di langkah 1 |
| 9 | Input tidak valid | Key 15 karakter atau plaintext `héllo` | Ditolak dengan pesan yang jelas |
| 10 | CBC dan ECB | Kirim pesan yang sama dua kali di tiap mode | CBC berbeda setiap kali, ECB selalu sama |

## 11. Pengujian

```bash
python tests.py
```

Berisi 61 pengujian, antara lain:

- S-box hasil perhitungan GF(2^8) sesuai nilai standar (`S[00] = 63`, `S[53] = ED`).
- Key expansion dan enkripsi blok sesuai test vector FIPS-197 untuk AES-128, AES-192, dan AES-256.
- Mode CBC sesuai test vector NIST SP 800-38A.
- Hasil ECB dengan key dan plaintext ASCII sama dengan OpenSSL.
- Round trip seluruh ukuran key dan mode, penolakan input tidak valid, serta logika KDC (Alice tidak bisa membuka ticket, Bob bisa).

Selain itu, ketiga proses telah diuji berjalan pada `127.0.0.1`, `127.0.0.2`, dan `127.0.0.3` dengan lalu lintas loopback direkam. Paket berisi data hanya muncul pada pasangan Alice dan KDC serta Alice dan Bob, dan master key, session key, maupun plaintext chat tidak ditemukan pada data yang terekam.

## 12. Batasan

- Langkah 1 dikirim polos sesuai skenario, sehingga identitas Alice dan Bob terlihat oleh penyadap.
- Tidak ada pemeriksaan integritas (MAC) pada pesan chat karena di luar ketentuan tugas.
- Session key acak dibangkitkan dari huruf dan angka agar tetap ASCII, sehingga ruang key lebih kecil daripada 128 bit penuh.
- Master key disimpan di memori selama program berjalan dan diketik manual, sebagai simulasi master key yang sudah didistribusikan sebelumnya.
