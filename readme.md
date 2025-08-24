# ZIP / FILE Security Analyzer - Yilzi Dev

> Tools ini dibuat oleh **Yilzi Dev** untuk menganalisis file atau arsip (ZIP/TAR) secara menyeluruh.
> Menampilkan analisis konten, hash, deteksi bahasa pemrograman, risiko keamanan, entropi, dan pola mencurigakan.
> Hasilnya bisa ditampilkan di terminal dengan tabel dan juga disimpan ke file teks, JSON, atau CSV.

---

## 📁 Fitur Utama

* Mendukung file tunggal: `.txt`, `.md`, `.py`, `.js`, `.sh`, `.ps1`, `.docx`
* Mendukung arsip: `.zip`, `.tar`, `.tar.gz`, `.tgz`
* Analisis metadata:

  * Ukuran asli & terkompresi
  * Rasio kompresi
  * Hash (MD5, SHA1, SHA256)
  * Apakah file binary atau text
  * Tipe / bahasa pemrograman
* Analisis konten:

  * Pencarian pola berbahaya (`curl`, `wget`, `powershell`, `eval`, `exec`, hex obfuscated, base64 panjang)
  * Deteksi entropi (untuk obfuscation/enkripsi)
  * Peringkat risiko (Rendah / Sedang / Tinggi, skor 0-100)
* Output:

  * Tabel ringkasan di terminal
  * Laporan teks rinci (`.txt`)
  * Opsional export JSON (`.json`) dan CSV (`.csv`)
* Animasi progres & spinner di terminal

---

## ⚙️ Instalasi

1. Pastikan sudah terinstall **Python 3.7+**
2. Clone atau download repo ini:

   ```bash
   git clone <REPO_URL>
   cd <folder_project>
   ```
3. Install dependensi Python:

   ```bash
   pip install tabulate python-docx
   ```

---

## 🛠 Struktur Project

```
project/
│
├─ zip_checker.py           # Script utama
├─ tester.zip               # Contoh arsip ZIP untuk tes
├─ contoh.txt               # Contoh file teks untuk tes
```

---

## 🚀 Cara Penggunaan

### 1. Jalankan analisis file tunggal / arsip

```bash
python zip_checker.py <path_file>
```

Contoh:

```bash
python zip_checker.py tester.zip
python zip_checker.py contoh.txt
```

> Jika output file tidak ditentukan, secara otomatis akan dibuat:
> `data_file_yilzidev_<timestamp>.txt`

### 2. Menentukan nama file output

Gunakan opsi `-o` atau `--output`:

```bash
python zip_checker.py tester.zip -o hasil.txt
```

Hasilnya akan disimpan di `hasil.txt`.

### 3. Export ke JSON atau CSV

Tambahkan opsi `--json` atau `--csv`:

```bash
python zip_checker.py tester.zip -o hasil.txt --json --csv
```

### 4. Menonaktifkan animasi terminal

Gunakan opsi `--no-anim` jika ingin hasil langsung muncul tanpa spinner:

```bash
python zip_checker.py tester.zip --no-anim
```

---

## 💡 Tips & Catatan

* Pastikan file ZIP tidak corrupt agar semua file di dalamnya bisa dianalisis.
* File teks yang dibaca mendukung `.txt`, `.docx`, `.py`, `.js`, dan lainnya.
* Analisis risiko bersifat indikatif, tetap lakukan review manual jika menemukan potensi bahaya.
* Semua hasil disimpan dengan nama file standar `data_file_yilzidev_<timestamp>.txt` jika output tidak ditentukan.

---

## 📞 Kontak

Jika ada pertanyaan atau ingin request fitur, hubungi **Yilzi Dev**: @Yilziii (Telegram)

---

*Happy Securing!* 🔐
