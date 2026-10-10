# Perbaikan origin dan penyiapan QR 2FA

- Origin dibandingkan berdasarkan protokol, hostname, dan port efektif; slash akhir dan kapitalisasi hostname tidak menyebabkan penolakan. Domain atau protokol berbeda tetap ditolak. Nilai ENV dibersihkan dari whitespace dan tanda kutip luar.
- Isi APP_URL dengan alamat dashboard yang benar: `https://prediksi-all-web-production-e77b.up.railway.app`. Jangan memakai URL panel agent.
- Login terdiri dari dua tahap: ID/password, lalu 2FA. Pada penyiapan pertama, server menampilkan QR dan kunci manual setelah password benar. Admin belum dapat membuka dashboard sampai kode 2FA tervalidasi.
- Setelah aktivasi, QR tidak dapat diminta kembali. Session tahap password berlaku 5 menit dan tidak memberikan akses admin.
- Data dan kunci lama tetap digunakan. Tidak ada penghapusan volume atau database. Perbaikan volume pada versi sebelumnya tetap disertakan.
- Uji lokal mencakup QR setelah password, penolakan akses admin sebelum 2FA, aktivasi, penyembunyian QR setelah aktivasi, origin salah ditolak, serta normalisasi hostname/port. Deploy Railway pengguna belum diuji langsung.
