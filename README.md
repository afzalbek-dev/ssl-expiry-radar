# 🔒 SSL Expiry Radar — TLS Certificate Expiry Scanner

Veb-saytlar va API xizmatlarining SSL/TLS sertifikatlarini avtomatlashtirilgan tarzda tekshiruvchi, tugash muddatini oldindan hisoblovchi va ogohlantiruvchi skaner.

---

## 🌟 Imkoniyatlari

- **SNI va TLS Validatsiyasi:** Standart xavfsiz TLS rozetkasi orqali server sertifikatini o'qiydi.
- **SAN (Subject Alternative Name) tekshiruvi:** Sertifikat qamrab olgan barcha qo'shimcha domenlarni ko'rsatadi.
- **Kategoriyali Ogohlantirish:**
  - 🟢 `HEALTHY` (30 kundan ortiq)
  - 🟡 `WARNING` (8 - 30 kun)
  - 🔴 `CRITICAL` (7 kun yoki kamroq)
  - ☠️ `EXPIRED` (Tugagan)
- **Ko'p domenli skanerlash:** Faylga yozilgan domenlar ro'yxatini ketma-ket avtomat tekshiradi.

---

## 🚀 Ishga Tushirish

### 1. Bitta Domenni Tekshirish
```bash
python3 -m ssl_radar.cli check github.com
```

### 2. Ro'yxatdagi Domenlarni Skanlash
```bash
python3 -m ssl_radar.cli scan-list domains.txt
```

---

## 🧪 Testlash

```bash
pytest tests/ -v
```

---

## 📄 Litsenziya

MIT License. Muallif: [Afzalbek](https://github.com/afzalbek-dev).
