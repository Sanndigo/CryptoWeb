# CryptoWeb (WebCrypt)

Универсальный онлайн шифратор/дешифратор, кодировщик и форматер. Упакован в единый контейнер: Astro (Frontend) раздается через FastAPI (Backend).
(Веб-морда для Python Cryptography Framework).

## Кодирование:
  Base64 / Base32
  Base85 / URL
  Hexadecimal
  Binary & Morse
## Шифрование:
  AES-256 (GCM)
  ChaCha20-Poly1305
  Fernet
  3DES / XOR
## Хеширование: 
  SHA-256 / SHA-512
  SHA3-256 / BLAKE2b
  bcrypt (Adaptive)
  MD5 (Legacy)
## Инструменты:
  Burnable Links
  Password Gen
  JSON Formatter
  JWT Decoder

## Структура проекта
- `src/` - Исходники Astro JS + Tailwind CSS (v4)
- `src/api/` - Исходники API на Python (FastAPI)
- `Dockerfile` - Multi-stage сборка (собирает Astro и запускает вместе с FastAPI)
- `docker-compose.yml` - Файл оркестрации для развертывания

## Развертывание через Docker

Проект полностью готов к запуску в Docker.

1. Убедитесь, что у вас установлен Docker и Docker Compose.
2. Запустите проект командой:
```bash
docker compose up -d --build
```
3. Приложение (и UI, и API) будет доступно локально по порту `8100` (http://127.0.0.1:8100).

*Для использования Nginx Proxy Manager направьте доменное имя на порт 8100 (IP 127.0.0.1).*

*Веб-дизайн создан Google Stitch
*В разработке применялся ИИ
