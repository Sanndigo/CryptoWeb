# CryptoWeb

Универсальный онлайн шифратор/дешифратор, кодировщик и форматер. Упакован в единый контейнер: Astro (Frontend) раздается через FastAPI (Backend).

## Структура проекта
- `src/` - Исходники Astro JS + Tailwind CSS (v4)
- `src/api/` - Исходники API на Python (FastAPI)
- `Dockerfile` - Multi-stage сборка (собирает Astro и запускает вместе с FastAPI)
- `docker-compose.yml` - Файл оркестрации для развертывания

## Развертывание через Docker (Portainer / VPS)

Проект полностью готов к запуску в Docker в один контейнер.

1. Убедитесь, что у вас установлен Docker и Docker Compose (или загрузите проект в Portainer как Stack).
2. Запустите проект командой:
```bash
docker compose up -d --build
```
3. Приложение (и UI, и API) будет доступно локально по порту `25800` (http://127.0.0.1:25800).

*Для использования Nginx Proxy Manager направьте доменное имя на порт 25800 (IP 127.0.0.1).*
