# CryptoWeb

Универсальный онлайн шифратор/дешифратор, кодировщик и форматер, написанный на Astro JS (Frontend) и FastAPI (Backend).

## Структура проекта
- `frontend/` - UI на Astro JS + Tailwind CSS (v4)
- `backend/` - API на Python (FastAPI)
- `docker-compose.yaml` - Файл оркестрации для развертывания

## Запуск для разработки (Локально)

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Для Linux/Mac
pip install -r requirements.txt
uvicorn main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

## Развертывание через Docker (Portainer / VPS)

Проект полностью готов к запуску в Docker.

1. Склонируйте репозиторий на ваш сервер.
2. Убедитесь, что у вас установлен Docker и Docker Compose (или загрузите проект в Portainer как Stack).
3. Запустите проект командой:
```bash
docker compose up -d --build
```
4. Приложение будет доступно по порту `4321` (http://your-server-ip:4321), а API по порту `8000`.

*Для использования nginx в качестве reverse proxy, проксируйте домен на порт 4321 для фронтенда и на 8000 для `/process` API.*
