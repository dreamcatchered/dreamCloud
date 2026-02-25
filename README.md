# 🔐 Dream Cloud - Зашифрованное облачное хранилище

**Бесплатное, приватное облачное хранилище с сквозным шифрованием (E2E)**

![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Особенности

### 🔒 Безопасность
- **End-to-End Encryption** - AES-256-GCM шифрование на устройстве
- **Zero Knowledge** - Сервер никогда не видит расшифрованные данные
- **Open Source** - Проверь код на GitHub
- **No Tracking** - Полная приватность

### 💾 Хранилище
- **Telegram Backend** - Файлы хранятся в Telegram, не на сервере
- **Бесплатно** - Неограниченное хранилище (лимит Telegram)
- **Моментально** - Загруженные файлы доступны тут же
- **Надёжно** - Защищено инфраструктурой Telegram

### 📱 Пользовательское
- **Современный интерфейс** - Красивый и интуитивный дизайн
- **Папки** - Организуй файлы как хочешь
- **Поделиться** - Создавай ссылки для шаринга с паролем
- **Быстро** - Всё работает мгновенно

---

## 🚀 Быстрый старт

### 1. Подготовка

```bash
# Клонировать репо (или скачать)
cd cloud

# Установить зависимости
pip install -r requirements.txt

# Инициализировать Telegram (если первый раз)
python init_telegram.py
# Следуй инструкциям для авторизации
```

### 2. Запустить БД

```bash
python migrate_db.py
```

### 3. Запустить приложение

```bash
python run.py
```

Откройи: **http://127.0.0.1:5033**

---

## 📝 Использование

1. **Регистрация** - Кликни "Зарегистрироваться"
2. **Вход** - Введи логин и пароль
3. **Загрузка** - Кликни "Загрузить" и выбери файл
4. **Папки** - Создавай папки для организации
5. **Скачивание** - Кликни на файл и выбери "Скачать"
6. **Шаринг** - Кликни "Поделиться" и отправь ссылку

---

## 🏗 Архитектура

```
┌─────────────┐
│   Клиент    │
│  (браузер)  │
└──────┬──────┘
       │
       │ HTTPS
       ↓
┌──────────────────────────┐
│   Flask приложение       │
│  - Аутентификация        │
│  - Управление папками    │
│  - Генерация ссылок      │
└──────┬───────────────────┘
       │
       ├─→ SQLite БД (метаданные)
       │
       └─→ ┌──────────────────┐
           │   Телеграм        │
           │  - Хранилище      │
           │  - Зашифрованные  │
           │    файлы          │
           └──────────────────┘

Поток файла:
User → Encrypt (местно) → Telegram → Память (метаданные) → Удалить темп
```

---

## 🔐 Как работает шифрование

1. **Генерация ключа** - Уникальный ключ для каждого файла
2. **Локальное шифрование** - AES-256-GCM на устройстве
3. **Загрузка** - Шифрованный файл в Telegram
4. **Хранение ключа** - Ключ зашифрован мастер-ключом
5. **Расшифровка** - Локально при скачивании

---

## 📊 API Endpoints

### Аутентификация
```
POST   /api/auth/register              Регистрация
POST   /api/auth/login                 Вход
POST   /api/auth/logout                Выход
GET    /api/auth/me                    Профиль
POST   /api/auth/change-password       Изменить пароль
```

### Файлы
```
GET    /api/files                      Список файлов
POST   /api/files/upload               Загрузить
GET    /api/files/<id>                 Инфо о файле
GET    /api/files/<id>/download        Скачать
DELETE /api/files/<id>                 Удалить
```

### Папки
```
GET    /api/folders                    Список папок
POST   /api/folders                    Создать
GET    /api/folders/<id>               Инфо о папке
PUT    /api/folders/<id>               Обновить
DELETE /api/folders/<id>               Удалить
```

### Шаринг
```
GET    /api/shares                     Мои ссылки
POST   /api/shares                     Создать ссылку
DELETE /api/shares/<id>                Удалить ссылку
```

---

## 🛠 Технологии

| Компонент | Технология |
|-----------|-----------|
| Backend | Flask 3.0.0 |
| Database | SQLite + SQLAlchemy |
| Encryption | AES-256-GCM |
| Storage | Telegram API |
| Frontend | Vanilla JS + HTML/CSS |
| Icons | Lucide |
| Auth | Flask-Login + Bcrypt |

---

## 📦 Требования

- Python 3.9+
- pip
- ~100 MB место на диске
- Интернет соединение

---

## 🔑 Конфигурация

Смотри `.env` файл:

```env
# Flask
FLASK_SECRET_KEY=your-secret-key
HOST=127.0.0.1
PORT=5033

# Telegram
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash
TELEGRAM_CHAT_ID=your_chat_id

# Database
DATABASE_URL=sqlite:///cloud.db

# File limits
MAX_FILE_SIZE_MB=2000
```

---

## 📄 Лицензия

MIT License - Используй свободно!

```
Copyright (c) 2026 Dream Cloud

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🐛 Решение проблем

### Ошибка "Client not authorized"
```bash
rm cloud_session.session
python init_telegram.py
```

### Ошибка БД
```bash
rm cloud.db
python migrate_db.py
```

### Файлы не загружаются
- Проверь размер (макс 2000 МБ)
- Проверь место на диске
- Посмотри консоль на ошибки

---

## 🚀 Production Deploy

### Используя Gunicorn
```bash
gunicorn -w 4 -b 0.0.0.0:5033 app:app
```

### Используя Docker
```bash
docker build -t dream-cloud .
docker run -p 5033:5033 dream-cloud
```

### Используя Systemd
```bash
sudo cp dream-cloud.service /etc/systemd/system/
sudo systemctl enable dream-cloud
sudo systemctl start dream-cloud
```

---

## 📞 Контакты

- **Issues**: Сообщай об ошибках
- **Suggestions**: Предложи улучшения
- **Security**: Сообщай об уязвимостях приватно

---

## 📚 Документация

- [QUICKSTART.md](QUICKSTART.md) - Быстрый старт
- [PROJECT_STATUS.md](PROJECT_STATUS.md) - Статус проекта
- [CLEANUP_REPORT.md](CLEANUP_REPORT.md) - Отчёт об очистке

---

**Made with ❤️ for privacy**

Dream Cloud - Your encrypted cloud, your rules.
