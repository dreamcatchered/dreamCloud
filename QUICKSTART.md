# Dream Cloud - Quickstart Guide

Зашифрованное облачное хранилище с Telegram backend.

## 🚀 Быстрый старт

### 1. Подготовка

```bash
# Установить зависимости
pip install -r requirements.txt

# Инициализировать Telegram сессию
python init_telegram.py
# Следуйте инструкциям, чтобы авторизоваться в Telegram
```

### 2. Инициализировать БД

```bash
python migrate_db.py
```

### 3. Запустить сервер

```bash
python run.py
```

Сервер запустится на `http://127.0.0.1:5033`

## 📝 Использование

1. **Перейти на главную**: http://127.0.0.1:5033
2. **Зарегистрироваться**: Кнопка "Зарегистрироваться" на главной
3. **Войти**: Используй логин и пароль
4. **Загрузить файлы**: Кнопка "Загрузить" в дашбоарде
5. **Создать папку**: Кнопка "Папка" в дашбоарде
6. **Скачать файл**: Наведи на файл и кликни иконку скачивания
7. **Поделиться файлом**: Кликни иконку шаринга и скопируй ссылку

## 🔐 Особенности

- ✅ **E2E Encryption**: Все файлы зашифрованы на устройстве перед загрузкой
- ✅ **Telegram Storage**: Файлы хранятся в Telegram, не на сервере
- ✅ **Zero Knowledge**: Сервер никогда не видит расшифрованные данные
- ✅ **Folder Organization**: Создавай папки для организации файлов
- ✅ **File Sharing**: Делись файлами с защитой паролем
- ✅ **Beautiful UI**: Современный и интуитивный интерфейс

## 🛠 Структура проекта

```
cloud/
├── app.py                 # Flask приложение и API endpoints
├── models.py              # Базы данных моделей
├── telegram_client.py     # Telegram синхронный клиент
├── encryption_utils.py    # AES-256-GCM шифрование
├── templates/
│   ├── index.html        # Главная страница
│   ├── login.html        # Форма входа
│   ├── register.html     # Форма регистрации
│   ├── dashboard.html    # Главный интерфейс
│   └── ...               # Другие страницы
├── static/               # CSS, JS, иконки
├── requirements.txt      # Python зависимости
└── .env                  # Конфигурация
```

## 📊 API Endpoints

### Аутентификация
- `POST /api/auth/register` - Регистрация
- `POST /api/auth/login` - Вход
- `POST /api/auth/logout` - Выход
- `GET /api/auth/me` - Текущий пользователь

### Файлы
- `GET /api/files` - Список файлов
- `POST /api/files/upload` - Загрузить файл
- `GET /api/files/<id>/download` - Скачать файл
- `DELETE /api/files/<id>` - Удалить файл

### Папки
- `GET /api/folders` - Список папок
- `POST /api/folders` - Создать папку
- `GET /api/folders/<id>` - Информация о папке
- `DELETE /api/folders/<id>` - Удалить папку

### Шаринг
- `GET /api/shares` - Мои ссылки
- `POST /api/shares` - Создать ссылку
- `DELETE /api/shares/<id>` - Удалить ссылку

## 🔑 Переменные окружения

Смотри `.env` файл для полного списка. Важные:

```env
TELEGRAM_API_ID=<твой API ID>
TELEGRAM_API_HASH=<твой API HASH>
TELEGRAM_CHAT_ID=<ID чата для хранилища>
DATABASE_URL=sqlite:///cloud.db
MAX_FILE_SIZE_MB=2000
```

## ⚡ Производительность

- **Шифрование**: ~100MB/сек на современном оборудовании
- **Загрузка в Telegram**: Зависит от скорости интернета
- **Одновременные загрузки**: До 10 одновременно
- **Размер БД**: ~1MB на 1000 файлов

## 🐛 Решение проблем

### Ошибка "Client not authorized"
```bash
# Удали сессию и переинициализируй
rm cloud_session.session
python init_telegram.py
```

### Ошибка подключения к БД
```bash
# Переинициализируй БД
rm cloud.db
python migrate_db.py
```

### Файлы не загружаются
- Проверь размер файла (макс 2000MB по умолчанию)
- Проверь место на диске
- Посмотри логи в консоли

## 📝 Лицензия

MIT License - Используй свободно!

## 🚀 Deploy

Для production используй Gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:5033 app:app
```

Или Docker:

```bash
docker build -t dream-cloud .
docker run -p 5033:5033 dream-cloud
```
