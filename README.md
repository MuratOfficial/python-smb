<h1 align="center">🔐 python-smb</h1>
<p align="center">
  Это лёгкий веб-инструмент на основе **Flask**, позволяющий подключаться к SMB/CIFS-шаре и выполнять базовые операции с файлами.
</p>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/MuratOfficial/python-smb?style=flat-square" />
  <img src="https://img.shields.io/github/license/MuratOfficial/python-smb?style=flat-square" />
  <img src="https://img.shields.io/github/stars/MuratOfficial/python-smb?style=flat-square" />
</p>

---

## ⚙️ Возможности проекта

- 🚀 Веб-интерфейс для подключения к SMB/CIFS
- 🔍 Просмотр списка файлов и директорий
- 📤 Скачивание файлов через браузер
- 🔒 Работа со свежими версиями протокола SMB (с использованием `smbprotocol`)
- ⚙️ Конфигурация через `.env`

---

## 🧰 Технологии

- **Python** 3.8+
- **Flask** (≥2.0.0) — веб-сервер
- **Werkzeug** (≥2.0.0) — WSGI-утилиты Flask
- **smbprotocol** (≥1.10.0) — работа с SMBv2/v3
- **python-dotenv** (≥0.19.0) — загрузка переменных окружения из `.env`

---

## 🛠 Установка и запуск

1. Склонируйте репозиторий и перейдите в каталог:

   ```bash
     git clone https://github.com/MuratOfficial/python-smb.git
     cd python-smb
   ```
   
2. Создайте виртуальное окружение и установите зависимости:

  ```bash
    python -m venv venv
    source venv/bin/activate      # Linux/macOS
    venv\Scripts\activate         # Windows
    
    pip install -r requirements.txt
  ```

3. Создайте файл `.env` в корне проекта и задайте переменные:

   ```env
      SMB_SERVER=192.168.1.100
      SMB_SHARE=public
      SMB_USERNAME=user
      SMB_PASSWORD=pass123
      SMB_DOMAIN=WORKGROUP   # можно оставить пустым
      FLASK_ENV=development
   ```

4. Запустите приложение:

   ```bash
     flask run
   ```
   По умолчанию веб-сервис будет доступен по адресу: `http://127.0.0.1:5000`

## 🗂 Структура проекта

```
python-smb/
├── smb_app.py          # Основной Flask-приложение (роуты, интерфейс)
├── requirements.txt    # Зависимости
├── .env.example        # Пример конфигурационного файла
├── templates/          # Шаблоны Jinja2 для UI
│   └── index.html
└── static/             # Статические файлы (CSS)
```

📦 Разработано **MuratOfficial** — github.com/MuratOfficial


