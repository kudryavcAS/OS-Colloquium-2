# To-Do List API

REST API для управления задачами с авторизацией и базой данных.

## Стек технологий
- Python 3.10+
- FastAPI
- SQLAlchemy (SQLite)
- JWT Auth

## Запуск

1. Установить зависимости:
    ```bash
   pip install -r requirements.txt
2. Запустить сервер:
    ```bash
   uvicorn app.main:app --reload
3. Открыть документацию:
http://127.0.0.1:8000/docs