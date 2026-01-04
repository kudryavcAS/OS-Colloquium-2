from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.main import app, get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


def test_register_user():
    response = client.post(
        "/register",
        json={"username": "testuser", "password": "testpassword"},
    )
    assert response.status_code == 201
    assert response.json() == {"msg": "User created successfully"}


def test_login_user():
    client.post("/register", json={"username": "loginuser", "password": "password123"})

    response = client.post(
        "/token",
        data={"username": "loginuser", "password": "password123"},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"


def test_create_task_flow():
    username = "taskmaster"
    password = "123"
    client.post("/register", json={"username": username, "password": password})

    login_res = client.post("/token", data={"username": username, "password": password})
    token = login_res.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    task_data = {"title": "Test Task", "description": "Works!", "status": "todo"}

    create_res = client.post("/tasks", json=task_data, headers=headers)
    assert create_res.status_code == 201
    assert create_res.json()["title"] == "Test Task"

    read_res = client.get("/tasks", headers=headers)
    assert read_res.status_code == 200
    tasks = read_res.json()
    assert len(tasks) == 1
    assert tasks[0]["title"] == "Test Task"