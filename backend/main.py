import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

BACKEND = Path(__file__).parent
SITE = BACKEND.parent
DB_PATH = BACKEND / "app.db"
SITE_FILES = {
    "index.html": "text/html",
    "style.css": "text/css",
    "app.js": "text/javascript",
    "data.js": "text/javascript",
    "sw.js": "text/javascript",
}
IMAGE_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
}

app = FastAPI(title="Пошагово")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class RegisterData(BaseModel):
    username: str
    password: str
    role: str = "student"


class AddTasks(BaseModel):
    title: str
    cat: int
    time: str
    steps: list[list]
    forkOf: str = ""


class AddComments(BaseModel):
    step: int
    text: str
    idea: bool = False


class AddVote(BaseModel):
    step: int
    value: int


class AddProgress(BaseModel):
    reached: int | None = None
    left: int | None = None
    ms: int = 0


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def query(sql, params=()):
    with closing(connect()) as conn:
        return [dict(row) for row in conn.execute(sql, params)]


def execute(sql, params=()):
    with closing(connect()) as conn, conn:
        return conn.execute(sql, params).lastrowid


def create_tables():
    execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL
        )
    """)
    execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            cat INTEGER NOT NULL,
            time TEXT NOT NULL,
            author TEXT NOT NULL,
            expert INTEGER NOT NULL,
            version INTEGER NOT NULL,
            forkOf TEXT NOT NULL,
            created INTEGER NOT NULL,
            starts INTEGER NOT NULL,
            useful INTEGER NOT NULL,
            steps TEXT NOT NULL
        )
    """)
    execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            step INTEGER NOT NULL,
            text TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            idea INTEGER NOT NULL,
            accepted INTEGER NOT NULL,
            date TEXT NOT NULL
        )
    """)
    execute("""
        CREATE TABLE IF NOT EXISTS votes (
            task_id INTEGER NOT NULL,
            step INTEGER NOT NULL,
            name TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (task_id, step, name)
        )
    """)
    execute("""
        CREATE TABLE IF NOT EXISTS step_stats (
            task_id INTEGER NOT NULL,
            step INTEGER NOT NULL,
            reach INTEGER NOT NULL,
            time_ms INTEGER NOT NULL,
            time_count INTEGER NOT NULL,
            PRIMARY KEY (task_id, step)
        )
    """)


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100000).hex()


def add_user(username, password, role):
    salt = secrets.token_hex(16)
    execute(
        "INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)",
        (username, salt, hash_password(password, salt), role),
    )


def new_session(user):
    token = secrets.token_hex(32)
    execute("INSERT INTO sessions (token, username) VALUES (?, ?)", (token, user["username"]))
    return {"name": user["username"], "role": user["role"], "token": token}


def current_user(authorization: str = Header("")):
    users = query(
        "SELECT users.* FROM sessions JOIN users ON users.username = sessions.username WHERE token = ?",
        (authorization,),
    )
    if not users:
        raise HTTPException(status_code=401, detail="Сначала войдите")
    return users[0]


def now_ms():
    return int(datetime.now().timestamp() * 1000)


def insert_task(title, cat, time, author, expert, version, fork_of, created, starts, useful, steps):
    return execute(
        """
        INSERT INTO tasks (title, cat, time, author, expert, version, forkOf, created, starts, useful, steps)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (title, cat, time, author, expert, version, fork_of, created, starts, useful, json.dumps(steps, ensure_ascii=False)),
    )


def insert_comment(task_id, step, text, name, role, idea, accepted, date):
    return execute(
        """
        INSERT INTO comments (task_id, step, text, name, role, idea, accepted, date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (task_id, step, text, name, role, idea, accepted, date),
    )


def seed():
    if query("SELECT id FROM users LIMIT 1"):
        return
    data = json.loads((BACKEND / "seed.json").read_text(encoding="utf-8"))
    for user in data["users"]:
        add_user(user["username"], data["password"], user["role"])
    for task in data["tasks"]:
        created = int(datetime.fromisoformat(task["created"]).timestamp() * 1000)
        task_id = insert_task(
            task["title"], task["cat"], task["time"], task["author"], task["expert"],
            task["version"], "", created, task["starts"], task["useful"], task["steps"],
        )
        for c in task["comments"]:
            insert_comment(task_id, c["step"], c["text"], c["name"], c["role"], c["idea"], c["accepted"], c["date"])


create_tables()
seed()


def find_task(task_id):
    tasks = query("SELECT * FROM tasks WHERE id = ?", (task_id,))
    if not tasks:
        raise HTTPException(status_code=404, detail="Инструкция не найдена")
    task = tasks[0]
    task["steps"] = json.loads(task["steps"])
    task["expert"] = bool(task["expert"])
    return task


def full_task(task):
    task_id = task["id"]
    count = len(task["steps"])

    task["comments"] = query("SELECT * FROM comments WHERE task_id = ? ORDER BY id", (task_id,))
    for comment in task["comments"]:
        comment["idea"] = bool(comment["idea"])
        comment["accepted"] = bool(comment["accepted"])

    task["votes"] = query("SELECT step, name, value FROM votes WHERE task_id = ?", (task_id,))

    task["stats"] = {"reach": [0] * count, "time": [0] * count, "count": [0] * count}
    for row in query("SELECT * FROM step_stats WHERE task_id = ?", (task_id,)):
        if row["step"] < count:
            task["stats"]["reach"][row["step"]] = row["reach"]
            task["stats"]["time"][row["step"]] = row["time_ms"]
            task["stats"]["count"][row["step"]] = row["time_count"]
    return task


def check_author(task, user):
    if task["author"] != user["username"]:
        raise HTTPException(status_code=403, detail="Это не ваша инструкция")


def is_text(value):
    return isinstance(value, str)


def clean_step(number, step):
    error = HTTPException(status_code=400, detail=f"Шаг {number}: неверный формат")
    if len(step) < 4 or len(step) > 7:
        raise error
    step = step + [0, None, ""][len(step) - 4:]
    title, text, items, warn, _, image, more = step
    if not (is_text(title) and is_text(text) and is_text(warn) and is_text(more)):
        raise error
    if not isinstance(items, list) or not all(is_text(item) for item in items):
        raise error
    if image is not None:
        if not isinstance(image, dict) or not is_text(image.get("src")) or not is_text(image.get("alt")):
            raise error
        if not image["alt"].strip():
            raise HTTPException(status_code=400, detail=f"Шаг {number}: опишите, что на картинке")
        if len(image["src"]) > 2_000_000:
            raise HTTPException(status_code=400, detail=f"Шаг {number}: картинка слишком большая")
        image = {"src": image["src"], "alt": image["alt"]}
    return [title, text, items, warn, 0, image, more]


def check_task(data):
    if not data.title.strip() or not data.steps:
        raise HTTPException(status_code=400, detail="Нужно название и хотя бы один шаг")
    if data.cat < 0 or data.cat > 4:
        raise HTTPException(status_code=400, detail="Такого раздела нет")
    return [clean_step(i + 1, step) for i, step in enumerate(data.steps)]


def check_step(task, step):
    if step < 0 or step >= len(task["steps"]):
        raise HTTPException(status_code=400, detail="Такого шага нет")


def add_stat(task_id, step, reach, time_ms, time_count):
    execute(
        """
        INSERT INTO step_stats (task_id, step, reach, time_ms, time_count) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (task_id, step) DO UPDATE SET
            reach = reach + excluded.reach,
            time_ms = time_ms + excluded.time_ms,
            time_count = time_count + excluded.time_count
        """,
        (task_id, step, reach, time_ms, time_count),
    )


@app.post("/register")
def register(data: RegisterData):
    username = data.username.strip()
    if not username or not data.password:
        raise HTTPException(status_code=400, detail="Введите имя и пароль")
    if data.role not in ["student", "expert"]:
        raise HTTPException(status_code=400, detail="Такой роли нет")
    if query("SELECT id FROM users WHERE username = ?", (username,)):
        raise HTTPException(status_code=409, detail="Такой пользователь уже есть. Попробуйте войти!")

    add_user(username, data.password, data.role)
    return new_session({"username": username, "role": data.role})


@app.post("/login")
def login(data: RegisterData):
    users = query("SELECT * FROM users WHERE username = ?", (data.username.strip(),))
    if users and hmac.compare_digest(hash_password(data.password, users[0]["salt"]), users[0]["password_hash"]):
        return new_session(users[0])
    raise HTTPException(status_code=401, detail="Неверное имя или пароль")


@app.post("/logout")
def logout(authorization: str = Header("")):
    execute("DELETE FROM sessions WHERE token = ?", (authorization,))
    return {"message": "Вы вышли"}


@app.get("/tasks")
def get_tasks():
    tasks = query("SELECT * FROM tasks ORDER BY id")
    for task in tasks:
        task["steps"] = json.loads(task["steps"])
        task["expert"] = bool(task["expert"])
        full_task(task)
    return tasks


@app.get("/tasks/{task_id}")
def get_task(task_id: int):
    return full_task(find_task(task_id))


@app.post("/add_tasks")
def add_tasks(data: AddTasks, user: dict = Depends(current_user)):
    steps = check_task(data)
    task_id = insert_task(
        data.title, data.cat, data.time, user["username"], user["role"] == "expert",
        1, data.forkOf, now_ms(), 0, 0, steps,
    )
    return full_task(find_task(task_id))


@app.put("/tasks/{task_id}")
def edit_task(task_id: int, data: AddTasks, user: dict = Depends(current_user)):
    task = find_task(task_id)
    check_author(task, user)
    steps = check_task(data)
    execute(
        "UPDATE tasks SET title = ?, cat = ?, time = ?, steps = ?, version = version + 1, created = ? WHERE id = ?",
        (data.title, data.cat, data.time, json.dumps(steps, ensure_ascii=False), now_ms(), task_id),
    )
    return full_task(find_task(task_id))


@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, user: dict = Depends(current_user)):
    task = find_task(task_id)
    check_author(task, user)
    execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    execute("DELETE FROM comments WHERE task_id = ?", (task_id,))
    execute("DELETE FROM votes WHERE task_id = ?", (task_id,))
    execute("DELETE FROM step_stats WHERE task_id = ?", (task_id,))
    return {"message": "Инструкция удалена"}


@app.post("/tasks/{task_id}/comments")
def add_comment(task_id: int, data: AddComments, user: dict = Depends(current_user)):
    task = find_task(task_id)
    check_step(task, data.step)
    if not data.text.strip():
        raise HTTPException(status_code=400, detail="Сначала напишите комментарий")
    comment_id = insert_comment(
        task_id, data.step, data.text.strip(), user["username"], user["role"],
        data.idea, False, datetime.now().strftime("%d.%m.%Y"),
    )
    return query("SELECT * FROM comments WHERE id = ?", (comment_id,))[0]


@app.put("/tasks/{task_id}/comments/{comment_id}")
def accept_comment(task_id: int, comment_id: int, user: dict = Depends(current_user)):
    check_author(find_task(task_id), user)
    execute("UPDATE comments SET accepted = 1 WHERE id = ? AND task_id = ?", (comment_id, task_id))
    return {"message": "Предложение принято"}


@app.delete("/tasks/{task_id}/comments/{comment_id}")
def delete_comment(task_id: int, comment_id: int, user: dict = Depends(current_user)):
    check_author(find_task(task_id), user)
    execute("DELETE FROM comments WHERE id = ? AND task_id = ?", (comment_id, task_id))
    return {"message": "Комментарий удалён"}


@app.post("/tasks/{task_id}/votes")
def add_vote(task_id: int, data: AddVote, user: dict = Depends(current_user)):
    task = find_task(task_id)
    check_step(task, data.step)
    if data.value not in [-1, 0, 1]:
        raise HTTPException(status_code=400, detail="Оценка может быть только 1, 0 или -1")
    execute(
        "DELETE FROM votes WHERE task_id = ? AND step = ? AND name = ?",
        (task_id, data.step, user["username"]),
    )
    if data.value != 0:
        execute(
            "INSERT INTO votes (task_id, step, name, value) VALUES (?, ?, ?, ?)",
            (task_id, data.step, user["username"], data.value),
        )
    return {"message": "Оценка сохранена"}


@app.post("/tasks/{task_id}/progress")
def add_progress(task_id: int, data: AddProgress):
    task = find_task(task_id)
    if data.reached is not None:
        check_step(task, data.reached)
        add_stat(task_id, data.reached, 1, 0, 0)
    if data.left is not None:
        check_step(task, data.left)
        add_stat(task_id, data.left, 0, min(max(data.ms, 0), 3600000), 1)
    return {"message": "Прогресс сохранён"}


@app.get("/")
def site():
    return site_file("index.html")


@app.get("/img/{name}")
def image_file(name: str):
    path = SITE / "img" / name
    if Path(name).name != name or path.suffix.lower() not in IMAGE_TYPES or not path.is_file():
        raise HTTPException(status_code=404, detail="Картинка не найдена")
    return FileResponse(path, media_type=IMAGE_TYPES[path.suffix.lower()])


@app.get("/{name}")
def site_file(name: str):
    if name not in SITE_FILES:
        raise HTTPException(status_code=404, detail="Страница не найдена")
    return FileResponse(SITE / name, media_type=SITE_FILES[name])
