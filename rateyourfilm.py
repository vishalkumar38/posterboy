from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from mysql.connector import pooling
from dotenv import load_dotenv
import os

# Look for Railway's variables first, fallback to your local .env names if testing locally
SECRET_KEY = os.getenv("SECRET_KEY", "your-fallback-secret-key")
DB_HOST = os.getenv("MYSQLHOST") or os.getenv("DB_HOST")
DB_USER = os.getenv("MYSQLUSER") or os.getenv("DB_USER")
DB_PASS = os.getenv("MYSQLPASSWORD") or os.getenv("DB_PASS")
DB_NAME = os.getenv("MYSQL_DATABASE") or os.getenv("DB_NAME")
# Railway often uses custom ports, so we must grab the port variable!
DB_PORT = os.getenv("MYSQLPORT", 3306)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

mdb_pool = pooling.MySQLConnectionPool(
    pool_name="pool",
    pool_size=5,
    host=DB_HOST,
    user=DB_USER,
    passwd=DB_PASS,
    database=DB_NAME,
    port=int(DB_PORT) # Added the port here!
)

pwd_context = CryptContext(schemes=["bcrypt"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Movie(BaseModel):
    title: str
    year: int
    details: str

class Rating(BaseModel):
    movie_id: int
    rating: int


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="invalid token")
        return int(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="invalid token")

@app.post("/register")
def register(user: UserRegister):
    hashed = pwd_context.hash(user.password[:72])
    conn = mdb_pool.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES(%s, %s, %s)",
            (user.username, user.email, hashed)
        )
        conn.commit()
        return {"message": "user created"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.post("/login")
def login(user: UserLogin):
    conn = mdb_pool.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, password_hash FROM users WHERE email = %s",
            (user.email,)
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="invalid credentials")
        user_id, password_hash = row
        if not pwd_context.verify(user.password[:72], password_hash):
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = create_access_token({"sub": str(user_id)})
        return {"access_token": token, "token_type": "bearer"}
    finally:
        cursor.close()
        conn.close()

@app.get("/me")
def get_me(current_user_id: int = Depends(get_current_user)):
    return {"user_id": current_user_id}

@app.post("/movies")
def add_movie(movie: Movie, current_user_id: int = Depends(get_current_user)):
    conn = mdb_pool.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO movies (title, year, details) VALUES(%s, %s, %s)",
            (movie.title, movie.year, movie.details)
        )
        conn.commit()
        return {"message": "movie added"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.get("/movies")
def get_movies():
    conn = mdb_pool.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, title, year, details FROM movies")
        rows = cursor.fetchall()
        return [
            {"id": r[0], "title": r[1], "year": r[2], "details": r[3]}
            for r in rows
        ]
    finally:
        cursor.close()
        conn.close()

@app.get("/movies/search")
def search_movies(title: str):
    conn = mdb_pool.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, title, year, details FROM movies WHERE title LIKE %s",
            (f"%{title}%",)
        )
        rows = cursor.fetchall()
        return [
            {"id": r[0], "title": r[1], "year": r[2], "details": r[3]}
            for r in rows
        ]
    finally:
        cursor.close()
        conn.close()

@app.post("/rate")
def rate_movie(data: Rating, current_user_id: int = Depends(get_current_user)):
    if data.rating < 1 or data.rating > 10:
        raise HTTPException(status_code=400, detail="rating must be between 1 and 10")
    conn = mdb_pool.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id FROM rating WHERE user_id = %s AND movie_id = %s",
            (current_user_id, data.movie_id)
        )
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="you already rated this movie")
        cursor.execute(
            "INSERT INTO rating (user_id, movie_id, rating) VALUES (%s, %s, %s)",
            (current_user_id, data.movie_id, data.rating)
        )
        conn.commit()
        return {"message": "rating submitted"}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.get("/movies/{movie_id}/rating")
def see_rating(movie_id: int):
    conn = mdb_pool.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT m.title, m.year, m.details,
                   AVG(r.rating), COUNT(r.rating)
            FROM movies m
            LEFT JOIN rating r ON m.id = r.movie_id
            WHERE m.id = %s
            GROUP BY m.id
            """,
            (movie_id,)
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="movie not found")
        title, year, details, avg, count = row
        return {
            "title": title,
            "year": year,
            "details": details,
            "average_rating": round(float(avg), 1) if avg else None,
            "total_ratings": count
        }
    finally:
        cursor.close()
        conn.close()
















