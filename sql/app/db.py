import os
import psycopg2
from psycopg2 import pool
from dotenv import load_dotenv

load_dotenv()  # Загружаем переменные окружения из .env

connection_pool = pool.SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    host=os.getenv('DB_HOST', 'db'),
    database=os.getenv('DB_NAME', 'logsdb'),
    user=os.getenv('DB_USER', 'user'),
    password=os.getenv('DB_PASS', 'password'),
    port=os.getenv('DB_PORT', '5432')
)

def get_db_connection():
    """Получить соединение из пула"""
    return connection_pool.getconn()

def release_db_connection(conn):
    """Вернуть соединение в пул"""
    if conn:
        connection_pool.putconn(conn)

def close_all_connections():
    """Закрыть все соединения (для graceful shutdown)"""
    connection_pool.closeall()