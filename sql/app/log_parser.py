import pandas as pd
import psycopg2
import os
import time
from db import get_db_connection, release_db_connection
from dotenv import load_dotenv

load_dotenv()

def wait_for_db(max_retries=5, delay=3):
    """Ожидание готовности БД с проверкой соединения"""
    for i in range(max_retries):
        try:
            conn = get_db_connection()
            conn.cursor().execute("SELECT 1")
            release_db_connection(conn)
            return True
        except psycopg2.Error as e:
            print(f"Attempt {i+1}/{max_retries}: DB not ready - {e}")
            time.sleep(delay)
    raise ConnectionError("Could not connect to database")

def load_logs_to_db(csv_path='logs.csv'):
    wait_for_db()
    
    conn = None
    try:
        df = pd.read_csv(csv_path)
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Создание таблицы с улучшенной схемой
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(32) NOT NULL,
                url VARCHAR(256) NOT NULL,
                request TEXT NOT NULL,
                label INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_label (label)
            );
        """)
        
        # Пакетная вставка
        data = [tuple(x) for x in df[['ip', 'url', 'request', 'label']].to_records(index=False)]
        cur.executemany(
            "INSERT INTO logs (ip, url, request, label) VALUES (%s, %s, %s, %s)",
            data
        )
        conn.commit()
    finally:
        if conn:
            release_db_connection(conn)