import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def init_db():
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST', 'db'),
        database=os.getenv('DB_NAME', 'logsdb'),
        user=os.getenv('DB_USER', 'user'),
        password=os.getenv('DB_PASS', 'password'),
        port=os.getenv('DB_PORT', '5432')
    )
    
    try:
        with conn.cursor() as cur:
            # Читаем и выполняем SQL-скрипт
            with open('init.sql', 'r') as f:
                cur.execute(f.read())
            conn.commit()
            print("База данных успешно инициализирована")
    except Exception as e:
        print(f"Ошибка при инициализации базы данных: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    init_db() 