import os
import psycopg2
from dotenv import load_dotenv
from generate_test_data import generate_test_data

load_dotenv()

def init_db_with_data():
    """Инициализация базы данных и заполнение тестовыми данными"""
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
            
            # Генерируем и вставляем тестовые данные
            df = generate_test_data(1000)
            
            # Очищаем существующие данные
            cur.execute("TRUNCATE TABLE logs RESTART IDENTITY")
            
            # Вставляем новые данные
            for _, row in df.iterrows():
                cur.execute("""
                    INSERT INTO logs (ip, url, request, date, label)
                    VALUES (%s, %s, %s, %s, %s)
                """, (row['ip'], row['url'], row['request'], row['date'], row['label']))
            
            conn.commit()
            print("База данных успешно инициализирована и заполнена тестовыми данными")
    except Exception as e:
        print(f"Ошибка при инициализации базы данных: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    init_db_with_data() 