import os
import random
import pandas as pd
from db import get_db_connection
from datetime import datetime, timedelta

def generate_test_data(n=1000):
    """Генерация тестовых данных: 80% норма, 20% SQL-инъекция"""
    patterns = {
        'sql_injection': [
            '" or pg_sleep ( __TIME__ ) --"',
            'create user name identified by pass123 temporary tablespace temp default tablespace users;',
            '" AND 1 = utl_inaddr.get_host_address ((SELECT DISTINCT (table_name) FROM (SELECT DISTINCT (table_name), ROWNUM AS LIMIT FROM sys.all_tables)) WHERE LIMIT = 5)) AND \'i\' = \'i"',
            '" select * from users where id = \'1\' or @@1 = 1 union select 1,version() -- 1\'"',
            '" UNION SELECT username, password FROM users--"',
            '" OR 1=1--"',
            '" OR \'x\'=\'x"',
            '" OR 1=1#"',
            '" OR 1=1/*"',
            '" OR \'1\'=\'1\' --"',
            '" OR \'1\'=\'1\' #"',
            '" OR \'1\'=\'1\'/*"',
            '" OR 1=1 --"',
            '" OR 1=1 #"',
            '" OR 1=1/*"'
        ],
        'normal': [
            "SELECT * FROM products",
            "INSERT INTO orders VALUES (...)",
            "UPDATE profile SET name='...'",
            "DELETE FROM cart WHERE id=1",
            "SELECT id, name FROM users",
            "INSERT INTO logs (message) VALUES ('test')",
            "UPDATE settings SET value='new'",
            "DELETE FROM temp WHERE created_at < NOW()",
            "SELECT COUNT(*) FROM users",
            "INSERT INTO comments (text) VALUES ('Hello')"
        ]
    }
    
    urls = ['/login', '/profile', '/cart', '/search', '/admin', '/api/users', '/products', '/orders']
    
    logs = []
    base_date = datetime.now() - timedelta(days=30)
    
    for i in range(n):
        random_days = random.randint(0, 30)
        random_hours = random.randint(0, 23)
        random_minutes = random.randint(0, 59)
        date = base_date + timedelta(days=random_days, hours=random_hours, minutes=random_minutes)
        # 20% инъекций, 80% норма
        if random.random() < 0.2:
            query = random.choice(patterns['sql_injection'])
            label = 1
        else:
            query = random.choice(patterns['normal'])
            label = 0
        logs.append({
            'ip': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'url': random.choice(urls),
            'request': query,
            'date': date,
            'label': label
        })
    return pd.DataFrame(logs)

def insert_test_data():
    """Вставка тестовых данных в базу"""
    try:
        # Генерируем данные
        df = generate_test_data(1000)
        
        # Подключаемся к БД
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Очищаем существующие данные
        cur.execute("TRUNCATE TABLE logs RESTART IDENTITY")
        
        # Вставляем новые данные
        for _, row in df.iterrows():
            cur.execute("""
                INSERT INTO logs (ip, url, request, date, label)
                VALUES (%s, %s, %s, %s, %s)
            """, (row['ip'], row['url'], row['request'], row['date'], row['label']))
        
        conn.commit()
        print("Тестовые данные успешно добавлены в базу")
        
    except Exception as e:
        print(f"Ошибка при добавлении тестовых данных: {e}")
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    insert_test_data() 