# ... (импорты)
from sklearn.metrics import classification_report
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import re
from sklearn.metrics.pairwise import cosine_similarity
import os

def generate_logs(n=1000):
    """Генерация более реалистичных логов"""
    patterns = {
        'sql_injection': [
            '" or pg_sleep ( __TIME__ ) --"',
            'create user name identified by pass123 temporary tablespace temp default tablespace users;',
            '" AND 1 = utl_inaddr.get_host_address ((SELECT DISTINCT (table_name) FROM (SELECT DISTINCT (table_name), ROWNUM AS LIMIT FROM sys.all_tables)) WHERE LIMIT = 5)) AND \'i\' = \'i"',
            '" select * from users where id = \'1\' or @@1 = 1 union select 1,version() -- 1\'"',
            '" UNION SELECT username, password FROM users--"'
        ],
        'normal': [
            "SELECT * FROM products",
            "INSERT INTO orders VALUES (...)",
            "UPDATE profile SET name='...'",
            "DELETE FROM cart WHERE id=1"
        ]
    }
    
    logs = []
    for _ in range(n):
        if random.random() < 0.5:  # 50% инъекций
            query = random.choice(patterns['sql_injection'])
            label = 1
        else:
            query = random.choice(patterns['normal'])
            label = 0
            
        logs.append({
            'ip': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'url': random.choice(['/login', '/profile', '/cart', '/search']),
            'request': query,
            'label': label
        })
    return pd.DataFrame(logs)

def preprocess_query(query):
    """
    Предобработка SQL-запроса перед векторизацией.
    
    Args:
        query (str): Исходный SQL-запрос
        
    Returns:
        str: Предобработанный запрос
    """
    # Приводим к нижнему регистру
    query = query.lower()
    
    # Удаляем лишние пробелы
    query = ' '.join(query.split())
    
    # Удаляем комментарии
    query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
    query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
    
    return query

def load_dataset():
    """Загрузка датасета"""
    try:
        df = pd.read_csv('Modified_SQL_Dataset.csv')
        return df
    except Exception as e:
        print(f"Ошибка при загрузке датасета: {e}")
        return None

def prepare_vectorizer():
    """Подготовка векторизатора"""
    try:
        df = load_dataset()
        if df is None:
            return None
            
        vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            analyzer='char',
            min_df=2
        )
        
        # Предобработка запросов из датасета
        processed_queries = df['Query'].apply(preprocess_query)
        
        # Обучаем векторизатор на датасете
        vectorizer.fit(processed_queries)
        
        # Сохраняем векторизатор
        joblib.dump(vectorizer, 'vectorizer.pkl')
        
        # Сохраняем векторизованные запросы
        X = vectorizer.transform(processed_queries)
        joblib.dump(X, 'dataset_vectors.pkl')
        
        return vectorizer, X, df['Label'].values
        
    except Exception as e:
        print(f"Ошибка при подготовке векторизатора: {e}")
        return None

def predict_query(query):
    """
    Предсказывает, является ли запрос SQL-инъекцией, и возвращает похожие запросы из датасета.
    
    Args:
        query (str): SQL-запрос для проверки
        
    Returns:
        tuple: (is_injection, confidence, similar_queries, class_label) или (None, error_message)
    """
    try:
        # Проверяем явные признаки SQL-инъекции
        explicit_patterns = [
            'union all select',
            'union select',
            'or 1=1',
            'or \'1\'=\'1\'',
            'or "1"="1"',
            '--',
            '/*',
            ';--',
            ';/*',
            'exec(',
            'eval(',
            'load_file',
            'into outfile',
            'into dumpfile',
            'benchmark(',
            'sleep(',
            'waitfor delay',
            'pg_sleep',
            'dbms_pipe.receive_message'
        ]
        
        # Проверяем наличие явных признаков инъекции
        query_lower = query.lower()
        for pattern in explicit_patterns:
            if pattern in query_lower:
                print(f"Found explicit injection pattern: {pattern}")
                return True, 100.0, [], 'SQL-инъекция'
        # Проверка на 'order by <число>' с комментарием или без
        if re.search(r"order\s+by\s+\d+\s*(#|--)?", query_lower):
            print("Found explicit injection pattern: order by <number>")
            return True, 100.0, [], 'SQL-инъекция'

        # Если явных признаков нет, используем модель
        # Проверяем существование файлов
        if not os.path.exists('model.pkl'):
            return None, "Файл model.pkl не найден. Переобучите модель."
        if not os.path.exists('vectorizer.pkl'):
            return None, "Файл vectorizer.pkl не найден. Переобучите модель."
        if not os.path.exists('dataset_vectors.pkl'):
            return None, "Файл dataset_vectors.pkl не найден. Переобучите модель."
        if not os.path.exists('dataset_labels.pkl'):
            return None, "Файл dataset_labels.pkl не найден. Переобучите модель."
        if not os.path.exists('dataset_queries.pkl'):
            return None, "Файл dataset_queries.pkl не найден. Переобучите модель."
            
        # Загружаем модель и векторайзер
        model = joblib.load('model.pkl')
        vectorizer = joblib.load('vectorizer.pkl')
        dataset_vectors = joblib.load('dataset_vectors.pkl')
        dataset_labels = joblib.load('dataset_labels.pkl')
        dataset_queries = joblib.load('dataset_queries.pkl')
        
        # Предобработка запроса
        processed_query = preprocess_query(query)
        
        # Векторизация запроса
        query_vector = vectorizer.transform([processed_query])
        
        # Получаем вероятности классов и предсказание
        proba = model.predict_proba(query_vector)[0]
        inj_index = list(model.classes_).index(1) if 1 in model.classes_ else 0
        confidence = float(proba[inj_index]) * 100
        if confidence > 100:
            confidence = 100.0
        elif confidence < 0:
            confidence = 0.0
        prediction = model.predict(query_vector)[0]
        
        # Гибридная логика: и предсказание, и порог вероятности
        is_injection = bool(prediction) and confidence >= 50
        print(f"Prediction: {prediction}, Confidence: {confidence}%, Is Injection: {is_injection}")
        class_label = 'SQL-инъекция' if is_injection else 'Норма'
        
        # Находим похожие запросы из датасета
        similarities = cosine_similarity(query_vector, dataset_vectors)[0]
        top_indices = similarities.argsort()[-5:][::-1]  # Топ-5 похожих запросов
        similar_queries = []
        for idx in top_indices:
            similar_queries.append({
                'query': dataset_queries[idx],
                'is_injection': bool(dataset_labels[idx]),
                'similarity': float(similarities[idx])
            })
        return is_injection, confidence, similar_queries, class_label
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None, f"Внутренняя ошибка: {str(e)}"

def initialize():
    """
    Инициализация модели и подготовка данных для предсказаний.
    """
    try:
        print("Loading dataset...")
        # Загружаем датасет
        df = pd.read_csv('Modified_SQL_Dataset.csv')
        print(f"Dataset loaded with {len(df)} rows")
        # Переименовываем колонки для удобства
        df = df.rename(columns={'Query': 'query', 'Label': 'label'})
        print("Preparing vectorizer...")
        # Подготавливаем векторайзер
        vectorizer = TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=10000,
            stop_words='english'
        )
        print("Vectorizing dataset...")
        # Векторизуем датасет
        X = vectorizer.fit_transform(df['query'])
        y = df['label']
        print(f"Dataset vectorized with shape: {X.shape}")
        print("Saving vectorizer and dataset vectors...")
        # Сохраняем векторайзер и векторы датасета
        joblib.dump(vectorizer, 'vectorizer.pkl')
        joblib.dump(X, 'dataset_vectors.pkl')
        joblib.dump(y.values, 'dataset_labels.pkl')
        joblib.dump(df['query'].values, 'dataset_queries.pkl')
        print("Training model...")
        # Обучаем модель на X, y (используем тот же X, что и для векторизатора)
        model = train_model(X, y)
        print("Model trained successfully")
        # Выводим classification_report для диагностики
        print(classification_report(y, model.predict(X)))
        print("Saving model...")
        joblib.dump(model, 'model.pkl')
        print("Model initialized successfully")
        return True
    except Exception as e:
        print(f"Error initializing model: {str(e)}")
        return False

def train_model(X, y):
    """
    Обучение модели на векторизованных данных.
    Args:
        X: векторизованные запросы
        y: метки
    Returns:
        sklearn.base.BaseEstimator: Обученная модель
    """
    from sklearn.ensemble import RandomForestClassifier
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X, y)
    return model

if __name__ == '__main__':
    initialize()