import csv
import os
import psycopg2
import joblib
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from zabbix_integration import send_to_zabbix, get_injection_count, wait_for_zabbix
from pyzabbix import ZabbixAPI
import json
from psycopg2 import sql
from model import predict_query  # Добавлен импорт predict_query

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'supersecretkey')
app.config['SESSION_COOKIE_SECURE'] = True  # Для HTTPS

# Add escapejs filter
@app.template_filter('escapejs')
def escapejs_filter(s):
    if s is None:
        return ''
    return json.dumps(str(s))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple user store
USERS = {'admin': {'password': generate_password_hash('admin'), 'role': 'admin'}}

class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user = USERS.get(user_id)
    if user:
        return User(user_id, user.get('role', 'user'))
    return None

def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        database=os.environ.get('DB_NAME', 'logsdb'),
        user=os.environ.get('DB_USER', 'user'),
        password=os.environ.get('DB_PASS', 'password')
    )

# Загрузка модели с обработкой ошибок
try:
    model = joblib.load('model.pkl')
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

def extract_features_from_request(req):
    return [[len(req), int('or' in req.lower()), int('=' in req)]]

limiter = Limiter(get_remote_address, app=app)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = USERS.get(username)
        if user and check_password_hash(user['password'], password):
            login_user(User(username, user.get('role', 'user')))
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Получаем фильтры из запроса
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    ip = request.args.get('ip', '').strip()
    url = request.args.get('url', '').strip()
    ip_range = request.args.get('ip_range', '').strip()
    label = request.args.get('label', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    min_length = request.args.get('min_length', '')
    max_length = request.args.get('max_length', '')
    # По умолчанию показываем данные из датасета
    source = request.args.get('source', 'dataset')
    max_pages = int(request.args.get('max_pages', 20))

    logs = []
    total = 0
    if source == 'dataset':
        # Загружаем данные из датасета
        try:
            df = pd.read_csv('Modified_SQL_Dataset.csv')
            df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Перемешиваем строки
            total = len(df)
            per_page = int(per_page)
            if total > max_pages * per_page:
                df = df.iloc[:max_pages * per_page]
                total = max_pages * per_page
            # Пагинация
            df = df.iloc[(page-1)*per_page:page*per_page]
            for idx, row in df.iterrows():
                logs.append({
                    'date': '',
                    'url': '',
                    'request': row['Query'],
                    'label': int(row['Label']),
                    'id': idx
                })
        except Exception as e:
            print(f"Ошибка при загрузке датасета: {e}")
            flash('Ошибка при загрузке датасета', 'error')
    else:
        # Получаем данные из таблицы logs
        filters = []
        params = []
        if ip:
            filters.append('ip = %s')
            params.append(ip)
        if url:
            filters.append('url = %s')
            params.append(url)
        if ip_range:
            try:
                start_ip, end_ip = ip_range.split('-')
                filters.append('ip >= %s AND ip <= %s')
                params.extend([start_ip.strip(), end_ip.strip()])
            except Exception:
                pass
        if label in ('0', '1'):
            filters.append('label = %s')
            params.append(int(label))
        if date_from:
            filters.append('date >= %s')
            params.append(date_from)
        if date_to:
            filters.append('date <= %s')
            params.append(date_to)
        if min_length:
            filters.append('char_length(request) >= %s')
            params.append(int(min_length))
        if max_length:
            filters.append('char_length(request) <= %s')
            params.append(int(max_length))
        where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(f'SELECT COUNT(*) FROM logs {where}', params)
            total = cur.fetchone()[0]
            cur.execute(f'SELECT * FROM logs {where} ORDER BY date DESC LIMIT %s OFFSET %s', params + [per_page, (page-1)*per_page])
            logs_db = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            logs = [dict(zip(columns, row)) for row in logs_db]
            cur.close()
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")
            logs = []
            total = 0
            flash('Ошибка при загрузке логов', 'error')
        for log in logs:
            if log.get('date'):
                log['date'] = log['date'].strftime('%Y-%m-%d %H:%M:%S')
    injection_count = "N/A"
    if wait_for_zabbix():
        try:
            zabbix_server = os.environ.get('ZABBIX_SERVER_HOST', 'http://zabbix-web:8080')
            if not zabbix_server.startswith(('http://', 'https://')):
                zabbix_server = 'http://' + zabbix_server
            zapi = ZabbixAPI(zabbix_server)
            zapi.login(os.environ.get('ZABBIX_USER', 'Admin'), os.environ.get('ZABBIX_PASSWORD', 'zabbix'))
            item_name = "injection.count"
            item_filter = {
                "search": {"name": item_name},
                "output": ["itemid", "name", "lastvalue"],
                "sortfield": "name",
            }
            items = zapi.item.get(item_filter)
            if items:
                injection_count = items[0]["lastvalue"]
        except Exception as e:
            print(f"Error getting data from Zabbix: {e}")
    total_pages = (total // per_page) + (1 if total % per_page else 0)
    # Загружаем первые 10 запросов из датасета для выпадающего списка
    try:
        df_dataset = pd.read_csv('Modified_SQL_Dataset.csv')
        dataset_queries = df_dataset['Query'].head(10).tolist()
    except Exception as e:
        print(f"Ошибка при загрузке датасета: {e}")
        dataset_queries = []
    return render_template('index.html', logs=logs, injection_count=injection_count, page=page, total_pages=total_pages, per_page=per_page, ip=ip, url=url, ip_range=ip_range, label=label, date_from=date_from, date_to=date_to, min_length=min_length, max_length=max_length, dataset_queries=dataset_queries, source=source)

@app.route('/predict', methods=['POST'])
def predict():
    if not request.form.get('query'):
        flash('Пожалуйста, введите SQL-запрос для проверки', 'error')
        return redirect(url_for('index'))
    query = request.form.get('query')
    try:
        # Получаем предсказание и похожие запросы
        result = predict_query(query)
        if result is None or (isinstance(result, tuple) and result[0] is None):
            error_msg = result[1] if isinstance(result, tuple) and len(result) > 1 else 'Ошибка при анализе запроса. Попробуйте еще раз.'
            flash(error_msg, 'error')
            return redirect(url_for('index'))
        is_injection, confidence, similar_queries, class_label = result
        print(f"Prediction result: is_injection={is_injection}, confidence={confidence}%, class_label={class_label}")
        # Анализируем запрос на наличие подозрительных паттернов
        suspicious_patterns = []
        if "'" in query or '"' in query:
            suspicious_patterns.append("Обнаружены кавычки в запросе")
        if 'UNION' in query.upper():
            suspicious_patterns.append("Обнаружено использование UNION")
        if '--' in query or '/*' in query:
            suspicious_patterns.append("Обнаружены SQL-комментарии")
        # Определяем уровень риска
        if is_injection:
            risk_level = 'HIGH' if confidence > 80 else 'MEDIUM'
        else:
            risk_level = 'LOW'
        # Формируем рекомендации
        recommendations = []
        if is_injection:
            recommendations.append("Рекомендуется использовать параметризованные запросы")
            recommendations.append("Проверьте входные данные на наличие SQL-инъекций")
            recommendations.append("Используйте подготовленные выражения (prepared statements)")
        else:
            recommendations.append("Запрос выглядит безопасным")
            recommendations.append("Рекомендуется регулярно проверять запросы на наличие SQL-инъекций")
        # Сохраняем результат в базу данных
        save_prediction(query, is_injection, confidence, risk_level)
        # Отправляем данные в Zabbix
        send_to_zabbix(int(is_injection))
        return render_template('predict_result.html',
                             query=query,
                             analysis={
                                 'is_sql_injection': is_injection,
                                 'confidence': confidence,
                                 'risk_level': risk_level,
                                 'similar_queries': similar_queries,
                                 'class_label': class_label
                             },
                             suspicious_patterns=suspicious_patterns,
                             recommendations=recommendations)
    except Exception as e:
        app.logger.error(f"Ошибка при анализе запроса: {str(e)}")
        flash(f'Внутренняя ошибка: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/search', methods=['GET'])
@login_required
def search():
    page = int(request.args.get('page', 1))
    per_page = 50
    query = request.args.get('q', '')
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM logs WHERE request ILIKE %s', (f'%{query}%',))
        total = cur.fetchone()[0]
        cur.execute('''
            SELECT * FROM logs 
            WHERE request ILIKE %s 
            ORDER BY date DESC 
            LIMIT %s OFFSET %s
        ''', (f'%{query}%', per_page, (page-1)*per_page))
        logs = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        logs = [dict(zip(columns, row)) for row in logs]
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Search error: {e}")
        logs = []
        total = 0
        flash('Ошибка при поиске', 'error')
    for log in logs:
        if log.get('date'):
            log['date'] = log['date'].strftime('%Y-%m-%d %H:%M:%S')
    total_pages = (total // per_page) + (1 if total % per_page else 0)
    return render_template('index.html', logs=logs, page=page, total_pages=total_pages, q=query)

@app.route('/export')
@login_required
def export():
    try:
        conn = get_db_connection()
        query = "SELECT * FROM logs"
        df = pd.read_sql(query, conn)
        conn.close()
        csv = df.to_csv(index=False)
        return Response(
            csv,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=logs.csv"}
        )
    except Exception as e:
        print(f"Export error: {e}")
        flash('Ошибка при экспорте данных', 'error')
        return redirect(url_for('index'))

@app.route('/log/<int:log_id>')
@login_required
def log_detail(log_id):
    try:
        conn = get_db_connection()
        df = pd.read_sql("SELECT * FROM logs WHERE id=%s", conn, params=[log_id])
        conn.close()
        if df.empty:
            flash('Лог не найден', 'error')
            return redirect(url_for('index'))
        log = df.iloc[0].to_dict()
        return render_template('log_detail.html', log=log)
    except Exception as e:
        print(f"Log detail error: {e}")
        flash('Ошибка при загрузке лога', 'error')
        return redirect(url_for('index'))

@app.route('/api/stats')
@login_required
def api_stats():
    range_ = request.args.get('range', '24h')
    try:
        conn = get_db_connection()
        if range_ == '7d':
            query = "SELECT DATE(date) as day, COUNT(*) as cnt FROM logs WHERE label=1 AND date >= NOW() - INTERVAL '7 days' GROUP BY day ORDER BY day"
        elif range_ == '30d':
            query = "SELECT DATE(date) as day, COUNT(*) as cnt FROM logs WHERE label=1 AND date >= NOW() - INTERVAL '30 days' GROUP BY day ORDER BY day"
        else:  # 24h
            query = "SELECT to_char(date, 'HH24:00') as day, COUNT(*) as cnt FROM logs WHERE label=1 AND date >= NOW() - INTERVAL '24 hours' GROUP BY day ORDER BY day"
        df = pd.read_sql(query, conn)
        conn.close()
        return jsonify({
            "labels": df['day'].astype(str).tolist(),
            "values": df['cnt'].tolist()
        })
    except Exception as e:
        print(f"Stats error: {e}")
        return jsonify({"error": "Failed to get statistics"}), 500

@app.route('/api/logs', methods=['GET'])
@login_required
def api_logs():
    try:
        conn = get_db_connection()
        df = pd.read_sql("SELECT * FROM logs LIMIT 1000", conn)
        conn.close()
        return jsonify(df.to_dict('records'))
    except Exception as e:
        print(f"API logs error: {e}")
        return jsonify({"error": "Failed to get logs"}), 500

@app.route('/api/log/<int:log_id>')
@login_required
def api_log_detail(log_id):
    try:
        conn = get_db_connection()
        df = pd.read_sql("SELECT * FROM logs WHERE id=%s", conn, params=[log_id])
        conn.close()
        if df.empty:
            return {}, 404
        return df.iloc[0].to_dict()
    except Exception as e:
        print(f"API log detail error: {e}")
        return jsonify({"error": "Failed to get log details"}), 500

@app.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(user=current_user.username, role=current_user.role)
    return dict(user=None, role=None)

@app.context_processor
def inject_now():
    return {'now': datetime.now}

@app.route('/help')
@login_required
def help():
    return render_template('help.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/profile')
@login_required
def profile():
    logins = []  # Здесь должна быть логика для загрузки истории входов
    return render_template('profile.html', logins=logins)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old = request.form.get('old_password', '')
    new = request.form.get('new_password', '')
    
    if not old or not new:
        flash('Все поля должны быть заполнены', 'error')
        return redirect(url_for('profile'))
    
    user = USERS.get(current_user.username)
    if not user or not check_password_hash(user['password'], old):
        flash('Неверный текущий пароль', 'error')
        return redirect(url_for('profile'))
    
    USERS[current_user.username]['password'] = generate_password_hash(new)
    flash('Пароль успешно изменён', 'success')
    return redirect(url_for('profile'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            error = "Все поля должны быть заполнены"
        elif len(password) < 8:
            error = "Пароль должен содержать минимум 8 символов"
        elif username in USERS:
            error = "Пользователь уже существует"
        else:
            USERS[username] = {
                'password': generate_password_hash(password),
                'role': 'user'
            }
            flash("Регистрация успешна! Теперь войдите.", "success")
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/check_dataset', methods=['GET'])
@login_required
def check_dataset():
    try:
        # Загружаем датасет
        df = pd.read_csv('Modified_SQL_Dataset.csv')
        
        # Получаем параметры из запроса
        limit = int(request.args.get('limit', 10))  # Сколько запросов проверить
        offset = int(request.args.get('offset', 0))  # С какого запроса начать
        
        # Берем часть запросов из датасета
        queries = df['Query'].iloc[offset:offset+limit].tolist()
        true_labels = df['Label'].iloc[offset:offset+limit].tolist()
        
        results = []
        for query, true_label in zip(queries, true_labels):
            # Получаем предсказание
            result = predict_query(query)
            if result is None:
                continue
                
            prediction, confidence, similar_queries = result
            
            # Анализируем запрос
            suspicious_patterns = []
            if "'" in query or '"' in query:
                suspicious_patterns.append("Обнаружены кавычки в запросе")
            if 'UNION' in query.upper():
                suspicious_patterns.append("Обнаружено использование UNION")
            if '--' in query or '/*' in query:
                suspicious_patterns.append("Обнаружены SQL-комментарии")
                
            # Определяем уровень риска
            if prediction:
                risk_level = 'HIGH' if confidence > 80 else 'MEDIUM'
            else:
                risk_level = 'LOW'
                
            results.append({
                'query': query,
                'true_label': bool(true_label),
                'prediction': bool(prediction),
                'confidence': confidence,
                'risk_level': risk_level,
                'suspicious_patterns': suspicious_patterns,
                'similar_queries': similar_queries,
                'is_correct': bool(true_label) == bool(prediction)
            })
            
        # Считаем статистику
        total = len(results)
        correct = sum(1 for r in results if r['is_correct'])
        accuracy = (correct / total * 100) if total > 0 else 0
        
        return render_template('dataset_results.html',
                             results=results,
                             total=total,
                             correct=correct,
                             accuracy=accuracy,
                             offset=offset,
                             limit=limit)
                             
    except Exception as e:
        app.logger.error(f"Ошибка при проверке датасета: {str(e)}")
        flash('Произошла ошибка при проверке датасета', 'error')
        return redirect(url_for('index'))

def save_prediction(query, prediction, confidence, risk_level):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO logs (request, label, confidence, risk_level, date) VALUES (%s, %s, %s, %s, NOW())",
            (query, int(prediction), float(confidence), risk_level)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f'Ошибка при сохранении предсказания: {e}')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)