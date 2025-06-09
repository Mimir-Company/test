from flask import Blueprint, render_template, request, Response, abort
from flask_login import login_required, current_user
import pandas as pd
from db import get_db_connection
from datetime import datetime, timedelta
from functools import wraps

logs_bp = Blueprint('logs', __name__, url_prefix='/logs')

# Декоратор для проверки прав администратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def validate_date(date_str):
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return None

@logs_bp.route('/')
@login_required
def index():
    # Параметры по умолчанию
    page = request.args.get('page', 1, type=int)
    per_page = 100
    date_filter = request.args.get('date')
    log_type = request.args.get('type')
    search_query = request.args.get('search')
    sort = request.args.get('sort', 'id')
    order = request.args.get('order', 'desc')

    # Валидация параметров
    if order.lower() not in ('asc', 'desc'):
        order = 'desc'
    
    if sort not in ('id', 'date', 'request'):
        sort = 'id'

    conn = get_db_connection()
    try:
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        
        # Фильтр по дате
        if date_filter:
            date_obj = validate_date(date_filter)
            if date_obj:
                query += " AND DATE(date) = %s"
                params.append(date_obj)
        
        # Фильтр по типу
        if log_type == 'sql_injection':
            query += " AND label = 1"
        elif log_type == 'clean':
            query += " AND label = 0"
        
        # Поиск по тексту
        if search_query:
            query += " AND request LIKE %s"
            params.append(f"%{search_query}%")
        
        # Сортировка
        query += f" ORDER BY {sort} {order}"
        
        # Пагинация
        query += " LIMIT %s OFFSET %s"
        params.extend([per_page, (page - 1) * per_page])
        
        # Получение данных
        df = pd.read_sql(query, conn, params=params)
        
        # Получение общего количества для пагинации
        count_query = "SELECT COUNT(*) FROM logs"
        total_count = pd.read_sql(count_query, conn).iloc[0, 0]
        
        return render_template(
            'logs/index.html',
            logs=df.to_dict('records'),
            page=page,
            per_page=per_page,
            total_pages=(total_count // per_page) + 1,
            current_filters={
                'date': date_filter,
                'type': log_type,
                'search': search_query,
                'sort': sort,
                'order': order
            }
        )
    finally:
        conn.close()

@logs_bp.route('/export')
@login_required
@admin_required
def export():
    format_type = request.args.get('format', 'csv')
    date_from = request.args.get('from')
    date_to = request.args.get('to')
    
    conn = get_db_connection()
    try:
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        
        # Фильтр по дате
        if date_from:
            date_obj = validate_date(date_from)
            if date_obj:
                query += " AND DATE(date) >= %s"
                params.append(date_obj)
        
        if date_to:
            date_obj = validate_date(date_to)
            if date_obj:
                query += " AND DATE(date) <= %s"
                params.append(date_obj)
        
        if format_type == 'csv':
            def generate():
                chunk_size = 1000
                offset = 0
                while True:
                    chunk_query = query + f" LIMIT {chunk_size} OFFSET {offset}"
                    df = pd.read_sql(chunk_query, conn, params=params)
                    if df.empty:
                        break
                    yield df.to_csv(index=False, header=(offset == 0))
                    offset += chunk_size
            
            return Response(
                generate(),
                mimetype="text/csv",
                headers={
                    "Content-disposition": "attachment; filename=logs_export.csv",
                    "Content-Type": "text/csv; charset=utf-8"
                }
            )
        
        elif format_type == 'json':
            df = pd.read_sql(query, conn, params=params)
            return Response(
                df.to_json(orient='records'),
                mimetype="application/json",
                headers={
                    "Content-disposition": "attachment; filename=logs_export.json"
                }
            )
        
        else:
            abort(400, description="Unsupported export format")
    
    finally:
        conn.close()

@logs_bp.route('/stats')
@login_required
def stats():
    conn = get_db_connection()
    try:
        # Статистика за последние 7 дней
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=7)
        
        query = """
        SELECT 
            DATE(date) as day, 
            COUNT(*) as total,
            SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END) as threats
        FROM logs
        WHERE DATE(date) BETWEEN %s AND %s
        GROUP BY day
        ORDER BY day
        """
        
        stats_df = pd.read_sql(query, conn, params=[start_date, end_date])
        
        return render_template(
            'logs/stats.html',
            stats=stats_df.to_dict('records'),
            date_from=start_date.strftime('%Y-%m-%d'),
            date_to=end_date.strftime('%Y-%m-%d')
        )
    finally:
        conn.close()

@logs_bp.route('/add', methods=['POST'])
@login_required
@admin_required
def add_log():
    ip = request.form.get('ip')
    url = request.form.get('url')
    request_text = request.form.get('request')
    label = request.form.get('label', 0, type=int)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO logs (ip, url, request, label) VALUES (%s, %s, %s, %s)", (ip, url, request_text, label))
    conn.commit()
    cur.close()
    conn.close()

    # Отправляем данные в Zabbix
    from zabbix_integration import get_injection_count
    injection_count = get_injection_count()
    send_to_zabbix(injection_count)

    return redirect(url_for('logs.logs'))