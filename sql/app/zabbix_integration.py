import os
import psycopg2
import subprocess
import time
import logging
from pyzabbix import ZabbixAPI

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    try:
        return psycopg2.connect(
            host=os.environ.get('DB_HOST', 'localhost'),
            database=os.environ.get('DB_NAME', 'logsdb'),
            user=os.environ.get('DB_USER', 'user'),
            password=os.environ.get('DB_PASS', 'password')
        )
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise

def get_injection_count():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM logs WHERE label=1")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        return count
    except Exception as e:
        logger.error(f"Error getting injection count: {e}")
        return 0

def wait_for_zabbix(max_retries=30, delay=2):
    """Ожидание готовности Zabbix сервера"""
    zabbix_server = os.environ.get('ZABBIX_SERVER_HOST', 'http://zabbix-web:8080')
    if not zabbix_server.startswith(('http://', 'https://')):
        zabbix_server = 'http://' + zabbix_server
    
    for i in range(max_retries):
        try:
            zapi = ZabbixAPI(zabbix_server)
            zapi.login(os.environ.get('ZABBIX_USER', 'Admin'),
                      os.environ.get('ZABBIX_PASSWORD', 'zabbix'))
            logger.info("Successfully connected to Zabbix")
            return True
        except Exception as e:
            if i < max_retries - 1:
                logger.warning(f"Attempt {i+1}/{max_retries} to connect to Zabbix failed: {e}")
                time.sleep(delay)
            else:
                logger.error(f"Failed to connect to Zabbix after {max_retries} attempts: {e}")
                return False

def create_zabbix_host(zapi):
    """Создание хоста в Zabbix"""
    try:
        # Получаем группу Linux servers
        groups = zapi.hostgroup.get(filter={"name": "Linux servers"})
        if not groups:
            logger.warning("Linux servers group not found, using default group")
            group_id = 1
        else:
            group_id = groups[0]['groupid']

        # Создаем хост
        host = zapi.host.create({
            "host": "SQL-Injection-Monitor",
            "interfaces": [{
                "type": 1,
                "main": 1,
                "useip": 1,
                "ip": "127.0.0.1",
                "dns": "",
                "port": "10050"
            }],
            "groups": [{"groupid": group_id}],
            "templates": [{"templateid": 10001}]  # Template OS Linux
        })
        logger.info("Created new Zabbix host")
        return host['hostids'][0]
    except Exception as e:
        logger.error(f"Error creating Zabbix host: {e}")
        raise

def create_zabbix_item(zapi, host_id):
    """Создание элемента данных в Zabbix"""
    try:
        # Получаем интерфейс хоста
        interfaces = zapi.hostinterface.get(filter={"hostid": host_id})
        if not interfaces:
            raise Exception("No interfaces found for host")

        # Создаем элемент данных
        item = zapi.item.create({
            "hostid": host_id,
            "name": "SQL Injection Count",
            "key_": "injection.count",
            "type": 3,  # Numeric (unsigned)
            "value_type": 3,  # Numeric (unsigned)
            "interfaceid": interfaces[0]['interfaceid']
        })
        logger.info("Created new Zabbix item")
        return item['itemids'][0]
    except Exception as e:
        logger.error(f"Error creating Zabbix item: {e}")
        raise

def send_to_zabbix(value):
    """Отправка данных в Zabbix с использованием API"""
    if not wait_for_zabbix():
        logger.error("Zabbix server is not available")
        return False

    try:
        zabbix_server = os.environ.get('ZABBIX_SERVER_HOST', 'http://zabbix-web:8080')
        if not zabbix_server.startswith(('http://', 'https://')):
            zabbix_server = 'http://' + zabbix_server

        zapi = ZabbixAPI(zabbix_server)
        zapi.login(os.environ.get('ZABBIX_USER', 'Admin'),
                  os.environ.get('ZABBIX_PASSWORD', 'zabbix'))

        # Получаем или создаем хост
        hosts = zapi.host.get(filter={"host": "SQL-Injection-Monitor"})
        if not hosts:
            host_id = create_zabbix_host(zapi)
        else:
            host_id = hosts[0]['hostid']

        # Получаем или создаем элемент данных
        items = zapi.item.get(filter={"hostid": host_id, "key_": "injection.count"})
        if not items:
            create_zabbix_item(zapi, host_id)

        # Отправляем значение через zabbix_sender
        result = subprocess.run([
            "zabbix_sender",
            "-z", "zabbix-server",
            "-s", "SQL-Injection-Monitor",
            "-k", "injection.count",
            "-o", str(value)
        ], capture_output=True, text=True, check=True)
        
        logger.info(f"Successfully sent data to Zabbix: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error sending data via zabbix_sender: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Error sending data to Zabbix: {e}")
        return False

if __name__ == "__main__":
    count = get_injection_count()
    send_to_zabbix(count)