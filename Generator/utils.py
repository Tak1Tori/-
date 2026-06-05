import random
import pandas as pd
import string
from datetime import timedelta
import json
from config import RAW_RESERVED_USERNAME, RAW_RESERVED_PASSWORD

#Random password
def rand_password(file=RAW_RESERVED_PASSWORD):
    df = pd.read_csv(file, usecols=['password'])
    random_value = df['password'].sample().iloc[0]
    ran_pass = random.choice([1, 2, 3])

    if ran_pass == 1 or ran_pass == 2:
        password = random_value
    else:
        password = ''
        chars = string.ascii_letters + string.digits
        for j in range(-1, random.randrange(1, 24)):
            password += random.choice(chars)
    return password

#Random login(username)
def rand_login(file=RAW_RESERVED_USERNAME):
    df = pd.read_csv(file, usecols=['Username'])
    random_value = df['Username'].dropna().sample().iloc[0]
    ran_log = random.choice([1, 2, 3, 4, 5])

    if ran_log == 1 or ran_log == 2:
        login = random_value
    elif ran_log == 3:
        login = 'root'
    elif ran_log == 4:
        login = rand_password()
    else:
        login = ''
        chars = string.ascii_letters + string.digits
        for j in range(-1, random.randrange(1, 24)):
            login += random.choice(chars)
    return login

#Random IPv4
def ipv4_rand():
    ipv4_1 = random.randrange(0, 255)
    ipv4_2 = random.randrange(0, 255)
    ipv4_3 = random.randrange(0, 255)
    ipv4_4 = random.randrange(0, 255)
    return f"{ipv4_1}.{ipv4_2}.{ipv4_3}.{ipv4_4}"

#Random date
def get_random_datetime(start_date, end_date):
    # Считаем разницу между датами в секундах
    delta = end_date - start_date
    seconds_range = int(delta.total_seconds())

    # Выбираем случайное количество секунд
    random_seconds = random.randrange(seconds_range)

    # Прибавляем их к начальной дате
    return start_date + timedelta(seconds=random_seconds)


df = pd.read_csv('../Data/sessions_data.csv')

# Парсим parameters
params_list = df['parameters'].apply(json.loads).tolist()


def rand_user_agent_from_dataset():
    """Случайный реалистичный User-Agent из датасета."""
    params = random.choice(params_list)
    return params.get('user_agent_string', '')


def rand_time_from_dataset(start_date, end_date):
    """
    Случайное время, похожее на распределение в датасете.
    Учитывает день недели и час из реальных данных.
    """
    params = random.choice(params_list)
    hour = int(params.get('hour', '0').split()[0])  # "2 PM" → 14
    day_of_week = params.get('day_of_week', 'Monday')

    # Находим ближайший день недели в диапазоне
    # (упрощённо — просто случайное время в диапазоне)
    delta = end_date - start_date
    random_seconds = random.randint(0, int(delta.total_seconds()))
    return start_date + timedelta(seconds=random_seconds)

def extract_all_values(payload):
    """Извлекает все значения из key=value&..., склеивает через пробел."""
    if '=' not in payload:
        return payload
    parts = payload.split('&')
    values = []
    for part in parts:
        if '=' in part:
            values.append(part.split('=', 1)[1])
    return ' '.join(values)