#Libraries
import string
import pandas as pd
import json
import random
import uuid
from datetime import datetime, timedelta
from config import (TERMINAL_COMMANDS, ATOMIC_LINUX_PLAYLOADS, NUM_BENIGN_SESSIONS, DESCRIPTION_TO_TACTIC,
                    RSHELL_LINUX_ONLY, EXPLOITDB_SHELL_ONLY,NUM_MALICIOUS_SESSIONS, RAW_RESERVED_PASSWORD,
                    TECHNIQUE_TO_TACTIC,CATEGORY_TO_TACTIC, NUM_MIXED_SESSIONS, RAW_RESERVED_USERNAME, LOGS_SSH)


with open(TERMINAL_COMMANDS, 'r', encoding='utf-8') as f:
    LEGIT_COMMANDS = [json.loads(line) for line in f if line.strip()]

with open(ATOMIC_LINUX_PLAYLOADS, 'r', encoding='utf-8') as f:
    ATOMIC_SCENARIOS = [json.loads(line) for line in f if line.strip()]

with open(RSHELL_LINUX_ONLY, 'r', encoding='utf-8') as f:
    REVERSE_SHELLS = [json.loads(line) for line in f if line.strip()]

with open(EXPLOITDB_SHELL_ONLY, 'r', encoding='utf-8') as f:
    EXPLOITDB_SHELLS = [json.loads(line) for line in f if line.strip()]


def get_tactics_from_technique(technique_id):
    """Точный маппинг technique_id - список тактик MITRE."""
    # Сначала ищем полное совпадение (T1003.007)
    if technique_id in TECHNIQUE_TO_TACTIC:
        return TECHNIQUE_TO_TACTIC[technique_id]

    # Затем ищем родительскую технику (T1003)
    parent = technique_id.split('.')[0]
    if parent in TECHNIQUE_TO_TACTIC:
        return TECHNIQUE_TO_TACTIC[parent]

    # Fallback по префиксу
    prefix = technique_id[:3]
    prefix_map = {
        'T10': 'Initial Access', 'T11': 'Execution', 'T12': 'Persistence',
        'T13': 'Privilege Escalation', 'T14': 'Defense Evasion', 'T15': 'Credential Access',
        'T16': 'Discovery', 'T17': 'Lateral Movement', 'T18': 'Collection',
        'T19': 'Command and Control', 'T20': 'Exfiltration', 'T21': 'Impact',
    }
    return [prefix_map.get(prefix, 'Unknown')]

def get_tactics_for_commands(commands):
    """Собирает тактики для списка команд (из категорий легитимных команд)."""
    tactics = set()
    for cmd in commands:
        for lc in LEGIT_COMMANDS:
            if lc.get('command') == cmd:
                cat = lc.get('category', '')
                tactic = CATEGORY_TO_TACTIC.get(cat, '')
                if tactic:
                    tactics.add(tactic)
                break
    return list(tactics)

def get_tactics_from_description(desc):
    """Эвристика для Exploit-DB: тактики из описания."""
    tactics = []
    desc = desc.lower()


    for tactic, keywords in DESCRIPTION_TO_TACTIC.items():
        if any(kw in desc for kw in keywords):
            tactics.append(tactic)

    return tactics if tactics else ['Unknown']
#Random password
def rand_password():
    df = pd.read_csv(RAW_RESERVED_PASSWORD, usecols=['password'])
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
def rand_login():
    df = pd.read_csv(RAW_RESERVED_USERNAME, usecols=['Username'])
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

#Random legit command
def random_legit_command():
    """Вернуть случайную легитимную команду"""
    cmd = random.choice(LEGIT_COMMANDS)
    return cmd.get('command', cmd.get('payload', 'ls'))

#Random amount of noise(legit_command)
def random_noise_commands(min_cmds=3, max_cmds=15):
    """Генерация блока шумовых команд"""
    n = random.randint(min_cmds, max_cmds)
    return [random_legit_command() for _ in range(n)]

#Generate session
def generate_session(session_type, start_time):
    """
    session_type: 'benign', 'malicious', 'mixed'
    Возвращает список строк в TXT-формате
    """
    user = rand_login()
    ip = ipv4_rand()
    session_id = str(uuid.uuid4())[:8]
    password = rand_password()

    all_tactics = set()
    commands = []
    current_time = start_time
    commands_with_time = []

    current_time += timedelta(seconds=random.randint(1, 5))

    if session_type == 'benign':
        # Только легитимные команды
        commands = random_noise_commands(5, 20)
        all_tactics = set(get_tactics_for_commands(commands))

    elif session_type == 'malicious':
        # Шум - Атака - Шум
        pre_noise = random_noise_commands(1, 3)
        attack_commands, attack_tactics = generate_attack_sequence()
        post_noise = random_noise_commands(0, 3)
        commands = pre_noise + attack_commands + post_noise
        all_tactics = set(get_tactics_for_commands(pre_noise + post_noise))
        all_tactics.update(attack_tactics)

    elif session_type == 'mixed':
        # Атака замаскирована глубоко в легитимной работе
        all_noise = random_noise_commands(10, 25)
        attack_commands, attack_tactics = generate_attack_sequence()
        # Вставляем атаку в случайное место
        insert_pos = random.randint(3, len(all_noise) - 2)
        commands = all_noise[:insert_pos] + attack_commands + all_noise[insert_pos:]
        all_tactics = set(get_tactics_for_commands(all_noise))
        all_tactics.update(attack_tactics)

    # Запись команд
    for cmd in commands:
        current_time += timedelta(seconds=random.randint(1, 10))
        commands_with_time.append({
            "date": current_time.strftime('%Y-%m-%d %H:%M:%S'),
            "cmd": cmd
        })

    commands = commands_with_time
    end_time = current_time + timedelta(seconds=random.randint(1, 5))

    # Завершение сессии

    attempts_log = attempted_ssh(
        date_log_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
        date_exit_time=end_time.strftime('%Y-%m-%d %H:%M:%S'),
        real_username=user,
        real_password=password,
    )

    return {
        "session_id": session_id,
        "ip": ip,
        "username": user,
        "password": password,
        "date_start": start_time.strftime('%Y-%m-%d %H:%M:%S'),
        "date_end": end_time.strftime('%Y-%m-%d %H:%M:%S'),
        "attempts": len(attempts_log),
        "attempts_log": attempts_log,
        "commands": commands,
        "type": session_type,
        "tactics": sorted(list(all_tactics))
    }

#Generate attack
def generate_attack_sequence():
    """
    Собрать цепочку атаки:
    1. Взять случайный сценарий Atomic (разведка + действия)
    2. Добавить реверс-шелл в конец (C2)
    """
    attack_steps = []
    tactics = []

    # Выбираем источник: 50% Atomic, 50% Exploit-DB
    if random.random() < 0.5:
        scenario = random.choice(ATOMIC_SCENARIOS)
        command_block = scenario.get('command', '')
        attack_steps = [s.strip() for s in command_block.split('\n') if s.strip()]
        tid = scenario.get('technique_id', '')
        tactics = get_tactics_from_technique(tid)
    else:
        script = random.choice(EXPLOITDB_SHELLS)
        attack_steps = script.get('commands', [])
        desc = script.get('description', '')
        tactics = get_tactics_from_description(desc)

    # Без ограничений — берём как есть

    # С вероятностью 30% добавляем реверс-шелл в конец
    if random.random() < 0.3:
        rs = random.choice(REVERSE_SHELLS)
        attack_steps.append(rs.get('payload', rs.get('command', '')))
        if 'Command and Control' not in tactics:
            tactics.append('Command and Control')

    return attack_steps, tactics

#Attempted to SSH
def attempted_ssh(date_log_time, date_exit_time, real_username, real_password):
    date_log_time = datetime.strptime(date_log_time, '%Y-%m-%d %H:%M:%S')
    date_exit_time = datetime.strptime(date_exit_time, '%Y-%m-%d %H:%M:%S')

    attempts = []

    # Определяем уровень брутфорса
    if random.random() < 0.1:
        # Жёсткий брутфорс (100-1000 попыток)
        total_attempts = random.randint(100, 1000)
        step = 0.5
    elif random.random() < 0.5:
        # Средний брутфорс (20-100 попыток)
        total_attempts = random.randint(20, 100)
        step = 3
    else:
        # Лёгкий брутфорс (5-10 попыток)
        total_attempts = random.randint(5, 10)
        step = 6

    start_time = date_log_time - timedelta(seconds=int(total_attempts * step))

    # Генерируем попытки
    for i in range(total_attempts):
        if start_time >= date_log_time:
            break

        # Неудачная попытка
        attempts.append({
            "stable": "attempt",
            "time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "username": rand_login(),
            "password": rand_password()
        })
        start_time += timedelta(seconds=random.uniform(0.5, step))

    # Успешный вход
    attempts.append({
        "stable": "connected",
        "time": date_log_time.strftime('%Y-%m-%d %H:%M:%S'),
        "username": real_username,
        "password": real_password
    })

    # Выход
    attempts.append({
        "stable": "disconnected",
        "time": date_exit_time.strftime('%Y-%m-%d %H:%M:%S'),
        "username": real_username
    })

    return attempts

#Shell log
def log_ssh_generator():
    all_sessions = []
    start_date = datetime(2025, 9, 1, 0, 0)
    end_date = datetime(2026, 5, 10, 23, 59)

    print("Генерация сессий...")

    # Безвредные сессии
    for i in range(NUM_BENIGN_SESSIONS):
        base_time = get_random_datetime(start_date, end_date)
        all_sessions.append(generate_session('benign', base_time))
        print(f"{i} обработано сессий")

    # Вредоносные сессии (атака почти без шума)
    for i in range(NUM_MALICIOUS_SESSIONS):
        base_time = get_random_datetime(start_date, end_date)
        all_sessions.append(generate_session('malicious', base_time))
        print(f"{i} обработано сессий")

    # Смешанные сессии (атака спрятана)
    for i in range(NUM_MIXED_SESSIONS):
        base_time = get_random_datetime(start_date, end_date)
        print(f"{i} обработано сессий")
        all_sessions.append(generate_session('mixed', base_time))

    print(f"\nГотово!")
    print(f"Безвредных сессий: {NUM_BENIGN_SESSIONS}")
    print(f"Вредоносных сессий: {NUM_MALICIOUS_SESSIONS}")
    print(f"Смешанных сессий: {NUM_MIXED_SESSIONS}")

    with open(LOG_SSH, 'w', encoding='utf-8') as f:
        json.dump(all_sessions, f, indent=2, ensure_ascii=False)

    print(f"Метаданные сохранены в sessions_meta.json")