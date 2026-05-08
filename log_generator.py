#Libraries
import string
import pandas as pd
import json
import random
import uuid
from datetime import datetime, timedelta
from processing import TERMINAL_COMMANDS, ATOMIC_LINUX_PLAYLOADS, RSHELL_LINUX_ONLY, EXPLOITDB_SHELL_ONLY

#Constant
NUM_BENIGN_SESSIONS = 10000  # чисто легитимные сессии
NUM_MALICIOUS_SESSIONS = 6000  # сессии с атаками (шум + пейлоад)
NUM_MIXED_SESSIONS = 4000  # сессии, где атака спрятана глубоко в шуме
NUM_LOGS = 20000 # количество сессий для HTTP
RAW_RESERVED_USERNAME = 'raw_data/reserved-usernames.csv'
RAW_RESERVED_PASSWORD = 'raw_data/passwords.csv'

with open(TERMINAL_COMMANDS, 'r', encoding='utf-8') as f:
    LEGIT_COMMANDS = [json.loads(line) for line in f if line.strip()]

with open(ATOMIC_LINUX_PLAYLOADS, 'r', encoding='utf-8') as f:
    ATOMIC_SCENARIOS = [json.loads(line) for line in f if line.strip()]

with open(RSHELL_LINUX_ONLY, 'r', encoding='utf-8') as f:
    REVERSE_SHELLS = [json.loads(line) for line in f if line.strip()]

with open(EXPLOITDB_SHELL_ONLY, 'r', encoding='utf-8') as f:
    EXPLOITDB_SHELLS = [json.loads(line) for line in f if line.strip()]

#Mapping Category
CATEGORY_TO_TACTIC = {
    'Navigation': 'Discovery',
    'Viewing': 'Discovery',
    'System Info': 'Discovery',
    'Networking': 'Discovery',
    'File Management': 'Collection',
    'Editor': 'Execution',
    'Package Management': 'Execution',
    'Process': 'Execution',
    'Permissions': 'Defense Evasion',
    'User Management': 'Persistence',
}
#Mapping Tactics
TECHNIQUE_TO_TACTIC = {
    'T1001': ['Command and Control'],'T1001.002': ['Command and Control'],'T1003': ['Credential Access'],
    'T1003.001': ['Credential Access'],'T1003.007': ['Credential Access'],'T1003.008': ['Credential Access'],
    'T1005': ['Collection'],'T1007': ['Discovery'],'T1014': ['Defense Evasion'],'T1016': ['Discovery'],
    'T1016.001': ['Discovery'],'T1018': ['Discovery'],'T1027': ['Defense Evasion'],'T1027.001': ['Defense Evasion'],
    'T1027.002': ['Defense Evasion'],'T1027.004': ['Defense Evasion'],'T1027.013': ['Defense Evasion'],
    'T1030': ['Command and Control'],'T1033': ['Discovery'],'T1036.003': ['Defense Evasion'],'T1036.004': ['Defense Evasion'],
    'T1036.005': ['Defense Evasion'],'T1036.006': ['Defense Evasion'],'T1037.004': ['Persistence', 'Privilege Escalation'],
    'T1040': ['Discovery'],'T1046': ['Discovery'],'T1048': ['Exfiltration'],'T1048.002': ['Exfiltration'],'T1048.003': ['Exfiltration'],
    'T1049': ['Discovery'],'T1053.002': ['Persistence', 'Privilege Escalation'],'T1053.003': ['Persistence', 'Privilege Escalation'],'T1053.006': ['Persistence', 'Privilege Escalation'],
    'T1056.001': ['Collection'],'T1057': ['Discovery'],'T1059.004': ['Execution'],'T1059.006': ['Execution'],
    'T1069.001': ['Discovery'],'T1069.002': ['Discovery'],'T1070.003': ['Defense Evasion'],'T1070.004': ['Defense Evasion'],
    'T1070.006': ['Defense Evasion'],'T1070.008': ['Defense Evasion'],'T1071.001': ['Command and Control'],'T1074.001': ['Collection'],
    'T1078': ['Initial Access', 'Defense Evasion', 'Persistence', 'Privilege Escalation'],'T1078.003': ['Initial Access', 'Defense Evasion', 'Persistence', 'Privilege Escalation'],
    'T1082': ['Discovery'],'T1083': ['Discovery'],'T1087.001': ['Discovery'],'T1087.002': ['Discovery'],'T1090.001': ['Command and Control'],
    'T1090.003': ['Command and Control'],'T1098.004': ['Persistence'],'T1105': ['Command and Control'],'T1110.001': ['Credential Access'],
    'T1110.004': ['Credential Access'],'T1113': ['Collection'],'T1115': ['Collection'],'T1124': ['Discovery'],
    'T1132.001': ['Command and Control'],'T1135': ['Discovery'],'T1136.001': ['Persistence'],'T1136.002': ['Persistence'],
    'T1140': ['Defense Evasion'],'T1195.002': ['Initial Access'],'T1201': ['Discovery'],'T1217': ['Discovery'],
    'T1222.002': ['Defense Evasion'],'T1485': ['Impact'],'T1486': ['Impact'],'T1489': ['Impact'],'T1496': ['Impact'],
    'T1497.001': ['Defense Evasion'],'T1497.003': ['Defense Evasion'],'T1518.001': ['Discovery'],'T1529': ['Impact'],
    'T1531': ['Impact'],'T1543.002': ['Persistence', 'Privilege Escalation'],'T1546.004': ['Privilege Escalation', 'Persistence'],
    'T1546.005': ['Privilege Escalation', 'Persistence'],'T1546.018': ['Privilege Escalation', 'Persistence'],
    'T1547.006': ['Privilege Escalation', 'Persistence'],'T1548.001': ['Privilege Escalation', 'Defense Evasion'],
    'T1548.003': ['Privilege Escalation', 'Defense Evasion'],'T1552': ['Credential Access'],'T1552.001': ['Credential Access'],
    'T1552.003': ['Credential Access'],'T1552.004': ['Credential Access'],'T1552.007': ['Credential Access'],
    'T1553.004': ['Defense Evasion'],'T1555.003': ['Credential Access'],'T1556.003': ['Defense Evasion'],
    'T1560.001': ['Collection'],'T1560.002': ['Collection'],'T1564.001': ['Defense Evasion'],
    'T1568.002': ['Command and Control'],'T1569.002': ['Execution'],'T1569.003': ['Execution'],'T1571': ['Command and Control'],
    'T1572': ['Exfiltration'],'T1574.006': ['Persistence', 'Privilege Escalation', 'Defense Evasion'],'T1580': ['Discovery'],
    'T1614': ['Discovery'],'T1614.001': ['Discovery'],'T1652': ['Discovery'],'T1659': ['Command and Control'],
    'T1685': ['Impact'],'T1685.002': ['Impact'],'T1685.004': ['Impact'],'T1685.006': ['Impact'],
    'T1686': ['Impact'],'T1690': ['Impact'],
}

DESCRIPTION_TO_TACTIC = {
        'Privilege Escalation': [
            'privilege escalation', 'local root', 'suid', 'sudo', 'privesc',
            'privilege', 'elevation', 'root shell', 'root exploit',
            'setuid', 'setgid', 'cap_sys_admin', 'local exploit'
        ],
        'Execution': [
            'remote code execution', 'rce', 'command execution',
            'code injection', 'arbitrary code', 'buffer overflow',
            'format string', 'remote exploit', 'remote root',
            'remote command', 'command injection', 'shell',
        ],
        'Impact': [
            'denial of service', 'dos', 'ddos', 'crash', 'etrn',
            'flood', 'memory leak', 'resource exhaustion',
            'hang', 'freeze', 'reboot', 'shutdown',
        ],
        'Command and Control': [
            'reverse shell', 'bind shell', 'backdoor', 'connect back',
            'reverse_tcp', 'bind_tcp',
        ],
        'Discovery': [
            'scanner', 'enumeration', 'discovery', 'scan',
            'information', 'file read', 'directory traversal',
            'path traversal', 'read file', 'disclose',
        ],
        'Credential Access': [
            'password', 'credential', 'hash', 'brute force',
            'authentication bypass', 'login bypass', 'passwd',
            'shadow', 'hash dump',
        ],
        'Persistence': [
            'persistence', 'backdoor', 'rootkit', 'boot',
            'cron', 'rc.local', 'init.d', 'startup',
        ],
        'Defense Evasion': [
            'bypass', 'evasion', 'hide', 'obfuscation', 'clear log',
            'symlink', 'race condition', 'insecure', 'predictable',
            'temporary file', 'file creation', 'file overwrite',
        ],
        'Initial Access': [
            'remote exploit', 'remote root', 'remote attack',
            'remote code', 'unauth', 'unauthenticated',
        ],
        'Lateral Movement': [
            'ssh', 'lateral', 'pivoting', 'pass-the',
        ],
        'Exfiltration': [
            'exfiltration', 'data leak', 'steal', 'transfer',
        ],
    }
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
def gen_ssh_log():
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

    with open('data/sessions.json', 'w', encoding='utf-8') as f:
        json.dump(all_sessions, f, indent=2, ensure_ascii=False)

    print(f"Метаданные сохранены в sessions_meta.json")