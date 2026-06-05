import json
import random
import uuid
import csv
from datetime import datetime, timedelta

from utils import rand_login, rand_password, ipv4_rand, get_random_datetime, rand_user_agent_from_dataset, extract_all_values

# ─── Константы ───
NUM_BENIGN = 10000
NUM_MALICIOUS = 6000
NUM_MIXED = 4000

# ─── Легитимные шаблоны HTTP-запросов к админкам ───
LEGIT_REQUESTS = [
    {"method": "GET", "path": "/wp-admin/", "payload": ""},
    {"method": "GET", "path": "/wp-admin/edit.php", "payload": ""},
    {"method": "GET", "path": "/wp-admin/plugins.php", "payload": ""},
    {"method": "POST", "path": "/wp-admin/admin-ajax.php", "payload": "action=heartbeat"},
    {"method": "GET", "path": "/wp-admin/profile.php", "payload": ""},
    {"method": "POST", "path": "/wp-login.php", "payload": "log={user}&pwd={password}"},
    {"method": "GET", "path": "/admin/", "payload": ""},
    {"method": "GET", "path": "/admin/auth/user/", "payload": ""},
    {"method": "POST", "path": "/admin/login/", "payload": "username={user}&password={password}"},
    {"method": "GET", "path": "/administrator/", "payload": ""},
    {"method": "POST", "path": "/administrator/index.php",
     "payload": "option=com_login&username={user}&passwd={password}"},
    {"method": "GET", "path": "/dashboard", "payload": ""},
    {"method": "GET", "path": "/settings", "payload": ""},
    {"method": "GET", "path": "/users", "payload": ""},
    {"method": "GET", "path": "/logout", "payload": ""},
    {"method": "GET", "path": "/", "payload": ""},
]

LEGIT_PAYLOADS = [
    "action=heartbeat&_nonce=abc123",
    "action=edit&post=42",
    "action=delete&post=15&_wpnonce=xyz789",
    "s=search+term&post_type=post",
    "log=admin&pwd=correct_password",
    "option=blogname&value=My+Site",
    "action=update&plugin=akismet%2Fakismet.php",
    "action=activate&plugin=contact-form-7%2Fwp-contact-form-7.php",
    "username=admin&password=correct_password&csrf_token=abc",
    "q=search+term&model=user",
    "action=delete_selected&ids=1,2,3",
    "page=2&per_page=20",
    "sort=date&order=desc",
    "filter=active&search=term",
    "action=heartbeat&_nonce=abc123",
    "action=edit&post=42",
    "s=search+term&post_type=post",
    "log=admin&pwd=correct_password",
    "page=2&per_page=20",
    "sort=date&order=desc",
    "q={value}"
]

# ─── Загрузка и объединение вредоносных payload'ов ───
with open('../Data/payload_combined.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    next(reader)
    ATTACK_PAYLOADS = {}
    LEGIT_VALUES = {}
    for row in reader:
        if len(row) >= 4:
            label = row[2].strip()
            payload = row[0].strip()
            if label != 'norm' and payload:
                if label not in ATTACK_PAYLOADS:
                    ATTACK_PAYLOADS[label] = []
                ATTACK_PAYLOADS[label].append(payload)
            elif label == 'norm' and payload:
                if label not in LEGIT_VALUES:
                    LEGIT_VALUES[label] = []
                LEGIT_VALUES[label].append(payload)

NAME_MAPPING = {
    'Command Injection': 'cmdi', 'Directory Traversal': 'path-traversal',
    'XSS Injection': 'xss', 'Server Side Request Forgery': 'ssrf',
    'XXE Injection': 'xxe', 'File Inclusion': 'lfi', 'NoSQL Injection': 'nosqli',
    'sqli': 'sqli', 'xss': 'xss', 'cmdi': 'cmdi',
    'path-traversal': 'path-traversal', 'ssrf': 'ssrf',
}

merged = {}
for label, payloads in ATTACK_PAYLOADS.items():
    unified = NAME_MAPPING.get(label, label)
    if unified not in merged:
        merged[unified] = []
    merged[unified].extend(payloads)

ATTACK_PAYLOADS = merged

MAX_PER_TYPE = 1000
for label in list(ATTACK_PAYLOADS.keys()):
    if len(ATTACK_PAYLOADS[label]) > MAX_PER_TYPE:
        ATTACK_PAYLOADS[label] = random.sample(ATTACK_PAYLOADS[label], MAX_PER_TYPE)

# Равные веса для всех типов
total_types = len(ATTACK_PAYLOADS)
ATTACK_WEIGHTS = {label: 1.0 / total_types for label in ATTACK_PAYLOADS}

print(f"Типов атак: {len(ATTACK_PAYLOADS)}")
for t, p in ATTACK_PAYLOADS.items():
    print(f"  {t}: {len(p)}")

# ─── Атакующие шаблоны запросов ───
ATTACK_TEMPLATES = [
    {"method": "POST", "path": "/wp-login.php", "payload_template": "log=admin&pwd={payload}"},
    {"method": "POST", "path": "/wp-admin/admin-ajax.php", "payload_template": "action=search&term={payload}"},
    {"method": "POST", "path": "/login", "payload_template": "username={payload}&password=admin"},
    {"method": "GET", "path": "/search", "payload_template": "q={payload}"},
    {"method": "GET", "path": "/api/users", "payload_template": "id={payload}"},
    {"method": "GET", "path": "/products", "payload_template": "category={payload}"},
    {"method": "GET", "path": "/wp-admin/edit.php", "payload_template": "post={payload}"},
    {"method": "GET", "path": "/admin/auth/user/", "payload_template": "q={payload}"},
]


# ─── Функции ───

def random_legit_request(username, password):
    template = random.choice(LEGIT_REQUESTS)
    if '{user}' in template['payload']:
        full_payload = template['payload'].replace('{user}', username).replace('{password}', password)
        raw_payload = f"{username} {password}"
    else:
        full_payload = random.choice(LEGIT_PAYLOADS)
        value = random.choice(LEGIT_VALUES['norm'])
        if '{value}' in full_payload:
            full_payload = full_payload.replace('{value}', value)
            raw_payload = f"{value}"
        else:
            raw_payload = extract_all_values(full_payload)

    return {
        "method": template['method'],
        "path": template['path'],
        "user_agent": rand_user_agent_from_dataset(),
        "status": random.choice([200, 200, 200, 302, 404]),
        "payload": full_payload,
        "raw_payload": raw_payload
    }


def generate_attack_requests(username, password, num_attacks=3):
    requests = []
    attack_types_used = []

    for _ in range(num_attacks):
        types = list(ATTACK_PAYLOADS.keys())
        weights = [ATTACK_WEIGHTS[t] for t in types]
        attack_type = random.choices(types, weights=weights, k=1)[0]
        attack_types_used.append(attack_type)

        payload_text = random.choice(ATTACK_PAYLOADS[attack_type])
        template = random.choice(ATTACK_TEMPLATES)
        full_payload = template['payload_template'].replace('{payload}', payload_text)

        requests.append({
            "method": template['method'],
            "path": template['path'],
            "user_agent": random.choice(['sqlmap/1.7', 'nikto/2.5', 'curl/8.4', rand_user_agent_from_dataset()]),
            "status": random.choice([200, 403, 500]),
            "payload": full_payload,
            "raw_payload": payload_text
        })

    return requests, attack_types_used


def generate_session(session_type, start_time):
    user = rand_login()
    password = rand_password()
    ip = ipv4_rand()
    session_id = str(uuid.uuid4())[:8]

    current_time = start_time
    all_requests = []
    attack_types = []

    if session_type == 'benign':
        num_requests = random.randint(5, 20)
        for _ in range(num_requests):
            all_requests.append(random_legit_request(user, password))

    elif session_type == 'malicious':
        pre = [random_legit_request(user, password) for _ in range(random.randint(1, 3))]
        attack_reqs, attack_types = generate_attack_requests(user, password, random.randint(1, 4))
        post = [random_legit_request(user, password) for _ in range(random.randint(0, 2))]
        all_requests = pre + attack_reqs + post

    elif session_type == 'mixed':
        noise = [random_legit_request(user, password) for _ in range(random.randint(10, 25))]
        attack_reqs, attack_types = generate_attack_requests(user, password, random.randint(1, 3))
        insert_pos = random.randint(3, len(noise) - 2)
        all_requests = noise[:insert_pos] + attack_reqs + noise[insert_pos:]

    for req in all_requests:
        current_time += timedelta(seconds=random.randint(1, 15))
        req['date'] = current_time.strftime('%Y-%m-%d %H:%M:%S')

    end_time = current_time + timedelta(seconds=random.randint(1, 30))

    return {
        "session_id": session_id,
        "ip": ip,
        "username": user,
        "password": password,
        "date_start": start_time.strftime('%Y-%m-%d %H:%M:%S'),
        "date_end": end_time.strftime('%Y-%m-%d %H:%M:%S'),
        "requests": all_requests,
        "type": session_type,
        "attack_types": list(set(attack_types))
    }


def gen_http_logs():
    all_sessions = []
    start_date = datetime(2025, 9, 1, 0, 0)
    end_date = datetime(2026, 5, 10, 23, 59)

    print("Генерация HTTP-сессий...")

    for i in range(NUM_BENIGN):
        base_time = get_random_datetime(start_date, end_date)
        all_sessions.append(generate_session('benign', base_time))
        if (i + 1) % 500 == 0:
            print(f"  Benign: {i + 1}/{NUM_BENIGN}")

    for i in range(NUM_MALICIOUS):
        base_time = get_random_datetime(start_date, end_date)
        all_sessions.append(generate_session('malicious', base_time))
        if (i + 1) % 500 == 0:
            print(f"  Malicious: {i + 1}/{NUM_MALICIOUS}")

    for i in range(NUM_MIXED):
        base_time = get_random_datetime(start_date, end_date)
        all_sessions.append(generate_session('mixed', base_time))
        if (i + 1) % 500 == 0:
            print(f"  Mixed: {i + 1}/{NUM_MIXED}")

    with open('../Logs/http_sessions.json', 'w', encoding='utf-8') as f:
        json.dump(all_sessions, f, indent=2, ensure_ascii=False)

    print(f"\nГотово! Всего сессий: {len(all_sessions)}")
    print(f"  Benign: {NUM_BENIGN}, Malicious: {NUM_MALICIOUS}, Mixed: {NUM_MIXED}")


if __name__ == '__main__':
    gen_http_logs()