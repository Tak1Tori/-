#Libraries
import json
import re
import yaml
import glob
import os
import csv

#Constant variables
LINUX_LANGUAGES = {'bash', 'sh', 'python', 'perl', 'python3', 'php', 'ruby', 'lua', 'awk', 'gawk'}
ATOMIC_DIR = "raw_data/atomics"  # путь к папке с техниками
RAW_LINUX_TERMINAL_COMMANDS = "raw_data/LINUX_TERMINAL_COMMANDS.jsonl"
RAW_REVERSESHELL_PLAYLOADS_DATASET = "raw_data/Reverseshell_payloads_dataset.jsonl"
ATOMIC_LINUX_PLAYLOADS = "data/atomic_linux_payloads.jsonl"
RSHELL_LINUX_ONLY = "data/rshell_linux_only.jsonl"
TERMINAL_COMMANDS = "data/terminal_cmds.jsonl"
EXPLOITDB_DIR = "raw_data/exploitdb"
CSV_FILES = [
    "files_exploits.csv",
    "files_shellcodes.csv"
]
EXPLOITDB_SHELL_ONLY = "data/exploitdb_shell_only.jsonl"

def catch_err(line_num, line, errors):
    obj = None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        try:
            fixed_line = line.encode('utf-8').decode('unicode_escape')
            obj = json.loads(fixed_line)
        except:
            fixed_line = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', line)
            try:
                obj = json.loads(fixed_line)
            except:
                errors.append(f"Line {line_num}: {str(e)[:100]}")
    return obj, errors

#Extraction of Linux ReverseShell
def extr_reverse_shell_payloads():
    linux_payloads = []
    skipped = []
    errors = []

    with open(RAW_REVERSESHELL_PLAYLOADS_DATASET, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            try:
                obj, errors= catch_err(line_num, line, errors)
            except:
                continue

            lang = obj.get('language', '').lower()
            plat = obj.get('platform', '').lower()

            if lang in LINUX_LANGUAGES or plat == 'linux':
                linux_payloads.append(obj)
            else:
                skipped.append(obj.get('id', f'line_{line_num}'))

    # Сохраняем результат
    with open(RSHELL_LINUX_ONLY, 'w', encoding='utf-8') as f:
        for obj in linux_payloads:
            # Используем ensure_ascii=False для сохранения спецсимволов
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')

    print(f"Оставлено Linux: {len(linux_payloads)}")
    print(f"Пропущено (не Linux): {len(skipped)}")
    print(f"Ошибок парсинга: {len(errors)}")
    if errors:
        print("Первые 5 ошибок:")
        for err in errors[:5]:
            print(f"  {err}")

#Parser Atomic Red Team(Linux)
def parser_atomic_red():

    atomic_commands = []
    skipped_no_linux = 0
    skipped_no_executor = 0
    errors = []

    for yaml_file in glob.glob(os.path.join(ATOMIC_DIR, "T*", "T*.yaml")):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            errors.append(f"YAML error {yaml_file}: {str(e)[:80]}")
            continue

        technique_id = data.get('attack_technique', 'UNKNOWN')

        for test in data.get('atomic_tests', []):
            test_name = test.get('name', 'unnamed')
            platforms = test.get('supported_platforms', [])
            test_description = test.get('description', '')
            # Фильтр: только Linux
            if 'linux' not in [p.lower() for p in platforms]:
                skipped_no_linux += 1
                continue

            executor = test.get('executor', {})
            executor_name = executor.get('name', '').lower()

            # Только shell-исполнители
            if executor_name not in ['sh', 'bash']:
                skipped_no_executor += 1
                continue

            command = executor.get('command', '').strip()
            if not command:
                continue

            atomic_commands.append({
                'source': 'atomic-red-team',
                'technique_id': technique_id,
                'test_name': test_name,
                'description': test_description,
                'executor': executor_name,
                'command': command
            })

    # Сохраняем
    with open(ATOMIC_LINUX_PLAYLOADS, 'w', encoding='utf-8') as f:
        for obj in atomic_commands:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')

    print(f"Извлечено Linux-сценариев: {len(atomic_commands)}")
    print(f"Пропущено (не Linux): {skipped_no_linux}")
    print(f"Пропущено (не sh/bash): {skipped_no_executor}")
    if errors:
        print(f"Ошибок YAML: {len(errors)}")
        for e in errors[:3]:
            print(f"  {e}")

def extr_linux_terminal_cmd():
    linux_terminal_cmds = []
    errors = []

    with open(RAW_LINUX_TERMINAL_COMMANDS, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            try:
                obj, errors = catch_err(line_num, line, errors)
            except:
                continue

            linux_terminal_cmds.append(obj)

    with open(TERMINAL_COMMANDS, 'w', encoding='utf-8') as f:
        for obj in linux_terminal_cmds:
            # Используем ensure_ascii=False для сохранения спецсимволов
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')

    print(f"Оставлено Linux: {len(linux_terminal_cmds)}")
    print(f"Ошибок парсинга: {len(errors)}")
    if errors:
        print("Первые 5 ошибок:")
        for err in errors[:5]:
            print(f"  {err}")


def extr_exploitdb_shell_cmd():
    shell_scripts = []

    for csv_name in CSV_FILES:
        csv_path = os.path.join(EXPLOITDB_DIR, csv_name)

        if not os.path.exists(csv_path):
            print(f"Не найден: {csv_path}")
            continue

        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)

            for row in reader:
                # Фильтр: только .sh И только Linux
                file_path = row.get('file', '')
                platform = row.get('platform', '').lower()

                if not file_path.endswith('.sh'):
                    continue
                if platform != 'linux':
                    continue

                description = row.get('description', '')
                title = row.get('title', '') or os.path.basename(file_path)

                # Полный путь к файлу
                full_path = os.path.join(EXPLOITDB_DIR, file_path)

                # Пробуем прочитать команды (если файл существует)
                commands = []
                if os.path.exists(full_path):
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f_script:
                            for line in f_script:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                 commands.append(line)
                    except:
                        pass

                shell_scripts.append({
                    'source': 'exploit-db',
                    'file': file_path,
                    'title': title,
                    'platform': platform,
                    'description': description,
                    'command_count': len(commands),
                    'commands': commands
                })

    # Сохраняем
    with open(EXPLOITDB_SHELL_ONLY, 'w', encoding='utf-8') as f:
        for obj in shell_scripts:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')

    print(f"Найдено Linux .sh файлов: {len(shell_scripts)}")

    # Посмотрим первые 3
    for i, obj in enumerate(shell_scripts[:3]):
        print(f"\n{'=' * 50}")
        print(f"Файл: {obj['file']}")
        print(f"Description: {obj['description'][:150]}")
        print(f"Команд: {obj['command_count']}")

def is_noise_line(line):
    line = line.strip()
    if not line:
        return True

    noise_starters = [
        'source:', 'there is', 'there are', 'this script', 'this module',
        'the following', 'note:', 'author:', 'credit:', 'vendor:',
        'disclaimer:', 'description:', 'usage:', 'example:', 'see also:',
        'reference:', 'references:', 'tested on:', 'platform:', 'version:',
        'cve:', 'date:', 'exploit title:', 'type:', 'affected',
        'download:', 'solution:', 'workaround:', 'mitigation:',
        'the ', 'a ', 'an ', 'this ', 'it ', 'they ', 'we ',
        'after ', 'before ', 'when ', 'during ',
        'if you', 'to exploit', 'to use', 'you can', 'this issue',
        '**', '*/', '/*',
    ]

    lower = line.lower()
    if any(lower.startswith(w) for w in noise_starters):
        return True

    if lower.startswith('https://') or lower.startswith('http://'):
        return True

    # C-код (явные признаки)
    if re.match(r"^\s*(static|void|int|char|struct|unsigned|long|#include|#define)\s", line):
        return True

    if len(line.split()) > 12 and not any(c in line for c in '|>&;$=`(){}[]'):
        return True

    return False


def remove_heredoc_content(commands):
    result = []
    in_heredoc = False
    heredoc_marker = None

    for cmd in commands:
        if not in_heredoc:
            m = re.search(r'(?:cat\s+)?<<\s*[\'"]?(\w+)[\'"]?', cmd)
            if m:
                in_heredoc = True
                heredoc_marker = m.group(1)
                result.append(cmd)
                continue

        if in_heredoc and cmd.strip() == heredoc_marker:
            in_heredoc = False
            continue

        if not in_heredoc:
            result.append(cmd)

    return result

def clean_db():
    # Загружаем
    with open(EXPLOITDB_SHELL_ONLY, 'r', encoding='utf-8') as f:
        scripts = [json.loads(line) for line in f if line.strip()]

    # Чистим
    total_before = 0
    total_after = 0

    for script in scripts:
        before = len(script['commands'])
        total_before += before

        # Шаг 1: убрать мусорные строки
        script['commands'] = [c for c in script['commands'] if not is_noise_line(c)]
        # Шаг 2: убрать содержимое heredoc
        script['commands'] = remove_heredoc_content(script['commands'])

        after = len(script['commands'])
        total_after += after
        script['command_count'] = after

    # Сохраняем
    with open(EXPLOITDB_SHELL_ONLY, 'w', encoding='utf-8') as f:
        for obj in scripts:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')

    print(f"Команд до очистки: {total_before}")
    print(f"Команд после очистки: {total_after}")
    print(f"Удалено: {total_before - total_after}")

    # Покажем проблемные
    for s in scripts:
        if s['file'] in ['exploits/linux/dos/33591.sh', 'exploits/linux/dos/25647.sh']:
            print(f"\n{s['file']}:")
            print(f"  Команд: {s['command_count']}")
            for c in s['commands'][:5]:
                print(f"  {c[:100]}")