import yaml
import glob
import os
from config import ATOMIC_DIR, ATOMIC_LINUX_PLAYLOADS
from utils import save_jsonl

#Parser Atomic Red Team(Linux)
def extract_atomic():
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
    save_jsonl(atomic_commands, ATOMIC_LINUX_PLAYLOADS)

    print(f"Извлечено Linux-сценариев: {len(atomic_commands)}")
    print(f"Пропущено (не Linux): {skipped_no_linux}")
    print(f"Пропущено (не sh/bash): {skipped_no_executor}")
    if errors:
        print(f"Ошибок YAML: {len(errors)}")
        for e in errors[:3]:
            print(f"  {e}")

if __name__ == "__main__":
    extract_atomic()