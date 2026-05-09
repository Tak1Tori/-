from config import RSHELL_LINUX_ONLY, LINUX_LANGUAGES, RAW_REVERSESHELL_PLAYLOADS_DATASET
from utils import catch_err, save_jsonl

#Extraction of Linux ReverseShell
def extract_rshell():
    linux_payloads = []
    skipped = []
    errors = []

    with open(RAW_REVERSESHELL_PLAYLOADS_DATASET, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            obj, errors = catch_err(line_num, line, errors)
            if obj is None:
                continue

            lang = obj.get('language', '').lower()
            plat = obj.get('platform', '').lower()

            if lang in LINUX_LANGUAGES or plat == 'linux':
                linux_payloads.append(obj)
            else:
                skipped.append(obj.get('id', f'line_{line_num}'))

    # Сохраняем результат
    save_jsonl(linux_payloads, RSHELL_LINUX_ONLY)

    print(f"Оставлено Linux: {len(linux_payloads)}")
    print(f"Пропущено (не Linux): {len(skipped)}")
    print(f"Ошибок парсинга: {len(errors)}")
    if errors:
        print("Первые 5 ошибок:")
        for err in errors[:5]:
            print(f"  {err}")