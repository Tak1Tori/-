from config import TERMINAL_COMMANDS, RAW_LINUX_TERMINAL_COMMANDS
from utils import catch_err, save_jsonl

def extract_cmds():
    linux_terminal_cmds = []
    errors = []

    with open(RAW_LINUX_TERMINAL_COMMANDS, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            obj, errors = catch_err(line_num, line, errors)
            if obj is None:
                continue

            linux_terminal_cmds.append(obj)

    save_jsonl(linux_terminal_cmds, TERMINAL_COMMANDS)

    print(f"Оставлено Linux: {len(linux_terminal_cmds)}")
    print(f"Ошибок парсинга: {len(errors)}")
    if errors:
        print("Первые 5 ошибок:")
        for err in errors[:5]:
            print(f"  {err}")