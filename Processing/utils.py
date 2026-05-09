import json
import re

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

def save_jsonl(data, path):
    with open(path, 'w', encoding='utf-8') as f:
        for obj in data:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')

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