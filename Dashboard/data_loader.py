import json
import pandas as pd


def load_sessions(path='data/sessions.json'):
    with open(path, 'r', encoding='utf-8') as f:
        sessions = json.load(f)

    # Плоская таблица для графиков
    rows = []
    for s in sessions:
        tactics = s.get('tactics', [])
        commands = s.get('commands', [])
        cmd_names = [c['cmd'] for c in commands]

        for cmd in commands:
            rows.append({
                'session_id': s['session_id'],
                'type': s['type'],
                'ip': s.get('ip', ''),
                'username': s.get('username', ''),
                'tactics': ', '.join(tactics),
                'num_tactics': len(tactics),
                'num_commands': len(commands),
                'cmd': cmd['cmd'],
                'cmd_time': cmd['date'],
                'has_C2': 1 if 'Command and Control' in tactics else 0,
                'has_PrivEsc': 1 if 'Privilege Escalation' in tactics else 0,
                'has_Discovery': 1 if 'Discovery' in tactics else 0,
                'has_Execution': 1 if 'Execution' in tactics else 0,
                'has_Impact': 1 if 'Impact' in tactics else 0,
            })

    df = pd.DataFrame(rows)
    return df, sessions