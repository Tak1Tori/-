import json
import pandas as pd
from collections import Counter


def load_sessions(path='data/sessions.json'):
    with open(path, 'r', encoding='utf-8') as f:
        sessions = json.load(f)

    # Плоская таблица команд
    rows = []
    for s in sessions:
        for cmd in s.get('commands', []):
            rows.append({
                'session_id': s['session_id'],
                'type': s['type'],
                'ip': s.get('ip', ''),
                'username': s.get('username', ''),
                'tactics': ', '.join(s.get('tactics', [])),
                'num_commands': len(s.get('commands', [])),
                'cmd': cmd['cmd'],
                'cmd_time': cmd['date'],
            })

    df = pd.DataFrame(rows)

    # Тактики напрямую из sessions
    tactic_counter = Counter()
    for s in sessions:
        for t in s.get('tactics', []):
            tactic_counter[t] += 1

    tactic_counts = pd.DataFrame({
        'Tactic': list(tactic_counter.keys()),
        'Count': list(tactic_counter.values())
    }).sort_values('Count', ascending=False)

    # Агрегация по сессиям (только то, что нужно)
    df_sessions = df.groupby('session_id').agg({
        'type': 'first',
        'ip': 'first',
        'username': 'first',
        'tactics': 'first',
        'num_commands': 'first',
    }).reset_index()

    all_tactics = sorted(set(t for s in sessions for t in s.get('tactics', [])))

    # Для каждой сессии: бинарный вектор (1 = тактика присутствует)
    tactic_matrix = []
    for s in sessions:
        session_tactics = s.get('tactics', [])
        tactic_matrix.append([1 if t in session_tactics else 0 for t in all_tactics])

    corr_df = pd.DataFrame(tactic_matrix, columns=all_tactics).corr()

    df['date'] = pd.to_datetime(df['cmd_time'])
    daily = df.groupby(df['date'].dt.date).agg({
        'session_id': 'nunique',
        'cmd': 'count'
    }).reset_index()

    return df, df_sessions, tactic_counts, corr_df, sessions, daily