import json
tactics = []
with open('../Logs/sessions.json', 'r', encoding='utf-8') as f:
    sessions = json.load(f)

for session in sessions:
    tactics.append(session.get('tactics'))
print(tactics)