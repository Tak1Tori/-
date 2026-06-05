import csv

# Читаем оба
with open('../Raw_data/payload_full.csv', 'r', encoding='utf-8') as f:
    existing = list(csv.reader(f))

with open('../Raw_data/new_http_payloads.csv', 'r', encoding='utf-8') as f:
    new = list(csv.reader(f))

# Объединяем (заголовок только от первого)
combined = existing + new[1:]

with open('../Data/payload_combined.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f, delimiter=',' , quotechar='"', quoting=1)
    writer.writerows(combined)

print(f"Было: {len(existing)-1}")
print(f"Добавлено: {len(new)-1}")
print(f"Итого: {len(combined)-1}")