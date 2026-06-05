import os
import csv
from config import TARGET_DIRS, PAYLOADS_ALL_PATH

def extract_files(base_path, target_dirs):
    payloads =[]

    for d in target_dirs:
        dir_path = os.path.join(base_path, d)

        if os.path.exists(dir_path) and os.path.isdir(dir_path):
            print(f"\nScanning: {d}")

            # Рекурсивный обход всех подпапок (Intruder, Files и т.д.)
            for root, dirs, files in os.walk(dir_path):
                for file_name in files:
                    # Проверяем расширение
                    if file_name.lower().endswith(('.txt', '.svg')):
                        full_path = os.path.join(root, file_name)
                        payloads.append([{'payload': d }, {'url': full_path}])
                        print(f"  [+] Found: {file_name}")
        else:
            print(f"\n[!] Directory not found: {d}")

    return payloads  # Важно вернуть результат

def extract_http_payloads(target_dirs):
    payloads = extract_files(PAYLOADS_ALL_PATH, TARGET_DIRS)
    with open('../Raw_data/new_http_payloads.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=1)
        writer.writerow(['payload', 'length', 'attack_type', 'label'])
        for payload, files in payloads:
            files = files.get('url')
            print(files)
            if files.lower().endswith('.txt'):
                with open(files, 'r', encoding='utf-8') as f:
                    for line in f:
                        cleaned_line = line.strip()
                        if cleaned_line:
                            print(cleaned_line)
                            writer.writerow([cleaned_line, len(cleaned_line), payload.get('payload'), 'anom'])

            elif files.lower().endswith('.svg'):
                with open(files, 'r', encoding='utf-8', errors='ignore') as f:
                    full_svg = f.read()
                    one_line_svg = " ".join(full_svg.split())
                    if one_line_svg:
                        writer.writerow([one_line_svg, len(one_line_svg), payload.get('payload'), 'anom'])