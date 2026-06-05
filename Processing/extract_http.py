from config import RAW_WEB, WEB

def extract_payloads():
    with open(RAW_WEB, 'r') as f:
        payloads = f.read()
    new_file = []

    for i in range(4, len(payloads)):
        if payloads[i] == ',' and payloads[i - 1] == '}' and payloads[i + 1] == '\n':
            new_file.append('\n')
            continue
        if payloads[i] != '\n':
            new_file.append(payloads[i])
        if payloads[i] == len(payloads):
            break
    new_file = ''.join(new_file).strip()
    print(new_file)
    with open(WEB, 'w') as f:
        f.write(new_file)