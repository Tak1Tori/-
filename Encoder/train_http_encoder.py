import csv
from sentence_transformers import SentenceTransformer, InputExample
from sentence_transformers.sentence_transformer import losses
from torch.utils.data import DataLoader

def tran_http_encdoer():
    # Загружаем payload_combined.csv (все типы атак + norm)
    payloads = []
    with open('../Data/payload_combined.csv', 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  # пропустить заголовок
        for row in reader:
            if len(row) >= 4:
                payload_text = row[0].strip()
                label = row[2].strip()
                if payload_text and label:
                    payloads.append({'payload': payload_text, 'type': label})

    print(f"Всего payloads: {len(payloads)}")

    # Описания для каждого типа атаки
    TYPE_DESCRIPTIONS = {
        'sqli': 'SQL Injection attack payload that manipulates database queries',
        'xss': 'Cross-Site Scripting attack payload that injects malicious scripts',
        'cmdi': 'Command Injection attack payload that executes system commands',
        'path-traversal': 'Path Traversal attack that accesses files outside web root',
        'ssrf': 'Server-Side Request Forgery payload that exploits server requests',
        'xxe': 'XML External Entity attack payload that exploits XML parsers',
        'lfi': 'Local File Inclusion payload that includes local files',
        'nosqli': 'NoSQL Injection attack payload for NoSQL databases',
        'norm': 'Normal safe parameter value',
    }

    # Пары payload → описание типа
    train_examples = []
    skipped = 0

    for p in payloads:
        payload_text = p['payload']
        ptype = p['type']
        description = TYPE_DESCRIPTIONS.get(ptype, f'{ptype} payload')

        if payload_text and description:
            train_examples.append(InputExample(texts=[payload_text, description]))
        else:
            skipped += 1

    print(f"Пар для обучения: {len(train_examples)}")
    print(f"Пропущено: {skipped}")

    # Модель
    model = SentenceTransformer('all-MiniLM-L6-v2')
    train_dataloader = DataLoader(train_examples, shuffle=True, batch_size=32)
    train_loss = losses.MultipleNegativesRankingLoss(model)

    model.fit(
        train_objectives=[(train_dataloader, train_loss)],
        epochs=10,
        warmup_steps=int(len(train_dataloader) * 0.1),
        show_progress_bar=True
    )

    model.save('../http-encoder')
    print("HTTP-энкодер сохранён в http-encoder/")

if __name__ == "__main__":
    tran_http_encdoer()