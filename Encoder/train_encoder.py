import json
from sentence_transformers import SentenceTransformer, InputExample
from sentence_transformers.sentence_transformer import losses
from torch.utils.data import DataLoader

def train_command_encoder():
    # 1. Загружаем легитимные команды
    with open('data/terminal_cmds.jsonl', 'r', encoding='utf-8') as f:
        commands = [json.loads(line) for line in f if line.strip()]

    print(f"Всего команд: {len(commands)}")

    # 2. Пары command - description
    train_examples = []
    skipped = 0

    for cmd in commands:
        command_text = cmd.get('command', '').strip()
        description = cmd.get('description', '').strip()

        if command_text and description:
            train_examples.append(InputExample(texts=[command_text, description]))
        else:
            skipped += 1

    print(f"Пар для обучения: {len(train_examples)}")
    print(f"Пропущено (нет description): {skipped}")

    # 3. Модель
    model = SentenceTransformer('all-MiniLM-L6-v2')

    train_dataloader = DataLoader(train_examples, shuffle=True, batch_size=32)
    train_loss = losses.MultipleNegativesRankingLoss(model)

    # 4. Обучение
    model.fit(
        train_objectives=[(train_dataloader, train_loss)],
        epochs=10,
        warmup_steps=int(len(train_dataloader) * 0.1),
        show_progress_bar=True
    )
    # 5. Сохраняем
    model.save('command-encoder')
    print("Энкодер сохранён в command-encoder/")

if __name__ == '__main__':
    train_command_encoder()