import json
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.model_selection import train_test_split

# Загрузка
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Device: {device}")

encoder = SentenceTransformer('../command-encoder', device='cuda')

with open('../Test/sessions.json', 'r', encoding='utf-8') as f:
    sessions = json.load(f)

print(f"Сессий всего: {len(sessions)}")

# Метки
type_to_idx = {'benign': 0, 'malicious': 1, 'mixed': 2}
idx_to_type = {v: k for k, v in type_to_idx.items()}

all_tactics = sorted(set(t for s in sessions for t in s.get('tactics', [])))
mlb = MultiLabelBinarizer()
mlb.fit([all_tactics])

print(f"Типы: {type_to_idx}")
print(f"Тактик: {len(all_tactics)}")


# Датасет
class SessionDataset(Dataset):
    def __init__(self, sessions, encoder, max_len=50, device='cpu'):
        self.sessions = sessions
        self.max_len = max_len
        self.emb_dim = encoder.get_embedding_dimension()

        # Кодируем все сессии сразу при инициализации
        self.embeddings = []
        self.type_labels = []
        self.tactic_labels = []

        for s in sessions:
            commands = [c['cmd'] for c in s['commands'][:max_len]]
            if commands:
                emb = encoder.encode(commands, convert_to_tensor=True, device=device)
                if emb.shape[0] < max_len:
                    pad = torch.zeros(max_len - emb.shape[0], self.emb_dim)
                    emb = torch.cat([emb, pad])
                else:
                    emb = emb[:max_len]
            else:
                emb = torch.zeros(max_len, self.emb_dim)

            self.embeddings.append(emb.cpu())
            self.type_labels.append(type_to_idx.get(s['type'], 0))
            self.tactic_labels.append(
                torch.tensor(mlb.transform([s.get('tactics', [])])[0], dtype=torch.float)
            )

        # Стекуем в тензоры
        self.embeddings = torch.stack(self.embeddings)
        self.type_labels = torch.tensor(self.type_labels)
        self.tactic_labels = torch.stack(self.tactic_labels)

    def __len__(self):
        return len(self.sessions)

    def __getitem__(self, idx):
        return self.embeddings[idx], self.type_labels[idx], self.tactic_labels[idx]


# Модель
class SessionClassifier(nn.Module):
    def __init__(self, emb_dim=384, num_types=3, num_tactics=None):
        super().__init__()
        self.attention = nn.MultiheadAttention(emb_dim, num_heads=4, batch_first=True)
        self.ln = nn.LayerNorm(emb_dim)
        self.head_type = nn.Linear(emb_dim, num_types)
        self.head_tactics = nn.Linear(emb_dim, num_tactics)

    def forward(self, x):
        attn, _ = self.attention(x, x, x)
        x = self.ln(attn + x)
        pooled = x.mean(dim=1)
        return self.head_type(pooled), torch.sigmoid(self.head_tactics(pooled))


print("Готово.")

# Разделение
dataset = SessionDataset(sessions, encoder)

train_data, test_data = train_test_split(dataset, test_size=0.2, random_state=42)

train_loader = DataLoader(train_data, batch_size=16, shuffle=True)
test_loader = DataLoader(test_data, batch_size=16)

# Модель
model = SessionClassifier(emb_dim=384, num_types=3, num_tactics=len(all_tactics)).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)
loss_type = nn.CrossEntropyLoss()
loss_tactics = nn.BCELoss()

# Обучение
epochs = 10
for epoch in range(epochs):
    model.train()
    total_loss = 0
    for emb, t_label, t_hot in train_loader:
        emb, t_label, t_hot = emb.to(device), t_label.to(device), t_hot.to(device)
        optimizer.zero_grad()
        out_type, out_tactics = model(emb)
        loss = loss_type(out_type, t_label) + loss_tactics(out_tactics, t_hot)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    model.eval()
    correct = 0
    total = 0
    with torch.no_grad():
        for emb, t_label, _ in test_loader:
            emb, t_label = emb.to(device), t_label.to(device)
            out_type, _ = model(emb)
            correct += (out_type.argmax(1) == t_label).sum().item()
            total += t_label.size(0)

    print(f"Epoch {epoch + 1}/{epochs} | Loss: {total_loss / len(train_loader):.4f} | Acc: {correct / total:.2%}")

# ─── 9. Сохранение ───
torch.save({
    'model_state_dict': model.state_dict(),
    'all_tactics': all_tactics,
    'type_to_idx': type_to_idx,
    'mlb_classes': mlb.classes_.tolist()
}, '../session-classifier.pt')

print("Модель сохранена: session-classifier.pt")