import json
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.model_selection import train_test_split

# ─── 1. Загрузка ───
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Device: {device}")

encoder = SentenceTransformer('../command-encoder', device=device)

with open('../Logs/sessions.json', 'r', encoding='utf-8') as f:
    sessions = json.load(f)

print(f"Сессий всего: {len(sessions)}")

# ─── 2. Метки ───
type_to_idx = {'benign': 0, 'malicious': 1, 'mixed': 2}
idx_to_type = {v: k for k, v in type_to_idx.items()}

all_tactics = sorted(set(t for s in sessions for t in s.get('tactics', [])))
mlb = MultiLabelBinarizer()
mlb.fit([all_tactics])

print(f"Типы: {type_to_idx}")
print(f"Тактик: {len(all_tactics)}")


# ─── 3. Датасет ───
class SessionDataset(Dataset):
    def __init__(self, sessions, encoder, max_len=50):
        self.sessions = sessions
        self.encoder = encoder
        self.max_len = max_len
        self.emb_dim = encoder.get_embedding_dimension()

    def __len__(self):
        return len(self.sessions)

    def __getitem__(self, idx):
        s = self.sessions[idx]
        commands = [c['cmd'] for c in s['commands'][:self.max_len]]

        if commands:
            emb = self.encoder.encode(commands, convert_to_tensor=True)
            if emb.shape[0] < self.max_len:
                pad = torch.zeros(self.max_len - emb.shape[0], self.emb_dim, device=emb.device)
                emb = torch.cat([emb, pad])
            else:
                emb = emb[:self.max_len]
        else:
            emb = torch.zeros(self.max_len, self.emb_dim)

        type_label = type_to_idx.get(s['type'], 0)
        tactics_hot = torch.tensor(mlb.transform([s.get('tactics', [])])[0], dtype=torch.float)

        return emb, type_label, tactics_hot


# ─── 4. Модель ───
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


# ─── 5. Загружаем эмбеддинги заранее (фикс GPU/CPU) ───
print("Кодируем сессии...")
all_embeddings = []
all_type_labels = []
all_tactic_labels = []

for i in range(len(sessions)):
    if i % 500 == 0:
        print(f"  {i}/{len(sessions)}")
    s = sessions[i]
    commands = [c['cmd'] for c in s['commands'][:50]]

    if commands:
        emb = encoder.encode(commands, convert_to_tensor=True)
        if emb.shape[0] < 50:
            pad = torch.zeros(50 - emb.shape[0], emb.shape[1], device=emb.device)
            emb = torch.cat([emb, pad])
        else:
            emb = emb[:50]
    else:
        emb = torch.zeros(50, 384)

    all_embeddings.append(emb.cpu())
    all_type_labels.append(type_to_idx.get(s['type'], 0))
    all_tactic_labels.append(torch.tensor(mlb.transform([s.get('tactics', [])])[0], dtype=torch.float))

print("Готово.")

# ─── 6. Разделение ───
embeddings_tensor = torch.stack(all_embeddings)
type_tensor = torch.tensor(all_type_labels)
tactics_tensor = torch.stack(all_tactic_labels)

indices = list(range(len(sessions)))
train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)

train_emb = embeddings_tensor[train_idx]
train_type = type_tensor[train_idx]
train_tactics = tactics_tensor[train_idx]

test_emb = embeddings_tensor[test_idx]
test_type = type_tensor[test_idx]
test_tactics = tactics_tensor[test_idx]

train_dataset = torch.utils.data.TensorDataset(train_emb, train_type, train_tactics)
test_dataset = torch.utils.data.TensorDataset(test_emb, test_type, test_tactics)

train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=16)

# ─── 7. Модель ───
model = SessionClassifier(emb_dim=384, num_types=3, num_tactics=len(all_tactics)).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)
loss_type = nn.CrossEntropyLoss()
loss_tactics = nn.BCELoss()

# ─── 8. Обучение ───
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
}, 'session-classifier.pt')

print("Модель сохранена: session-classifier.pt")