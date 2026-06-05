# models.py
import torch
from torch.utils.data import Dataset

class SessionDataset(Dataset):
    def __init__(self, sessions, encoder, type_to_idx, mlb, max_len=50, device='cuda'):
        self.sessions = sessions
        self.max_len = max_len
        self.emb_dim = encoder.get_embedding_dimension()
        self.embeddings = []
        self.type_labels = []
        self.tactic_labels = []

        for s in sessions:
            commands = [c['cmd'] for c in s['commands'][:max_len]]
            if commands:
                emb = encoder.encode(commands, convert_to_tensor=True, device=device)
                if emb.shape[0] < max_len:
                    pad = torch.zeros(max_len - emb.shape[0], self.emb_dim, device=device)
                    emb = torch.cat([emb, pad])
                else:
                    emb = emb[:max_len]
            else:
                emb = torch.zeros(max_len, self.emb_dim, device=device)

            self.embeddings.append(emb.to(device))
            self.type_labels.append(type_to_idx.get(s['type'], 0))
            self.tactic_labels.append(
                torch.tensor(mlb.transform([s.get('tactics', [])])[0], dtype=torch.float)
            )

        self.embeddings = torch.stack(self.embeddings)
        self.type_labels = torch.tensor(self.type_labels)
        self.tactic_labels = torch.stack(self.tactic_labels)

    def __len__(self):
        return len(self.sessions)

    def __getitem__(self, idx):
        return self.embeddings[idx], self.type_labels[idx], self.tactic_labels[idx]

class RequestDataset(Dataset):
    def __init__(self, payloads, labels, encoder, le, device='cuda'):
        self.embeddings = []
        self.binary_labels = []
        self.multi_labels = []

        for payload_text, label in zip(payloads, labels):
            emb = encoder.encode(payload_text, convert_to_tensor=True, device=device)
            self.embeddings.append(emb.to(device))
            self.binary_labels.append(0 if label == 'norm' else 1)
            self.multi_labels.append(
                torch.tensor(le.transform([label])[0], dtype=torch.long)
            )

        self.embeddings = torch.stack(self.embeddings)
        self.binary_labels = torch.tensor(self.binary_labels)
        self.multi_labels = torch.stack(self.multi_labels)

    def __len__(self):
        return len(self.embeddings)

    def __getitem__(self, idx):
        return self.embeddings[idx], self.binary_labels[idx], self.multi_labels[idx]
