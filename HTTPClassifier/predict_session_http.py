import torch
import json
from sentence_transformers import SentenceTransformer
from models import HTTPSessionClassifier


_model = None
_encoder = None
_checkpoint = None
_device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

def load_model(model_path='../http-session-classifier.pt'):
    global _model, _encoder, _checkpoint, _device
    if _model is not None:
        return _model, _encoder, _checkpoint

    _encoder = SentenceTransformer('../Http-encoder', device=_device)
    _checkpoint = torch.load(model_path, map_location=_device)
    _model = HTTPSessionClassifier(
        num_types=3,
        num_attacks=len(_checkpoint['all_attack_types'])
    ).to(_device)
    _model.load_state_dict(_checkpoint['model_state_dict'])
    _model.eval()

    return _model, _encoder, _checkpoint


def predict_http_session(requests, max_len=50, threshold=0.5):
    """Модель сессии на эмбеддингах (SSH-подобная)."""
    payloads = [r.get('raw_payload', r.get('payload', '')) for r in requests[:max_len]]
    _model, _encoder, _checkpoint = load_model()

    all_attack_types = _checkpoint['all_attack_types']
    type_to_idx = _checkpoint['type_to_idx']
    idx_to_type = {v: k for k, v in type_to_idx.items()}

    if payloads:
        emb = _encoder.encode(payloads, convert_to_tensor=True, device=_device)
        if emb.shape[0] < max_len:
            pad = torch.zeros(max_len - emb.shape[0], emb.shape[1], device=_device)
            emb = torch.cat([emb, pad])
    else:
        emb = torch.zeros(max_len, 384, device=_device)

    emb = emb.unsqueeze(0)  # (1, N, 384)

    with torch.no_grad():
        out_type, out_attack = _model(emb)

    type_idx = out_type.argmax(1).item()
    session_type = idx_to_type[type_idx]

    probs = out_attack[0].cpu().tolist()
    attacks = [all_attack_types[i] for i, p in enumerate(probs) if p > threshold]

    return {
        'type': session_type,
        'attack_types': attacks,
        'probabilities': {all_attack_types[i]: round(p, 3) for i, p in enumerate(probs)}
    }


# Тест
if __name__ == '__main__':

    legit_session = [
        {"raw_payload": "heartbeat abc123"},
        {"raw_payload": "edit 42"},
        {"raw_payload": "2 20"},
        {"raw_payload": "zxc"},
        {"raw_payload": ""}

    ]

    mal_session = [
        {"raw_payload": "heartbeat abc123"},
        {"raw_payload": "' OR '1'='1"},
        {"raw_payload": "' UNION SELECT * FROM users--"},
    ]

    mixed_session = [
        {"raw_payload": "correct password"},
        {"raw_payload": "2 20"},
        {"raw_payload": "../../etc/passwd"},
        {"raw_payload": "date desc"},
        {"raw_payload": "{${sleep(hexdec(dechex(20)))}}"}
    ]

    print("Легитимная:", json.dumps(predict_http_session(legit_session), indent=2, ensure_ascii=False))
    print("\nВредоносная:", json.dumps(predict_http_session(mal_session), indent=2, ensure_ascii=False))
    print("\nСмешанная:", json.dumps(predict_http_session(mixed_session), indent=2, ensure_ascii=False))