import torch
from sentence_transformers import SentenceTransformer
from models import RequestClassifier

_model = None
_encoder = None
_checkpoint = None
_device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

def load_model(model_path='../http-classifier.pt'):
    global _model, _encoder, _checkpoint, _device
    if _model is not None:
        return _model, _encoder, _checkpoint

    _encoder = SentenceTransformer('../Http-encoder', device=_device)
    _checkpoint = torch.load(model_path, map_location=_device)
    _model = RequestClassifier(
        emb_dim=384,
        num_types=len(_checkpoint['classes'])
    ).to(_device)
    _model.load_state_dict(_checkpoint['model_state_dict'])
    _model.eval()

    return _model, _encoder, _checkpoint

def predict(payloads):

    model, encoder, checkpoint = load_model()
    classes = checkpoint['classes']
    # Свежие примеры, которых нет в датасете
    results = []

    for payload in payloads:
        emb = encoder.encode(payload, convert_to_tensor=True, device=_device)
        with torch.no_grad():
            out_bin, out_type = model(emb.to(_device))

        is_attack = out_bin.item() > 0.5
        attack_type = classes[out_type.argmax().item()] if is_attack else 'norm'

        results.append({
            'payload': payload,
            'is_attack': is_attack,
            'type': attack_type,
            'confidence': round(out_bin.item(), 3)
        })

    return results

if __name__ == '__main__':
    test_cases = [
        ("' OR 1=1 --", "sqli"),
        ("<script>alert('xss')</script>", "xss"),
        ("; cat /etc/passwd", "cmdi"),
        ("http://169.254.169.254/latest/meta-data/", "ssrf"),
        ("normal user input", "norm"),
        ("john.doe@email.com", "norm"),
        ("../../etc/passwd", "path-traversal"),
        ("' OR '1'='1", 'sqli'),
        ("' UNION SELECT * FROM users--", "sqli"),
        ("../../etc/passwd", "path-traversal"),
        ("action=heartbeat", "heartbeat"),
        ("' OR '1'='1", 'sqli'),
        ("<script>alert(1)</script>", "xss"),
        ("../../etc/passwd", 'path-traversal'),
        ("heartbeat", 'norm'),
        ("2 20", 'norm'),
        ("zxc", 'norm'),
        ("clown", 'norm'),
        ("wass+up boy", 'norm'),
        ('/etc/passwd', 'path-traversal'),
        ('/root/bin/python3', 'path-traversal'),
        ("{${sleep(hexdec(dechex(20)))}}", 'cmdi' )


    ]
    results = predict([p for p, _ in test_cases])

    for (payload, expected), result in zip(test_cases, results):
        status = "Win" if (expected == 'norm' and not result['is_attack']) or (
                    expected != 'norm' and result['is_attack']) else "Lose"
        print(
            f"{status} {payload[:50]:<50} | expected: {expected:<15} | pred: {result['type']:<15} | conf: {result['confidence']:.3f}")