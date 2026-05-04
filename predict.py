import argparse
import re
from pathlib import Path

import joblib


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATH_RE = re.compile(r"(?:[A-Za-z]:\\[^\s]+|/[^\s]+)")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{16,64}\b")


def normalize_commands(text: str) -> str:
    text = text.lower()
    text = IPV4_RE.sub(" IP ", text)
    text = PATH_RE.sub(" PATH ", text)
    text = HASH_RE.sub(" HASH ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Predict attack class from a sequence of commands."
    )
    parser.add_argument(
        "--model",
        default="artifacts/command_attack_model.joblib",
        help="Path to the trained joblib model",
    )
    parser.add_argument(
        "commands",
        nargs="+",
        help='Command sequence, for example: "whoami net user ipconfig"',
    )
    args = parser.parse_args()

    model_path = Path(args.model)
    model = joblib.load(model_path)

    raw_text = " ".join(args.commands)
    normalized_text = normalize_commands(raw_text)
    predicted_label = model.predict([normalized_text])[0]

    probabilities = None
    if hasattr(model, "predict_proba"):
        class_names = model.classes_
        scores = model.predict_proba([normalized_text])[0]
        probabilities = sorted(
            zip(class_names, scores), key=lambda item: item[1], reverse=True
        )

    print(f"Input: {raw_text}")
    print(f"Predicted class: {predicted_label}")
    if probabilities:
        print("Top probabilities:")
        for label, score in probabilities[:3]:
            print(f"  {label}: {score:.3f}")


if __name__ == "__main__":
    main()
