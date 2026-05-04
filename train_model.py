import argparse
import re
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


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


def load_dataset(csv_path: Path) -> tuple[list[str], list[str]]:
    df = pd.read_csv(csv_path)
    if "commands" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain 'commands' and 'label' columns")

    texts = [normalize_commands(value) for value in df["commands"].astype(str)]
    labels = df["label"].astype(str).tolist()
    return texts, labels


def build_pipeline() -> Pipeline:
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 3),
                    min_df=1,
                    sublinear_tf=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                ),
            ),
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train a simple command-sequence attack classifier."
    )
    parser.add_argument(
        "--data",
        default="data/examples.csv",
        help="Path to CSV dataset with columns: label, commands",
    )
    parser.add_argument(
        "--output",
        default="artifacts/command_attack_model.joblib",
        help="Where to save the trained model",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.3,
        help="Test split size for quick validation",
    )
    args = parser.parse_args()

    data_path = Path(args.data)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    texts, labels = load_dataset(data_path)
    pipeline = build_pipeline()

    enough_data_for_split = len(set(labels)) > 1 and len(texts) >= 10
    if enough_data_for_split:
        x_train, x_test, y_train, y_test = train_test_split(
            texts,
            labels,
            test_size=args.test_size,
            random_state=42,
            stratify=labels,
        )
        pipeline.fit(x_train, y_train)
        predictions = pipeline.predict(x_test)
        print("Validation report:")
        print(classification_report(y_test, predictions, zero_division=0))
    else:
        pipeline.fit(texts, labels)
        print("Dataset too small for validation split; trained on full dataset.")

    pipeline.fit(texts, labels)
    joblib.dump(pipeline, output_path)
    print(f"Model saved to: {output_path}")


if __name__ == "__main__":
    main()
