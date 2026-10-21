from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# 1. Set project paths
BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "data" / "SMSSpamCollection"
ARTIFACT_DIR = BASE_DIR / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "scam_text_model.joblib"


# 2. Load and prepare the dataset
def load_dataset():
    print("\nLoading dataset...")

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}\n"
            "Place SMSSpamCollection inside ml/data/."
        )

    data = pd.read_csv(
        DATASET_PATH,
        sep="\t",
        header=None,
        names=["label", "message"],
        encoding="utf-8",
    )

    data = data.dropna(subset=["label", "message"])

    data["label"] = data["label"].str.strip().str.lower()
    data["message"] = data["message"].str.strip()

    # Keep only the original dataset's two classes.
    data = data[data["label"].isin(["ham", "spam"])]

    # Remove empty messages.
    data = data[data["message"] != ""]

    # Convert original labels into our project's labels.
    data["label"] = data["label"].map({
        "ham": "legitimate",
        "spam": "scam",
    })

    # Remove duplicate message-label pairs.
    data = data.drop_duplicates(subset=["message", "label"])

    # Remove messages that have conflicting labels.
    conflicting = (
        data.groupby("message")["label"].nunique()
    )

    conflicting_messages = conflicting[
        conflicting > 1
    ].index

    data = data[
        ~data["message"].isin(conflicting_messages)
    ]

    if data["label"].nunique() != 2:
        raise ValueError(
            "The dataset must contain both classes."
        )

    print(f"Usable messages: {len(data)}")

    print("\nClass distribution:")
    print(data["label"].value_counts())

    return data


# 3. Divide the data into training and testing sets.
def split_dataset(data):
    X = data["message"]
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print(f"\nTraining messages: {len(X_train)}")
    print(f"Testing messages: {len(X_test)}")

    return X_train, X_test, y_train, y_test


# 4. Build the machine-learning model.
def build_model():
    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                max_features=30000,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])

    return model


# 5. Train and evaluate the model.
def train_and_evaluate(
    model,
    X_train,
    X_test,
    y_train,
    y_test,
):
    print("\nTraining model...")

    model.fit(X_train, y_train)

    print("Training completed!")

    predictions = model.predict(X_test)

    print("\n" + "=" * 50)
    print("MODEL EVALUATION")
    print("=" * 50)

    print(
        f"\nAccuracy: "
        f"{accuracy_score(y_test, predictions):.4f}"
    )

    print("\nClassification report:")

    print(
        classification_report(
            y_test,
            predictions,
            labels=["legitimate", "scam"],
            zero_division=0,
        )
    )

    print("\nConfusion matrix:")
    print("Class order: legitimate, scam")

    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=["legitimate", "scam"],
        )
    )

    return model


# 6. Save the trained model.
def save_model(model):
    ARTIFACT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(model, MODEL_PATH)

    print(f"\nModel saved successfully!")
    print(f"Location: {MODEL_PATH}")


# 7. Run the complete training process.
def main():
    data = load_dataset()

    X_train, X_test, y_train, y_test = split_dataset(data)

    model = build_model()

    model = train_and_evaluate(
        model,
        X_train,
        X_test,
        y_train,
        y_test,
    )

    save_model(model)

    print("\nYour AI model training process is complete!")


if __name__ == "__main__":
    main()
    