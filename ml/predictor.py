from pathlib import Path

import joblib


# Locate the saved model.
BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "artifacts" / "scam_text_model.joblib"

MODEL_VERSION = "baseline-v1"


# Load the trained model once when this module is imported.
if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Trained model not found at: {MODEL_PATH}. "
        "Run python ml/train.py first."
    )

model = joblib.load(MODEL_PATH)


def predict_message(text: str) -> dict:
    """
    Classify an SMS-like message using the trained model.

    Returns:
        label: 'scam' or 'legitimate'
        score: estimated model probability for the scam class
        model_version: identifier for this model
    """

    if not isinstance(text, str):
        raise TypeError("Message must be a string.")

    if not text.strip():
        raise ValueError("Message cannot be empty.")

    # Predict the message class.
    label = str(model.predict([text])[0])

    # Obtain the classifier's estimated probability for each class.
    probabilities = model.predict_proba([text])[0]

    # Find the position corresponding to the scam class.
    classes = list(model.classes_)
    scam_index = classes.index("scam")

    scam_score = float(probabilities[scam_index])

    return {
        "label": label,
        "score": round(scam_score, 4),
        "model_version": MODEL_VERSION,
    }


if __name__ == "__main__":
    test_messages = [
        (
            "Congratulations! You won a prize. "
            "Claim it now by clicking this link."
        ),
        "Hi, our class meeting is tomorrow at 10 AM.",
    ]

    for message in test_messages:
        result = predict_message(message)

        print("\nMessage:", message)
        print("Prediction:", result)
        