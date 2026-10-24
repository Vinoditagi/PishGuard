
from ml.predictor import predict_message


def main():
    message = "Congratulations! You won a prize. Claim it now."

    result = predict_message(message)

    # Check the response contract expected by the backend.
    assert result["label"] in ("scam", "legitimate")
    assert isinstance(result["score"], float)
    assert 0.0 <= result["score"] <= 1.0
    assert result["model_version"] == "baseline-v1"

    print("ML integration import: PASSED")
    print("Backend response:", result)


if __name__ == "__main__":
    main()
