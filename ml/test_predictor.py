
from predictor import predict_message


def test_suspicious_prize_message():
    result = predict_message(
        "Congratulations! You won a prize. "
        "Claim it now by clicking this link."
    )

    assert result["label"] in ("scam", "legitimate")
    assert 0.0 <= result["score"] <= 1.0
    assert result["model_version"] == "baseline-v1"

    print("Prize message:", result)


def test_normal_message():
    result = predict_message(
        "Hi, our class meeting is tomorrow at 10 AM."
    )

    assert result["label"] in ("scam", "legitimate")
    assert 0.0 <= result["score"] <= 1.0

    print("Normal message:", result)


def test_empty_message():
    try:
        predict_message("   ")
    except ValueError:
        print("Empty-message validation passed.")
    else:
        raise AssertionError("Empty messages should be rejected.")


def test_non_string_input():
    try:
        predict_message(123)
    except TypeError:
        print("Non-string validation passed.")
    else:
        raise AssertionError("Non-string inputs should be rejected.")


if __name__ == "__main__":
    test_suspicious_prize_message()
    test_normal_message()
    test_empty_message()
    test_non_string_input()

    print("\nAll predictor interface tests passed.")
