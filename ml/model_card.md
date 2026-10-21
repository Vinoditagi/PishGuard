
# AI Scam & Phishing Detector — Model Card

## 1. Model Overview

- Model name: SMS Scam Text Classifier
- Version: baseline-v1
- Task: Binary text classification
- Algorithm: Logistic Regression
- Text representation: TF-IDF
- Framework: Python and scikit-learn

## 2. Purpose

The model classifies text messages as either scam-like
or legitimate-like based on patterns learned from labelled
SMS examples.

It is an initial baseline for the AI Scam & Phishing
Detector project.

It does not independently verify whether a message or
URL is safe.

## 3. Dataset

- Dataset: UCI SMS Spam Collection
- Source: https://archive.ics.uci.edu/dataset/228/sms+spam+collection
- Original labels: ham and spam
- Project labels: legitimate and scam
- Usable examples after cleaning: 5,158
- Legitimate examples: 4,516
- Scam-labelled examples: 642

The original spam label is mapped to scam for this
project's initial baseline. Spam and phishing are not
identical categories.

## 4. Training Configuration

- Training/test split: 80% / 20%
- Random state: 42
- TF-IDF n-grams: unigrams and bigrams
- Maximum TF-IDF features: 30,000
- Classifier: Logistic Regression
- Maximum iterations: 1,000
- Class weighting: balanced

## 5. Evaluation Results

The initial held-out test results were:

- Test examples: 1,032
- Accuracy: 97.67%

Scam class:
- Precision: approximately 88%
- Recall: approximately 94%
- F1-score: approximately 91%

Legitimate class:
- Precision: approximately 99%
- Recall: approximately 98%
- F1-score: approximately 99%

Confusion matrix (actual rows, predicted columns):

                 Legitimate  Scam
Actual legitimate     888      16
Actual scam             8     120

These results apply to the held-out portion of the SMS
Spam Collection dataset, not to all real-world scams.

## 6. Limitations

- Training data consists of SMS spam and legitimate messages.
- The model has not been established as a reliable phishing URL detector.
- It may fail on new scam techniques, unfamiliar wording,
  other languages, or messages unlike its training data.
- Random train/test splitting may produce optimistic results
  if similar messages occur in both sets.
- Predicted probabilities have not been calibrated or
  validated as real-world scam probabilities.
- A legitimate prediction does not prove a message is safe.

## 7. Intended Use

Use this model as one signal in a broader detection workflow.

The application should combine its output with other relevant
signals, explain uncertainty, and provide safe recommendations.

Do not use this model as the sole basis for security decisions.

## 8. Model Artifact

Saved model:
artifacts/scam_text_model.joblib

Prediction interface:
predictor.py — predict_message(text)

## 9. Future Improvements

- Evaluate on a separate, suitable scam/phishing dataset.
- Inspect false positives and false negatives.
- Test for duplicate and near-duplicate data leakage.
- Assess probability calibration and threshold selection.
- Expand coverage to relevant scam categories and languages.
- Integrate URL analysis as a separate component.
