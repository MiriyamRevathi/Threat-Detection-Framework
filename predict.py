import time
import pandas as pd
import joblib


# ==========================================
# Load Model (Only Once)
# ==========================================

model = joblib.load("models/random_forest_model.pkl")
label_encoder = joblib.load("models/label_encoder.pkl")


# ==========================================
# Prediction Function
# ==========================================

def predict_attacks(filepath):

    start_time = time.time()

    # ------------------------------
    # Read CSV
    # ------------------------------

    data = pd.read_csv(filepath)

    total_records = len(data)

    # ------------------------------
    # Remove Target Column
    # ------------------------------

    if "Attack Type" in data.columns:
        data = data.drop(columns=["Attack Type"])

    # ------------------------------
    # Prediction
    # ------------------------------

    predictions = model.predict(data)

    predictions = label_encoder.inverse_transform(predictions)

    # ------------------------------
    # Attack Counts
    # ------------------------------

    attack_counts = (
        pd.Series(predictions)
        .value_counts()
        .sort_values(ascending=False)
        .to_dict()
    )

    # ------------------------------
    # Normal / Threat Counts
    # ------------------------------

    normal_records = attack_counts.get("Normal Traffic", 0)

    threat_records = total_records - normal_records

    # ------------------------------
    # Threat Score (%)
    # ------------------------------

    threat_score = round(
        (threat_records / total_records) * 100,
        2
    )

    # ------------------------------
    # Risk Level
    # ------------------------------

    if threat_score < 5:
        risk_level = "LOW"

    elif threat_score < 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"

    # ------------------------------
    # Prediction Time
    # ------------------------------

    prediction_time = round(
        time.time() - start_time,
        3
    )

    # ------------------------------
    # Return Everything
    # ------------------------------

    return {

        "total_records": total_records,

        "normal_records": normal_records,

        "threat_records": threat_records,

        "attack_counts": attack_counts,

        "risk_level": risk_level,

        "threat_score": threat_score,

        "prediction_time": prediction_time,

        "model_name": "Random Forest",

        "accuracy": "99.8%"

    }