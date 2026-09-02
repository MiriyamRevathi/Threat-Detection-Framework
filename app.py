from flask import Flask, render_template, request
import os
from predict import predict_attacks

app = Flask(__name__)

# ===========================
# Configuration
# ===========================

UPLOAD_FOLDER = "uploads"
SAMPLE_FOLDER = "sample_data"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ===========================
# Helper Function
# ===========================

def show_prediction(filepath, filename):
    """
    Runs prediction and renders result page.
    """

    results = predict_attacks(filepath)

    return render_template(
        "result.html",
        filename=filename,
        total_records=results["total_records"],
        normal_records=results["normal_records"],
        threat_records=results["threat_records"],
        attack_counts=results["attack_counts"],
        risk_level=results["risk_level"],
        threat_score=results["threat_score"],
        prediction_time=results["prediction_time"],
        model_name=results["model_name"],
        accuracy=results["accuracy"]
    )


# ===========================
# Home Page
# ===========================

@app.route("/")
def home():
    return render_template("index.html")


# ===========================
# Upload CSV
# ===========================

@app.route("/upload", methods=["POST"])
def upload():

    if "file" not in request.files:
        return "No file selected."

    file = request.files["file"]

    if file.filename == "":
        return "Please choose a CSV file."

    if not file.filename.lower().endswith(".csv"):
        return "Only CSV files are allowed."

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        file.filename
    )

    file.save(filepath)

    return show_prediction(filepath, file.filename)


# ===========================
# Demo Dataset
# ===========================

@app.route("/demo/<dataset>")
def demo(dataset):

    sample_files = {
        "normal": "normal.csv",
        "dos": "dos.csv",
        "ddos": "ddos.csv",
        "portscan": "portscan.csv",
        "mixed": "mixed.csv"
    }

    if dataset not in sample_files:
        return "Invalid demo dataset.", 404

    filepath = os.path.join(
        SAMPLE_FOLDER,
        sample_files[dataset]
    )

    return show_prediction(
        filepath,
        sample_files[dataset]
    )


# ===========================
# Run Application
# ===========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)