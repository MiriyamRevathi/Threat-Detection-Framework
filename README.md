<div align="center">
### AI-Based Cyber Threat Detection Framework###

Enterprise AI-powered Cyber Threat Detection Platform built using **Flask**, **Machine Learning**, and the **CICIDS2017 Dataset**.

<p>
<a href="https://github.com/MiriyamRevathi/Threat-Detection-Framework">

# 📖 About

SentinelX is an AI-powered Cyber Threat Detection Framework that analyzes uploaded network traffic datasets and predicts malicious activity using a Random Forest model. The application provides an interactive dashboard, visual analytics, and downloadable reports through a clean Flask web interface.

---

# ✨ Features

- AI-powered Threat Detection
- Random Forest Classifier
- CSV Upload
- Interactive Dashboard
- Threat Distribution Charts
- Demo Dataset Support
- Downloadable Reports
- Responsive Dark UI

---

# 🤖 Machine Learning

- Algorithm: Random Forest Classifier
- Dataset: CICIDS2017
- Backend: Flask
- Language: Python
- Libraries: Scikit-learn, Pandas, NumPy, Plotly, Matplotlib

---

# 🛠️ Tech Stack

| Category | Technology |
|---|---|
| Backend | Flask |
| ML | Scikit-learn |
| Frontend | HTML, CSS, JavaScript |
| Data | Pandas, NumPy |
| Charts | Plotly, Matplotlib |

---

# 📂 Project Structure

```text
Threat-Detection-Framework/
├── app.py
├── predict.py
├── train_model.py
├── requirements.txt
├── requirements.lock
├── pyproject.toml
├── pytest.ini
├── poetry.lock
├── Pipfile.lock
├── cyber_threat/
│   ├── core/
│   ├── models/
│   ├── preprocessing/
│   ├── threat_intel/
│   ├── alerting/
│   ├── siem/
│   ├── analytics/
│   ├── visualization/
│   ├── api/
│   └── utils/
├── tests/
│   ├── test_app.py
│   ├── test_predict.py
│   ├── test_core.py
│   ├── test_models.py
│   ├── test_preprocessing.py
│   ├── test_alerting.py
│   ├── test_siem.py
│   ├── test_analytics.py
│   └── test_api.py
├── models/
├── templates/
├── static/
├── sample_data/
└── README.md
```

---

# 🚀 Installation & Lockfiles

Install dependencies using standard manifest or reproducible lockfile:

```bash
git clone https://github.com/MiriyamRevathi/Threat-Detection-Framework.git
cd Threat-Detection-Framework

# Install from locked dependencies
pip install -r requirements.lock

# Run the Flask Application
python app.py
```

---

# 🧪 Testing & Coverage

Execute the automated test suite with coverage report:

```bash
# Run pytest test suite
pytest

# Run pytest with code coverage report
pytest --cov=cyber_threat --cov=app --cov=predict
```

---

# 💻 Usage

1. Launch the application.
2. Upload a CSV dataset or select a demo dataset.
3. Run AI threat detection prediction.
4. View analytics dashboard.
5. Download reports.

---

# 👨‍💻 Developer

**Miriyam Revathi**

GitHub: https://github.com/MiriyamRevathi

---

<div align="center">

Made with ❤️ by **Miriyam Revathi**

</div>
