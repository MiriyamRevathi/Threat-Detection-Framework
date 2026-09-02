import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)
import joblib

# ==========================================
# LOAD DATASET
# ==========================================

print("=" * 60)
print("Loading Dataset...")
print("=" * 60)

df = pd.read_csv("data/raw/cicids2017_cleaned.csv")

print("\nDataset Loaded Successfully!")

# ==========================================
# BASIC INFORMATION
# ==========================================

print("\nShape of Dataset")
print(df.shape)

print("\nColumns")
print(df.columns.tolist())

print("\nFirst 5 Rows")
print(df.head())

print("\nData Types")
print(df.dtypes)

# ==========================================
# MISSING VALUES
# ==========================================

print("\nMissing Values")
print(df.isnull().sum())

# ==========================================
# DUPLICATE VALUES
# ==========================================

duplicates = df.duplicated().sum()

print("\nDuplicate Rows:", duplicates)

# ==========================================
# ATTACK TYPE DISTRIBUTION
# ==========================================

print("\nAttack Type Distribution")
print(df["Attack Type"].value_counts())

# ==========================================
# REMOVE DUPLICATES
# ==========================================

df = df.drop_duplicates()

print("\nShape after removing duplicates:")
print(df.shape)

# ==========================================
# RANDOM SAMPLING
# ==========================================

df = df.sample(n=125000, random_state=42).reset_index(drop=True)

print("\nShape after sampling:")
print(df.shape)

# ==========================================
# FEATURES & TARGET
# ==========================================

X = df.drop("Attack Type", axis=1)
Y = df["Attack Type"]

print("\nFeatures Shape:", X.shape)
print("Target Shape:", Y.shape)

# ==========================================
# LABEL ENCODING
# ==========================================

label_encoder = LabelEncoder()

Y = label_encoder.fit_transform(Y)

print("\nLabel Encoding Completed!")

print("\nClasses:")
for index, label in enumerate(label_encoder.classes_):
    print(f"{label} --> {index}")

# ==========================================
# TRAIN TEST SPLIT
# ==========================================

X_train, X_test, Y_train, Y_test = train_test_split(
    X,
    Y,
    test_size=0.2,
    random_state=42,
    stratify=Y,
    )

print("\nTrain-Test Split Completed!")

print("\nTraining Features :", X_train.shape)
print("Testing Features  :", X_test.shape)
print("Training Target   :", Y_train.shape)
print("Testing Target    :", Y_test.shape)

# ==========================================
# TRAIN RANDOM FOREST MODEL
# ==========================================

print("\nTraining Random Forest Model...")

Trixie = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

Trixie.fit(X_train, Y_train)

print("Model Trained Successfully!")
# ==========================================
# PREDICT TEST DATA
# ==========================================

print("\nMaking Predictions...")

Y_pred = Trixie.predict(X_test)

print("Prediction Completed!")

# ==========================================
# MODEL ACCURACY
# ==========================================

accuracy = accuracy_score(Y_test, Y_pred)

print("\n" + "=" * 60)
print("MODEL ACCURACY")
print("=" * 60)
print(f"Accuracy : {accuracy:.4f}")
print(f"Accuracy : {accuracy * 100:.2f}%")

# ==========================================
# CONFUSION MATRIX
# ==========================================

cm = confusion_matrix(Y_test, Y_pred)

print("\n" + "=" * 60)
print("CONFUSION MATRIX")
print("=" * 60)
print(cm)

# ==========================================
# CLASSIFICATION REPORT
# ==========================================

print("\n" + "=" * 60)
print("CLASSIFICATION REPORT")
print("=" * 60)

print(
    classification_report(
        Y_test,
        Y_pred,
        target_names=label_encoder.classes_
    )
)

# ==========================================
# SUMMARY
# ==========================================

print("\n" + "=" * 60)
print("MODEL SUMMARY")
print("=" * 60)
print(f"Algorithm           : Random Forest Classifier")
print(f"Training Samples    : {X_train.shape[0]}")
print(f"Testing Samples     : {X_test.shape[0]}")
print(f"Number of Features  : {X_train.shape[1]}")
print(f"Number of Classes   : {len(label_encoder.classes_)}")
print(f"Accuracy            : {accuracy * 100:.2f}%")
print("=" * 60)

# ==========================================
# SAVE MODEL
# ==========================================

joblib.dump(Trixie, "models/random_forest_model.pkl")
joblib.dump(label_encoder, "models/label_encoder.pkl")

print("\nModel Saved Successfully!")