import lightgbm as lgb
import numpy as np
import ember

# Load model
model = lgb.Booster(model_file="/home/fajr/Desktop/ember/ember2018/ember_model_2018.txt")
print("✓ Model loaded")

# Load the raw PE file directly (not JSON)
extractor = ember.features.PEFeatureExtractor()

# Read the raw PE file bytes
with open("MessageBox.exe", "rb") as f:
    raw_pe_data = f.read()

# Extract features directly from the PE bytes
features = extractor.feature_vector(raw_pe_data)
print(f"Vector Forn:{features}")

features = np.array(features).reshape(1, -1)
print(f"Array Form: {features}")
# Predict
result = model.predict(features)
result_value = result[0]
print(f"PREDICTION RESULT")
print(f"File: MessageBox.exe")
#print(f"Malware Probability: {result_value:.6f}")
print(f"Result Full Value:{result}")
print(f"Classification: {'🔴 MALICIOUS' if result > 0.5 else '🟢 BENIGN'}")
print(f"Result(first Value): {result_value}")
