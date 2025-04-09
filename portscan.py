import numpy as np
import joblib
import tensorflow as tf
import os

# Path to your saved model and encoder
MODEL_PATH = "portscan_model.tflite"
ENCODER_PATH = "encoder.pkl"

# Check if files exist
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
if not os.path.exists(ENCODER_PATH):
    raise FileNotFoundError(f"Encoder file not found at {ENCODER_PATH}")

# Load encoder
print("Loading encoder...")
encoder = joblib.load(ENCODER_PATH)

# Load TFLite model
print("Loading TFLite model...")
interpreter = tf.lite.Interpreter(model_path=MODEL_PATH)
interpreter.allocate_tensors()

# Get input and output tensors
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()
print(f"Model input shape: {input_details[0]['shape']}")
print(f"Model output shape: {output_details[0]['shape']}")

def preprocess_input(raw_features):
    """
    Process raw features into model input format
    
    Args:
        raw_features: List [dest_port, protocol, service, conn_state, history, orig_pkts]
        
    Returns:
        Preprocessed numpy array ready for model input
    """
    # Handle numeric features (dest_port, orig_pkts)
    dest_port = float(raw_features[0]) if raw_features[0] != '' else 0
    orig_pkts = float(raw_features[5]) if raw_features[5] != '' else 0
    numeric = np.array([dest_port, orig_pkts], dtype=np.float32)
    
    # Handle categorical features (protocol, service, conn_state, history)
    categorical_data = []
    for i, val in enumerate(raw_features[1:5]):
        # Clean value
        if val == '-' or val == '':
            val = 'Unknown'
        
        # Map to allowed categories
        allowed_categories = {
            0: ['tcp', 'udp', 'icmp', 'Unknown'],  # proto
            1: ['Unknown', 'http', 'dns', 'ssh'],  # service
            2: ['S0', 'SF', 'REJ', 'OTH'],         # conn_state
            3: ['S', 'SA', 'A', 'OTH']             # history
        }
        
        if val not in allowed_categories[i]:
            val = 'OTH'
            
        categorical_data.append(val)
    
    # Print preprocessing steps for debugging
    print(f"Numeric features: {numeric}")
    print(f"Categorical features (after cleaning): {categorical_data}")
    
    # Reshape to match encoder input
    categorical_data_array = np.array(categorical_data).reshape(1, -1)
    
    # One-hot encode
    categorical_encoded = encoder.transform(categorical_data_array).toarray()
    print(f"Encoded categorical shape: {categorical_encoded.shape}")
    
    # Combine all features
    combined = np.hstack([numeric, categorical_encoded[0]])
    print(f"Combined features shape: {combined.shape}")
    return combined.astype(np.float32)

def predict(features):
    """
    Predict if a connection is malicious
    
    Args:
        features: List [dest_port, protocol, service, conn_state, history, orig_pkts]
        
    Returns:
        Risk score (0-1) indicating likelihood of being malicious
    """
    preprocessed = preprocess_input(features)
    
    # Add batch dimension if needed
    if len(preprocessed.shape) == 1:
        preprocessed = np.expand_dims(preprocessed, axis=0)
        
    interpreter.set_tensor(input_details[0]['index'], preprocessed)
    interpreter.invoke()
    
    return float(interpreter.get_tensor(output_details[0]['index'])[0][0])

# Your specific test case from the log
# [dest_port, protocol, service, conn_state, history, orig_pkts]
real_connection = [38798, 'tcp', '-', 'S0', 'S', 1] 

print("\nTesting with real connection data:")
print(f"Input features: {real_connection}")
risk_score = predict(real_connection)
prediction = "MALICIOUS" if risk_score > 0.5 else "BENIGN"
    
print(f"Risk score: {risk_score:.6f}")
print(f"Prediction: {prediction}")
print(f"Actual label from log: Benign")
print(f"Correct prediction: {'Yes' if prediction == 'BENIGN' else 'No'}")