import shutil
import os
from flask import Flask, request, jsonify
import sqlite3
import importlib
import quantumshield
importlib.reload(quantumshield)  # Force reload of the module
from quantumshield import QuantumShield
import base64

application = Flask(__name__)
print("Starting Flask app...")

# Path to api_keys.db in the project directory
DB_PATH = os.path.join(os.path.dirname(__file__), 'api_keys.db')

# Ensure api_keys.db exists in the project directory
if not os.path.exists(DB_PATH):
    raise Exception("Cannot start app: api_keys.db is missing in the project directory")
else:
    print("api_keys.db found in the project directory")

print("Loading quantumshield module...")
import quantumshield
print("Quantumshield module loaded successfully")

print("Creating QuantumShield object...")
qs = QuantumShield(parameter_set="512")
print("QuantumShield object created")

print("Defining verify_api_key function...")
def verify_api_key(api_key):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys WHERE api_key = ?", (api_key,))
    result = cursor.fetchone()
    conn.close()
    return result is not None
print("verify_api_key function defined")

print("Setting up before_request middleware...")
@application.before_request
def require_api_key():
    api_key = request.headers.get('X-API-Key')
    if not api_key or not verify_api_key(api_key):
        return jsonify({"status": "error", "message": "Invalid or missing API key"}), 401
print("before_request middleware set up")

print("Defining routes...")
@application.route("/api/mlkem/generate-keypair", methods=["POST"])
def generate_keypair():
    try:
        parameter_set = request.json.get("parameter_set", "512")
        qs_temp = QuantumShield(parameter_set=parameter_set)
        key_pair = qs_temp.generate_keypair()
        print(f"key_pair: {key_pair}, Type: {type(key_pair)}")
        if isinstance(key_pair, tuple):
            public_key, private_key = key_pair
        else:
            public_key = key_pair.public_key.to_pem()
            private_key = key_pair.private_key.to_pem()
        return jsonify({
            "status": "success",
            "public_key": public_key,
            "private_key": private_key,
            "parameter_set": parameter_set
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@application.route("/api/mlkem/encapsulate", methods=["POST"])
def encapsulate():
    try:
        public_key = request.json.get("public_key")
        ciphertext, shared_secret = qs.encapsulate(public_key)
        return jsonify({
            "status": "success",
            "ciphertext": ciphertext,
            "shared_secret": base64.b64encode(shared_secret).decode()
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@application.route("/api/mlkem/decapsulate", methods=["POST"])
def decapsulate():
    try:
        private_key = request.json.get("private_key")
        ciphertext = request.json.get("ciphertext")
        shared_secret = qs.decapsulate(private_key, ciphertext)
        return jsonify({
            "status": "success",
            "shared_secret": base64.b64encode(shared_secret).decode()
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@application.route("/api/mlkem/hybrid-encrypt", methods=["POST"])
def hybrid_encrypt():
    try:
        data = request.json.get("data")
        public_key = request.json.get("public_key")
        encrypted = qs.hybrid_encrypt(data, public_key)
        return jsonify({"status": "success", "encrypted_data": encrypted}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@application.route("/api/mlkem/hybrid-decrypt", methods=["POST"])
def hybrid_decrypt():
    try:
        private_key = request.json.get("private_key")
        encrypted_data = request.json.get("encrypted_data")
        plaintext = qs.hybrid_decrypt(private_key, encrypted_data)
        return jsonify({"status": "success", "plaintext": plaintext}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@application.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200

print("Routes defined")
print("Flask app setup complete")

if __name__ == "__main__":
    print("Running Flask app directly...")
    application.run(host="0.0.0.0", port=8081)