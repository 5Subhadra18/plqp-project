import os
import json
import sys
import secrets
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

# Local imports
import cli_search
import access_manager
import encrypt_utils
from encrypt_utils import derive_kek, encrypt_with_key

# Setup
sys.path.append(str(Path(__file__).parent))
load_dotenv()

app = Flask(__name__, template_folder="templates")
CORS(app)

# Blueprints
from user_routes import user_bp
from partner_routes import partner_bp
app.register_blueprint(user_bp, url_prefix="/user")
app.register_blueprint(partner_bp, url_prefix="/partner")

# Environment variables
ENCRYPT_RESPONSE = os.getenv("ENCRYPT_RESPONSE", "1").lower() in ("1", "true", "yes")
ENCRYPT_PASSPHRASE = os.getenv("ENCRYPT_PASSPHRASE", "mySecret123")

# -----------------------------------------------------
# ROUTES
# -----------------------------------------------------

@app.route("/")
def home():
    return render_template("owner.html")

@app.route("/viewer")
def viewer_page():
    return render_template("viewer.html")


# ------------------ VIEW LOCATION ------------------
@app.route("/view_location", methods=["POST"])
def view_location():
    """
    Viewer requests owner's location.
    If access is valid, return ONLY the owner's real location.
    """
    try:
        data = request.get_json()
        owner = data.get("owner")
        viewer = data.get("viewer")

        if not owner or not viewer:
            return jsonify({"error": "Missing owner or viewer"}), 400

        # 🔹 Validate access
        access_manager.revoke_expired()
        if not access_manager.is_access_allowed(owner, viewer):
            return jsonify({"error": "Unauthorized access or access expired"}), 403

        # 🔹 Locate latest encrypted file
        backend_dir = Path(__file__).parent
        enc_files = sorted(
            backend_dir.glob("places_output_*.enc.json"),
            key=lambda f: f.stat().st_mtime
        )
        if not enc_files:
            return jsonify({"error": "No encrypted location data found"}), 404

        latest_file = enc_files[-1]
        with open(latest_file, "r", encoding="utf-8") as f:
            enc_content = json.load(f)

        # 🔹 Extract encrypted data
        enc_data = enc_content.get("enc_data", enc_content)

        # ✅ Return only enc_data (the viewer will decrypt and see only owner center)
        return jsonify({"enc_data": enc_data})

    except Exception as e:
        print("❌ Error in /view_location:", e)
        return jsonify({"error": str(e)}), 500


# ------------------ OWNER SEARCH ------------------
@app.route("/search", methods=["POST"])
def search():
    """
    Owner searches for nearby places — includes owner, dummy, and merged data.
    Encrypted result saved for later viewer access.
    """
    try:
        access_manager.revoke_expired()
        data = request.get_json()
        query = data.get("query")
        lat = data.get("lat")
        lon = data.get("lon")
        owner = data.get("owner")

        if not query or lat is None or lon is None:
            return jsonify({"error": "Missing query or coordinates"}), 400

        # 🔹 Owner performs location query (full data)
        result = cli_search.run_search(query, lat, lon)

        # 🔹 Encrypt result
        salt = secrets.token_bytes(16)
        key = derive_kek(ENCRYPT_PASSPHRASE, salt)
        token = encrypt_with_key(key, json.dumps(result).encode("utf-8"))

        # Split base64(nonce+tag+ct)
        from base64 import b64decode
        raw = b64decode(token)
        nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]

        enc_data = {
            "salt_hex": salt.hex(),
            "nonce_hex": nonce.hex(),
            "tag_hex": tag.hex(),
            "ciphertext_hex": ciphertext.hex(),
        }

        # 🔹 Save encrypted file (overwrites last)
        filename = f"places_output_{owner or 'user'}.enc.json"
        filepath = Path(__file__).parent / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({"enc_data": enc_data}, f, indent=2, ensure_ascii=False)

        print(f"🔒 Encrypted file saved to {filepath}")
        return jsonify({"enc_data": enc_data})

    except Exception as e:
        print("❌ Error in /search:", e)
        return jsonify({"error": str(e)}), 500


# ------------------ GRANT ACCESS ------------------
@app.route("/grant_access", methods=["POST"])
def grant_access():
    """
    Owner grants a viewer temporary access to their location.
    """
    try:
        data = request.get_json()
        owner = data.get("owner")
        viewer = data.get("viewer")
        duration = int(data.get("duration_minutes", 5))

        if not owner or not viewer:
            return jsonify({"error": "Missing owner or viewer"}), 400

        rule = access_manager.grant_access(owner, viewer, duration)
        return jsonify({"message": "✅ Access granted", "rule": rule})

    except Exception as e:
        print("❌ Error in /grant_access:", e)
        return jsonify({"error": str(e)}), 500


# -----------------------------------------------------
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Use Render's assigned port
    app.run(host="0.0.0.0", port=port)

