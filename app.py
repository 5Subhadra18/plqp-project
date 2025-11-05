import os
import json
import sys
import secrets
import time
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

# 🆕 IN-MEMORY STORAGE (replaces JSON files)
# Structure: { "owner_id": {"enc_data": {...}, "timestamp": float} }
LOCATION_CACHE = {}
CACHE_EXPIRY_SECONDS = 3600  # 1 hour

def clean_expired_cache():
    """Remove cached entries older than CACHE_EXPIRY_SECONDS"""
    now = time.time()
    expired_keys = [k for k, v in LOCATION_CACHE.items() 
                    if now - v.get("timestamp", 0) > CACHE_EXPIRY_SECONDS]
    for key in expired_keys:
        del LOCATION_CACHE[key]
    if expired_keys:
        print(f"🧹 Cleaned {len(expired_keys)} expired cache entries")

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
    Viewer requests owner's location from in-memory cache.
    If access is valid, return ONLY the owner's encrypted location data.
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

        # 🔹 Clean expired cache entries
        clean_expired_cache()

        # 🔹 Retrieve from in-memory cache
        if owner not in LOCATION_CACHE:
            return jsonify({"error": "No location data found for this owner"}), 404

        cached_entry = LOCATION_CACHE[owner]
        enc_data = cached_entry.get("enc_data")

        if not enc_data:
            return jsonify({"error": "Invalid cached data"}), 500

        # ✅ Return encrypted data
        print(f"✅ Viewer '{viewer}' accessed owner '{owner}' location")
        return jsonify({"enc_data": enc_data})

    except Exception as e:
        print("❌ Error in /view_location:", e)
        return jsonify({"error": str(e)}), 500


# ------------------ OWNER SEARCH ------------------
@app.route("/search", methods=["POST"])
def search():
    """
    Owner searches for nearby places — includes owner, dummy, and merged data.
    Encrypted result stored in memory for later viewer access.
    """
    try:
        access_manager.revoke_expired()
        data = request.get_json()
        query = data.get("query")
        lat = data.get("lat")
        lon = data.get("lon")
        owner = data.get("owner", "anonymous_user")

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

        # 🔹 Store in memory instead of file
        LOCATION_CACHE[owner] = {
            "enc_data": enc_data,
            "timestamp": time.time()
        }

        print(f"🔒 Encrypted location stored in memory for owner: {owner}")
        print(f"📊 Current cache size: {len(LOCATION_CACHE)} entries")
        
        return jsonify({"enc_data": enc_data})

    except Exception as e:
        print("❌ Error in /search:", e)
        return jsonify({"error": str(e)}), 500


# ------------------ UPLOAD LOCATION ------------------
@app.route("/upload_location", methods=["POST"])
def upload_location():
    """
    Owner uploads cached location data to server.
    This is called when granting access to ensure data is available.
    """
    try:
        data = request.get_json()
        owner = data.get("owner")
        enc_data = data.get("enc_data")

        if not owner or not enc_data:
            return jsonify({"error": "Missing owner or encrypted data"}), 400

        # Store in memory cache
        LOCATION_CACHE[owner] = {
            "enc_data": enc_data,
            "timestamp": time.time()
        }

        print(f"📤 Location data uploaded for owner: {owner}")
        return jsonify({"message": "✅ Location uploaded successfully"})

    except Exception as e:
        print("❌ Error in /upload_location:", e)
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


# ------------------ CACHE STATUS (DEBUG) ------------------
@app.route("/cache_status", methods=["GET"])
def cache_status():
    """Debug endpoint to view current cache contents"""
    clean_expired_cache()
    status = {
        "total_entries": len(LOCATION_CACHE),
        "owners": list(LOCATION_CACHE.keys()),
        "cache_expiry_seconds": CACHE_EXPIRY_SECONDS
    }
    return jsonify(status)


# -----------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)