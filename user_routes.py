# user_routes.py
from flask import Blueprint, request, jsonify
import cli_search, encrypt_utils, os, json, access_manager

user_bp = Blueprint("user_bp", __name__)

@user_bp.route("/search", methods=["POST"])
def search_places():
    """
    Handle user's encrypted place search.
    Optionally checks access permissions if 'owner' and 'viewer' are provided.
    """
    data = request.get_json()
    query = data.get("query")
    lat = data.get("lat")
    lon = data.get("lon")
    owner = data.get("owner")
    viewer = data.get("viewer")

    # Access check (if both provided)
    if owner and viewer:
        access_manager.revoke_expired()
        if not access_manager.is_access_allowed(owner, viewer):
            return jsonify({"error": "Access expired or unauthorized"}), 403

    result = cli_search.run_search(query, lat, lon)

    # Encrypt the response
    passphrase = os.getenv("ENCRYPT_PASSPHRASE", "mySecret123")
    key = encrypt_utils.derive_key_from_passphrase(passphrase)
    enc = encrypt_utils.encrypt_bytes_aes_gcm(json.dumps(result).encode("utf-8"), key)

    return jsonify({"enc_data":enc})