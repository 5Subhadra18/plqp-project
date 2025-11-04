# partner_routes.py
from flask import Blueprint, request, jsonify
import access_manager

partner_bp = Blueprint("partner_bp", __name__)

@partner_bp.route("/grant_access", methods=["POST"])
def grant_access():
    """
    Partner requests access to users location.
    Body: { "owner": "user123", "viewer": "agent007", "duration_minutes": 10 }
    """
    data = request.get_json()
    owner = data.get("owner")
    viewer = data.get("viewer")
    duration = int(data.get("duration_minutes", 5))

    if not owner or not viewer:
        return jsonify({"error": "Missing owner or viewer"}), 400

    rule = access_manager.grant_access(owner, viewer, duration)
    return jsonify({"status": "granted", "rule": rule})


@partner_bp.route("/verify_access", methods=["POST"])
def verify_access():
    """
    Partner verifies if access is still valid.
    Body: { "owner": "user123", "viewer": "agent007" }
    """
    data = request.get_json()
    owner = data.get("owner")
    viewer = data.get("viewer")

    allowed = access_manager.is_access_allowed(owner, viewer)
    return jsonify({"authorized":allowed})