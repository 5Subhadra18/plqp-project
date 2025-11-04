# cli_search.py
"""
Privacy-Preserving Location Query using Google Places API
- Automatically detects your location (via IP if GPS not available)
- Radius: 5 km
- Dummies: 7 synthetic locations around your true point
- Saves JSON compatible with render_map.py
"""

import json, math, os, sys, time, requests
from dotenv import load_dotenv

# Load .env file automatically
load_dotenv()
print("DEBUG: Loaded key =", os.getenv("PLACES_API_KEY"))


from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# -------------------------------
# CONFIG
# -------------------------------
PLACES_URL = "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
IPINFO_URL = "https://ipinfo.io/json"
USER_AGENT = "PrivacyPreservingLBS-Project/1.0 (contact: your_email@domain.com)"
RADIUS_M = 5000       # 5 km
NUM_DUMMIES = 7
AES_SALT = b"plqp-salt-2025"
PBKDF2_ITERS = 200000


# -------------------------------
# Helpers
# -------------------------------
def get_api_key():
    from dotenv import load_dotenv
    load_dotenv()  # ensure .env is read even if not loaded globally
    key = os.getenv("PLACES_API_KEY")
    if not key:
        print("❌ Google Places API key not set.")
        print("Run: export PLACES_API_KEY='YOUR_KEY' (Linux/macOS)")
        print("or   setx PLACES_API_KEY 'YOUR_KEY' (Windows)")
        sys.exit(1)
    return key



def detect_location():
    """Detect approximate lat/lon via IP lookup"""
    print("📍 Detecting your current location...")
    try:
        r = requests.get(IPINFO_URL, headers={"User-Agent": USER_AGENT}, timeout=8)
        r.raise_for_status()
        loc = r.json().get("loc")
        if not loc:
            raise ValueError("No coordinates found in response.")
        lat_str, lon_str = loc.split(",")
        lat, lon = float(lat_str), float(lon_str)
        print(f"✅ Approx location detected: {lat:.6f}, {lon:.6f}")
        return lat, lon
    except Exception as e:
        print("❌ Failed to detect location automatically:", e)
        sys.exit(1)


def generate_dummies(lat, lon, n=7, max_radius_m=1000):
    """Generate n dummy points around a given coordinate."""
    lat_deg_per_m = 1.0 / 111111.0
    lon_deg_per_m = 1.0 / (111111.0 * math.cos(math.radians(lat)) + 1e-12)
    dummies = []
    for i in range(n):
        r = max_radius_m * (0.4 + 0.6 * (i + 1) / (n + 1))
        bearing = (i * 137.508) % 360
        br = math.radians(bearing)
        dy = r * math.cos(br)
        dx = r * math.sin(br)
        new_lat = lat + dy * lat_deg_per_m
        new_lon = lon + dx * lon_deg_per_m
        dummies.append({"lat": new_lat, "lon": new_lon})
    return dummies


def haversine_m(lat1, lon1, lat2, lon2):
    R = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# -------------------------------
# Google Places API
# -------------------------------
def google_places_search(lat, lon, radius, query, api_key, max_results=30):
    """Call Google Places Nearby Search API"""
    params = {
        "location": f"{lat},{lon}",
        "radius": radius,
        "keyword": query,
        "key": api_key
    }
    headers = {"User-Agent": USER_AGENT}
    print("🔍 Querying Google Places API...")
    r = requests.get(PLACES_URL, params=params, headers=headers, timeout=15)
    r.raise_for_status()
    data = r.json()
    if "error_message" in data:
        print("❌ API Error:", data["error_message"])
        sys.exit(1)

    results = []
    for res in data.get("results", []):
        loc = res["geometry"]["location"]
        results.append({
            "name": res.get("name", "Unknown"),
            "lat": loc["lat"],
            "lon": loc["lng"],
            "address": res.get("vicinity", ""),
            "rating": res.get("rating"),
            "types": res.get("types", []),
            "place_id": res.get("place_id")
        })
    return results[:max_results]


# -------------------------------
# Encryption
# -------------------------------
def derive_key_from_passphrase(passphrase, salt=AES_SALT, key_len=32):
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    return PBKDF2(passphrase, salt, dkLen=key_len, count=PBKDF2_ITERS)


def encrypt_bytes_aes_gcm(plaintext_bytes, key_bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return {"nonce_hex": nonce.hex(), "tag_hex": tag.hex(), "ciphertext_hex": ct.hex()}


# -------------------------------
# Reusable Search Function for Flask
# -------------------------------
def run_search(query, lat, lon):
    """Run location query with Google Places API and dummy generation."""
    api_key = get_api_key()
    radius = RADIUS_M
    dummies = generate_dummies(lat, lon, n=NUM_DUMMIES)

    places = google_places_search(lat, lon, radius, query, api_key)
    for p in places:
        p["distance_m"] = haversine_m(lat, lon, p["lat"], p["lon"])
    places.sort(key=lambda x: x["distance_m"])

    candidates = [{"lat": lat, "lon": lon, "is_real": True}] + [
        {"lat": d["lat"], "lon": d["lon"], "is_real": False} for d in dummies
    ]

    output = {
        "query": query,
        "center": {"lat": lat, "lon": lon},
        "radius_m": radius,
        "dummies": dummies,
        "candidates": candidates,
        "merged_places": places,
        "candidate_count": len(candidates),
        "places_count": len(places),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    return output


# -------------------------------
# Main CLI execution
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cli_search.py <query> [--key <passphrase>]")
        sys.exit(1)

    query = sys.argv[1]
    key_arg = sys.argv[2] if len(sys.argv) > 2 else None

    lat, lon = detect_location()
    result = run_search(query, lat, lon)
    out_file = f"places_output_{query.replace(' ', '_')}.json"
    Path(out_file).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"✅ Results saved to {out_file}")

    if key_arg:
        key_bytes = derive_key_from_passphrase(key_arg)
        plaintext = json.dumps(result, separators=(",", ":")).encode()
        enc = encrypt_bytes_aes_gcm(plaintext, key_bytes)
        enc_file = out_file + ".enc.json"
        Path(enc_file).write_text(json.dumps({"enc_data": enc}, indent=2))
        print(f"🔒 Encrypted file saved to {enc_file}")

    print("🎯 Done.")
