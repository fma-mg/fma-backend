from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import hashlib
import secrets
import re
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

SUPABASE_URL  = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY  = os.environ.get("SUPABASE_KEY", "")
BRIDGE_SECRET = os.environ.get("BRIDGE_SECRET", "")
JWT_SECRET    = os.environ.get("JWT_SECRET", "")

TAUX_FMA    = 5
MONTANT_MIN = 500
MONTANT_MAX = 500000

# Import supabase ici pour catcher les erreurs proprement
try:
    from supabase import create_client
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    print(f"Supabase init error: {e}")
    supabase = None

def hash_password(password):
    salt = "FMA_SALT_2026"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def verifier_bridge_secret(req):
    return req.headers.get("X-Bridge-Secret") == BRIDGE_SECRET

def get_user_from_token(req):
    token = req.headers.get("Authorization", "").replace("Bearer ", "")
    if not token or not supabase:
        return None
    try:
        result = supabase.table("sessions").select("*").eq("token", token).execute()
        if not result.data:
            return None
        session = result.data[0]
        exp = datetime.fromisoformat(session["expires_at"])
        if datetime.now() > exp:
            return None
        user = supabase.table("users").select("*").eq("id", session["user_id"]).execute()
        return user.data[0] if user.data else None
    except Exception as e:
        print(f"Token error: {e}")
        return None

@app.route("/")
def index():
    return jsonify({"status": "FMA Backend running", "version": "1.0"})

@app.route("/api/auth/inscription", methods=["POST"])
def inscription():
    data     = request.json or {}
    nom      = data.get("nom", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not nom or not email or not password:
        return jsonify({"error": "Champs manquants"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mot de passe trop court"}), 400
    try:
        existe = supabase.table("users").select("id").eq("email", email).execute()
        if existe.data:
            return jsonify({"error": "Email déjà utilisé"}), 409
        supabase.table("users").insert({
            "nom": nom, "email": email,
            "password": hash_password(password),
            "solde_fma": 0,
            "created_at": datetime.now().isoformat()
        }).execute()
        return jsonify({"success": True}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/connexion", methods=["POST"])
def connexion():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    try:
        result = supabase.table("users").select("*").eq("email", email).eq("password", hash_password(password)).execute()
        if not result.data:
            return jsonify({"error": "Email ou mot de passe incorrect"}), 401
        user    = result.data[0]
        token   = secrets.token_hex(32)
        expires = (datetime.now() + timedelta(days=30)).isoformat()
        supabase.table("sessions").insert({
            "user_id": user["id"], "token": token, "expires_at": expires
        }).execute()
        return jsonify({"success": True, "token": token, "user": {
            "id": user["id"], "nom": user["nom"],
            "email": user["email"], "solde_fma": user["solde_fma"]
        }})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/portefeuille/solde", methods=["GET"])
def get_solde():
    user = get_user_from_token(request)
    if not user:
        return jsonify({"error": "Non authentifié"}), 401
    return jsonify({"solde_fma": user["solde_fma"], "solde_ar": user["solde_fma"] / TAUX_FMA})

@app.route("/api/portefeuille/historique", methods=["GET"])
def get_historique():
    user = get_user_from_token(request)
    if not user:
        return jsonify({"error": "Non authentifié"}), 401
    try:
        txs = supabase.table("transactions").select("*").eq("user_id", user["id"]).order("created_at", desc=True).limit(50).execute()
        return jsonify({"transactions": txs.data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/recharge/demande", methods=["POST"])
def demande_recharge():
    user = get_user_from_token(request)
    if not user:
        return jsonify({"error": "Non authentifié"}), 401
    data      = request.json or {}
    montant   = int(data.get("montant", 0))
    numero    = data.get("numero", "").strip()
    nom       = data.get("nom", "").strip().upper()
    reference = data.get("reference", "").strip()
    if not all([montant, numero, nom, reference]):
        return jsonify({"error": "Tous les champs sont requis"}), 400
    if not re.match(r"^034\d{7}$", numero):
        return jsonify({"error": "Numéro MVola invalide"}), 400
    if montant < MONTANT_MIN or montant > MONTANT_MAX:
        return jsonify({"error": f"Montant entre {MONTANT_MIN} et {MONTANT_MAX} Ar"}), 400
    try:
        ref_existe = supabase.table("transactions").select("id").eq("reference_mvola", reference).execute()
        if ref_existe.data:
            return jsonify({"error": "Référence déjà utilisée"}), 409
        supabase.table("recharges_en_attente").insert({
            "user_id": user["id"], "montant": montant, "numero": numero,
            "nom": nom, "reference": reference, "statut": "en_attente",
            "created_at": datetime.now().isoformat()
        }).execute()
        return jsonify({"success": True, "fma_attendu": montant * TAUX_FMA})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/bridge/en-attente", methods=["GET"])
def bridge_en_attente():
    if not verifier_bridge_secret(request):
        return jsonify({"error": "Non autorisé"}), 403
    try:
        result = supabase.table("recharges_en_attente").select("*").eq("statut", "en_attente").execute()
        return jsonify({"transactions": result.data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/bridge/valider", methods=["POST"])
def bridge_valider():
    if not verifier_bridge_secret(request):
        return jsonify({"error": "Non autorisé"}), 403
    data      = request.json or {}
    reference = data.get("reference")
    montant   = int(data.get("montant", 0))
    numero    = data.get("numero", "")
    nom       = data.get("nom", "")
    sms_brut  = data.get("sms_brut", "")
    try:
        result = supabase.table("recharges_en_attente").select("*").eq("reference", reference).eq("statut", "en_attente").execute()
        if not result.data:
            return jsonify({"error": "Transaction introuvable"}), 404
        transaction = result.data[0]
        if transaction["montant"] != montant or transaction["numero"] != numero:
            return jsonify({"error": "Données incorrectes"}), 400
        user_id = transaction["user_id"]
        fma     = montant * TAUX_FMA
        user    = supabase.table("users").select("solde_fma").eq("id", user_id).execute().data[0]
        supabase.table("users").update({"solde_fma": user["solde_fma"] + fma}).eq("id", user_id).execute()
        supabase.table("transactions").insert({
            "user_id": user_id, "type": "recharge",
            "montant_ar": montant, "montant_fma": fma,
            "reference_mvola": reference, "nom_envoyeur": nom,
            "numero_envoyeur": numero, "sms_brut": sms_brut,
            "created_at": datetime.now().isoformat()
        }).execute()
        supabase.table("recharges_en_attente").update({"statut": "validee"}).eq("id", transaction["id"]).execute()
        return jsonify({"success": True, "fma_credite": fma, "user_id": user_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/public/taux", methods=["GET"])
def public_taux():
    return jsonify({"taux": TAUX_FMA, "monnaie": "FMA"})

if __name__ == "__main__":
    app.run(debug=False, port=5000)
