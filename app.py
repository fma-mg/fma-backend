from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import hashlib
import secrets
import re
import requests as http
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
SUPABASE_URL  = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY  = os.environ.get("SUPABASE_KEY", "")
BRIDGE_SECRET = os.environ.get("BRIDGE_SECRET", "")
JWT_SECRET    = os.environ.get("JWT_SECRET", "")

TAUX_FMA    = 5
MONTANT_MIN = 500
MONTANT_MAX = 500000

# ─────────────────────────────────────────
# SUPABASE HTTP HELPERS
# ─────────────────────────────────────────
def db_url(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"

def db_headers(prefer=None):
    h = {
        "apikey":        SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type":  "application/json",
    }
    if prefer:
        h["Prefer"] = prefer
    return h

def db_select(table, filters=None, order=None, limit=None):
    """SELECT * FROM table WHERE ..."""
    params = {"select": "*"}
    if filters:
        params.update(filters)
    if order:
        params["order"] = order
    if limit:
        params["limit"] = str(limit)
    r = http.get(db_url(table), headers=db_headers(), params=params)
    return r.json() if r.ok else []

def db_insert(table, data):
    """INSERT INTO table VALUES (data)"""
    r = http.post(
        db_url(table),
        headers=db_headers(prefer="return=representation"),
        json=data
    )
    result = r.json()
    return result[0] if isinstance(result, list) and result else result

def db_update(table, filters, data):
    """UPDATE table SET data WHERE filters"""
    params = {}
    if filters:
        params.update(filters)
    r = http.patch(
        db_url(table),
        headers=db_headers(prefer="return=representation"),
        params=params,
        json=data
    )
    return r.ok

# ─────────────────────────────────────────
# UTILITAIRES
# ─────────────────────────────────────────
def hash_password(password):
    salt = "FMA_SALT_2026"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def verifier_bridge_secret(req):
    return req.headers.get("X-Bridge-Secret") == BRIDGE_SECRET

def get_user_from_token(req):
    token = req.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return None
    sessions = db_select("sessions", filters={"token": f"eq.{token}"})
    if not sessions:
        return None
    session = sessions[0]
    try:
        exp = datetime.fromisoformat(session["expires_at"].replace("Z", ""))
        if datetime.now() > exp:
            return None
    except Exception:
        return None
    users = db_select("users", filters={"id": f"eq.{session['user_id']}"})
    return users[0] if users else None

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────
@app.route("/")
def index():
    return jsonify({"status": "FMA Backend running", "version": "1.0"})

# ── AUTH ──
@app.route("/api/auth/inscription", methods=["POST"])
def inscription():
    data     = request.json or {}
    nom      = data.get("nom", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not nom or not email or not password:
        return jsonify({"error": "Champs manquants"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mot de passe trop court (min 6)"}), 400

    existe = db_select("users", filters={"email": f"eq.{email}"})
    if existe:
        return jsonify({"error": "Email déjà utilisé"}), 409

    db_insert("users", {
        "nom":        nom,
        "email":      email,
        "password":   hash_password(password),
        "solde_fma":  0,
        "created_at": datetime.now().isoformat()
    })
    return jsonify({"success": True, "message": "Compte créé !"}), 201


@app.route("/api/auth/connexion", methods=["POST"])
def connexion():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    users = db_select("users", filters={
        "email":    f"eq.{email}",
        "password": f"eq.{hash_password(password)}"
    })
    if not users:
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    user    = users[0]
    token   = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()

    db_insert("sessions", {
        "user_id":    user["id"],
        "token":      token,
        "expires_at": expires
    })

    return jsonify({
        "success": True,
        "token":   token,
        "user": {
            "id":        user["id"],
            "nom":       user["nom"],
            "email":     user["email"],
            "solde_fma": user["solde_fma"]
        }
    })

# ── PORTEFEUILLE ──
@app.route("/api/portefeuille/solde", methods=["GET"])
def get_solde():
    user = get_user_from_token(request)
    if not user:
        return jsonify({"error": "Non authentifié"}), 401
    return jsonify({
        "solde_fma": user["solde_fma"],
        "solde_ar":  user["solde_fma"] / TAUX_FMA
    })


@app.route("/api/portefeuille/historique", methods=["GET"])
def get_historique():
    user = get_user_from_token(request)
    if not user:
        return jsonify({"error": "Non authentifié"}), 401
    txs = db_select(
        "transactions",
        filters={"user_id": f"eq.{user['id']}"},
        order="created_at.desc",
        limit=50
    )
    return jsonify({"transactions": txs})

# ── RECHARGE MVOLA ──
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
        return jsonify({"error": "Numéro MVola invalide (ex: 0341234567)"}), 400
    if montant < MONTANT_MIN or montant > MONTANT_MAX:
        return jsonify({"error": f"Montant entre {MONTANT_MIN} et {MONTANT_MAX} Ar"}), 400

    # Anti-doublon référence
    ref_existe = db_select("transactions", filters={"reference_mvola": f"eq.{reference}"})
    if ref_existe:
        return jsonify({"error": "Cette référence a déjà été utilisée"}), 409

    db_insert("recharges_en_attente", {
        "user_id":    user["id"],
        "montant":    montant,
        "numero":     numero,
        "nom":        nom,
        "reference":  reference,
        "statut":     "en_attente",
        "created_at": datetime.now().isoformat()
    })

    return jsonify({
        "success":     True,
        "fma_attendu": montant * TAUX_FMA,
        "message":     "Demande enregistrée, vérification en cours..."
    })

# ── BRIDGE TERMUX ──
@app.route("/api/bridge/en-attente", methods=["GET"])
def bridge_en_attente():
    if not verifier_bridge_secret(request):
        return jsonify({"error": "Non autorisé"}), 403
    transactions = db_select("recharges_en_attente", filters={"statut": "eq.en_attente"})
    return jsonify({"transactions": transactions})


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

    # Trouver la transaction en attente
    result = db_select("recharges_en_attente", filters={
        "reference": f"eq.{reference}",
        "statut":    "eq.en_attente"
    })
    if not result:
        return jsonify({"error": "Transaction introuvable ou déjà traitée"}), 404

    transaction = result[0]

    if transaction["montant"] != montant:
        return jsonify({"error": "Montant incorrect"}), 400
    if transaction["numero"] != numero:
        return jsonify({"error": "Numéro incorrect"}), 400

    user_id = transaction["user_id"]
    fma     = montant * TAUX_FMA

    # Récupérer solde actuel
    users = db_select("users", filters={"id": f"eq.{user_id}"})
    if not users:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    ancien_solde  = users[0]["solde_fma"]
    nouveau_solde = ancien_solde + fma

    # Créditer
    db_update("users", {"id": f"eq.{user_id}"}, {"solde_fma": nouveau_solde})

    # Enregistrer transaction
    db_insert("transactions", {
        "user_id":         user_id,
        "type":            "recharge",
        "montant_ar":      montant,
        "montant_fma":     fma,
        "reference_mvola": reference,
        "nom_envoyeur":    nom,
        "numero_envoyeur": numero,
        "sms_brut":        sms_brut,
        "created_at":      datetime.now().isoformat()
    })

    # Marquer comme traitée
    db_update("recharges_en_attente", {"id": f"eq.{transaction['id']}"}, {"statut": "validee"})

    return jsonify({
        "success":       True,
        "fma_credite":   fma,
        "nouveau_solde": nouveau_solde,
        "user_id":       user_id
    })

# ── API PUBLIQUE ──
@app.route("/api/public/taux", methods=["GET"])
def public_taux():
    return jsonify({"taux": TAUX_FMA, "description": f"1 Ar = {TAUX_FMA} FMA"})


@app.route("/api/public/payer", methods=["POST"])
def public_payer():
    api_key     = request.headers.get("X-API-Key")
    data        = request.json or {}
    user_token  = data.get("user_token")
    montant_fma = int(data.get("montant_fma", 0))
    description = data.get("description", "Achat")

    marchands = db_select("marchands", filters={"api_key": f"eq.{api_key}", "actif": "eq.true"})
    if not marchands:
        return jsonify({"error": "API key invalide"}), 403

    sessions = db_select("sessions", filters={"token": f"eq.{user_token}"})
    if not sessions:
        return jsonify({"error": "Token utilisateur invalide"}), 401

    user_id = sessions[0]["user_id"]
    users   = db_select("users", filters={"id": f"eq.{user_id}"})
    if not users:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    user = users[0]
    if user["solde_fma"] < montant_fma:
        return jsonify({"error": "Solde insuffisant"}), 402

    nouveau_solde = user["solde_fma"] - montant_fma
    db_update("users", {"id": f"eq.{user_id}"}, {"solde_fma": nouveau_solde})
    db_insert("transactions", {
        "user_id":     user_id,
        "type":        "paiement",
        "montant_fma": montant_fma,
        "description": description,
        "created_at":  datetime.now().isoformat()
    })

    return jsonify({"success": True, "montant_debite": montant_fma, "nouveau_solde": nouveau_solde})


if __name__ == "__main__":
    app.run(debug=False, port=5000)
