"""
FMA Backend — Flask API
Gère les utilisateurs, soldes FMA, transactions et communication avec le bridge Termux.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
from datetime import datetime
import os
import hashlib
import secrets
import re

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
SUPABASE_URL    = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY    = os.environ.get("SUPABASE_KEY", "")
BRIDGE_SECRET   = os.environ.get("BRIDGE_SECRET", "SECRET_BRIDGE_KEY_CHANGE_MOI")
JWT_SECRET      = os.environ.get("JWT_SECRET", "JWT_SECRET_CHANGE_MOI")

TAUX_FMA        = 5        # 1 Ar = 5 FMA
MONTANT_MIN     = 500      # Ar
MONTANT_MAX     = 500000   # Ar

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ─────────────────────────────────────────
# UTILITAIRES
# ─────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = "FMA_SALT_2026"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def verifier_bridge_secret(req):
    return req.headers.get("X-Bridge-Secret") == BRIDGE_SECRET

def get_user_from_token(req):
    token = req.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    result = supabase.table("sessions").select("*").eq("token", token).execute()
    if not result.data:
        return None
    session = result.data[0]
    # Vérifier expiration
    exp = datetime.fromisoformat(session["expires_at"])
    if datetime.now() > exp:
        return None
    user = supabase.table("users").select("*").eq("id", session["user_id"]).execute()
    return user.data[0] if user.data else None

# ─────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────
@app.route("/api/auth/inscription", methods=["POST"])
def inscription():
    data = request.json
    nom      = data.get("nom", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not nom or not email or not password:
        return jsonify({"error": "Champs manquants"}), 400

    if len(password) < 6:
        return jsonify({"error": "Mot de passe trop court (min 6 caractères)"}), 400

    # Email déjà utilisé ?
    existe = supabase.table("users").select("id").eq("email", email).execute()
    if existe.data:
        return jsonify({"error": "Email déjà utilisé"}), 409

    user = supabase.table("users").insert({
        "nom":       nom,
        "email":     email,
        "password":  hash_password(password),
        "solde_fma": 0,
        "created_at": datetime.now().isoformat()
    }).execute()

    return jsonify({"success": True, "message": "Compte créé !"}), 201


@app.route("/api/auth/connexion", methods=["POST"])
def connexion():
    data     = request.json
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    result = supabase.table("users").select("*").eq("email", email).eq("password", hash_password(password)).execute()

    if not result.data:
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    user  = result.data[0]
    token = secrets.token_hex(32)

    # Créer session
    from datetime import timedelta
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    supabase.table("sessions").insert({
        "user_id":    user["id"],
        "token":      token,
        "expires_at": expires
    }).execute()

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

# ─────────────────────────────────────────
# PORTEFEUILLE
# ─────────────────────────────────────────
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

    txs = supabase.table("transactions") \
        .select("*") \
        .eq("user_id", user["id"]) \
        .order("created_at", desc=True) \
        .limit(50) \
        .execute()

    return jsonify({"transactions": txs.data})

# ─────────────────────────────────────────
# RECHARGE MVola
# ─────────────────────────────────────────
@app.route("/api/recharge/demande", methods=["POST"])
def demande_recharge():
    """Utilisateur soumet le formulaire MVola"""
    user = get_user_from_token(request)
    if not user:
        return jsonify({"error": "Non authentifié"}), 401

    data      = request.json
    montant   = int(data.get("montant", 0))
    numero    = data.get("numero", "").strip()
    nom       = data.get("nom", "").strip().upper()
    reference = data.get("reference", "").strip()

    # Validations
    if not all([montant, numero, nom, reference]):
        return jsonify({"error": "Tous les champs sont requis"}), 400

    if not re.match(r"^034\d{7}$", numero):
        return jsonify({"error": "Numéro MVola invalide (doit commencer par 034)"}), 400

    if montant < MONTANT_MIN or montant > MONTANT_MAX:
        return jsonify({"error": f"Montant entre {MONTANT_MIN} et {MONTANT_MAX} Ar"}), 400

    # Référence déjà utilisée ?
    ref_existe = supabase.table("transactions").select("id").eq("reference_mvola", reference).execute()
    if ref_existe.data:
        return jsonify({"error": "Cette référence a déjà été utilisée"}), 409

    # Enregistrer en attente
    demande = supabase.table("recharges_en_attente").insert({
        "user_id":   user["id"],
        "montant":   montant,
        "numero":    numero,
        "nom":       nom,
        "reference": reference,
        "statut":    "en_attente",
        "created_at": datetime.now().isoformat()
    }).execute()

    fma_attendu = montant * TAUX_FMA

    return jsonify({
        "success":     True,
        "fma_attendu": fma_attendu,
        "message":     f"Demande enregistrée. En attente de vérification SMS.",
        "recap": {
            "montant_ar":  montant,
            "montant_fma": fma_attendu,
            "numero":      numero,
            "nom":         nom,
            "reference":   reference
        }
    })

# ─────────────────────────────────────────
# BRIDGE — ENDPOINT POUR TERMUX
# ─────────────────────────────────────────
@app.route("/api/bridge/en-attente", methods=["GET"])
def bridge_en_attente():
    """Termux récupère les transactions en attente"""
    if not verifier_bridge_secret(request):
        return jsonify({"error": "Non autorisé"}), 403

    result = supabase.table("recharges_en_attente") \
        .select("*") \
        .eq("statut", "en_attente") \
        .execute()

    return jsonify({"transactions": result.data})


@app.route("/api/bridge/valider", methods=["POST"])
def bridge_valider():
    """Termux valide une transaction après vérification SMS"""
    if not verifier_bridge_secret(request):
        return jsonify({"error": "Non autorisé"}), 403

    data      = request.json
    reference = data.get("reference")
    montant   = int(data.get("montant", 0))
    numero    = data.get("numero", "")
    nom       = data.get("nom", "")
    sms_brut  = data.get("sms_brut", "")

    # Trouver la transaction en attente
    result = supabase.table("recharges_en_attente") \
        .select("*") \
        .eq("reference", reference) \
        .eq("statut", "en_attente") \
        .execute()

    if not result.data:
        return jsonify({"error": "Transaction introuvable ou déjà traitée"}), 404

    transaction = result.data[0]

    # Double vérification côté backend
    if transaction["montant"] != montant:
        return jsonify({"error": "Montant ne correspond pas"}), 400

    if transaction["numero"] != numero:
        return jsonify({"error": "Numéro ne correspond pas"}), 400

    user_id = transaction["user_id"]
    fma     = montant * TAUX_FMA

    # Créditer le solde
    user = supabase.table("users").select("solde_fma").eq("id", user_id).execute().data[0]
    nouveau_solde = user["solde_fma"] + fma

    supabase.table("users").update({"solde_fma": nouveau_solde}).eq("id", user_id).execute()

    # Enregistrer transaction
    supabase.table("transactions").insert({
        "user_id":         user_id,
        "type":            "recharge",
        "montant_ar":      montant,
        "montant_fma":     fma,
        "reference_mvola": reference,
        "nom_envoyeur":    nom,
        "numero_envoyeur": numero,
        "sms_brut":        sms_brut,
        "created_at":      datetime.now().isoformat()
    }).execute()

    # Marquer comme traitée
    supabase.table("recharges_en_attente").update({"statut": "validee"}).eq("id", transaction["id"]).execute()

    return jsonify({
        "success":      True,
        "fma_credite":  fma,
        "nouveau_solde": nouveau_solde,
        "user_id":      user_id
    })

# ─────────────────────────────────────────
# API PUBLIQUE (pour sites tiers)
# ─────────────────────────────────────────
@app.route("/api/public/payer", methods=["POST"])
def public_payer():
    """
    API publique pour sites tiers — débite le compte d'un utilisateur
    Nécessite un API key de marchand
    """
    data        = request.json
    api_key     = request.headers.get("X-API-Key")
    user_token  = data.get("user_token")
    montant_fma = int(data.get("montant_fma", 0))
    description = data.get("description", "Achat")

    # Vérifier marchand
    marchand = supabase.table("marchands").select("*").eq("api_key", api_key).execute()
    if not marchand.data:
        return jsonify({"error": "API key invalide"}), 403

    # Vérifier utilisateur
    session = supabase.table("sessions").select("*").eq("token", user_token).execute()
    if not session.data:
        return jsonify({"error": "Token utilisateur invalide"}), 401

    user_id = session.data[0]["user_id"]
    user    = supabase.table("users").select("*").eq("id", user_id).execute().data[0]

    if user["solde_fma"] < montant_fma:
        return jsonify({"error": "Solde insuffisant"}), 402

    # Débiter
    supabase.table("users").update({
        "solde_fma": user["solde_fma"] - montant_fma
    }).eq("id", user_id).execute()

    # Log transaction
    supabase.table("transactions").insert({
        "user_id":     user_id,
        "type":        "paiement",
        "montant_fma": montant_fma,
        "description": description,
        "marchand_id": marchand.data[0]["id"],
        "created_at":  datetime.now().isoformat()
    }).execute()

    return jsonify({
        "success":      True,
        "montant_debite": montant_fma,
        "nouveau_solde":  user["solde_fma"] - montant_fma
    })


@app.route("/api/public/taux", methods=["GET"])
def public_taux():
    return jsonify({
        "taux":        TAUX_FMA,
        "description": f"1 Ar = {TAUX_FMA} FMA",
        "monnaie":     "FMA"
    })


# ─────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
