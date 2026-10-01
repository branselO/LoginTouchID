import json
import base64
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

# Importaciones de la librería WebAuthn
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers import parse_authentication_credential_json, base64url_to_bytes
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse

from .models import WebAuthnCredential

# ==========================================
# CONFIGURACIÓN DEL SERVIDOR (Relying Party)
# ==========================================
RP_ID = "localhost" 
RP_NAME = "Proyecto Touch ID"
ORIGIN = "http://localhost:8000"


# ==========================================
# VISTAS DE REGISTRO DE HUELLA
# ==========================================

@login_required
def register_web(request):
    """Renderiza la página para registrar una nueva huella"""
    return render(request, 'Login/register_fingerprint.html')

@login_required
def register_webauthn_begin(request):
    """Fase 1: Django genera el desafío de registro para la Mac"""
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(request.user.id).encode("utf-8"),
        user_name=request.user.username,
        user_display_name=request.user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM, 
            resident_key=ResidentKeyRequirement.DISCOURAGED,
        ),
    )

    request.session['webauthn_registration_challenge'] = base64.b64encode(options.challenge).decode('utf-8')
    return JsonResponse(json.loads(options_to_json(options)))

@csrf_exempt
@login_required
def register_webauthn_complete(request):
    """Fase 2: Django recibe y guarda la llave pública generada por el Touch ID"""
    if request.method != "POST":
        return JsonResponse({"error": "Método no permitido"}, status=405)

    challenge_b64 = request.session.get('webauthn_registration_challenge')
    if not challenge_b64:
        return JsonResponse({"error": "No hay desafío activo"}, status=400)
    
    expected_challenge = base64.b64decode(challenge_b64)

    try:
        body = request.body.decode('utf-8')
        
        verification = verify_registration_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True,
        )

        WebAuthnCredential.objects.create(
            user=request.user,
            credential_id=verification.credential_id.hex(),
            public_key=verification.credential_public_key.hex(),
            sign_count=verification.sign_count
        )

        return JsonResponse({"status": "ok", "message": "¡Huella registrada exitosamente!"})

    except InvalidRegistrationResponse as e:
        return JsonResponse({"error": f"Fallo en la verificación: {str(e)}"}, status=400)


# ==========================================
# VISTAS DE INICIO DE SESIÓN (LOGIN)
# ==========================================

def login_web(request):
    """Renderiza la página para iniciar sesión con Touch ID"""
    return render(request, 'Login/login_fingerprint.html')

@csrf_exempt
def login_webauthn_begin(request):
    """Fase 1: Django recibe el usuario y le envía el desafío de login"""
    if request.method != "POST":
        return JsonResponse({"error": "Método no permitido"}, status=405)

    data = json.loads(request.body)
    username = data.get('username')

    try:
        user = User.objects.get(username=username)
        if not user.is_staff:
            return JsonResponse({"error": "Acceso denegado: Solo los administradores pueden iniciar sesión en este sistema."}, status=403)
        # ------------------------

    except User.DoesNotExist:
        return JsonResponse({"error": "Usuario no encontrado"}, status=404)

    user_credentials = user.webauthn_credentials.all()
    if not user_credentials.exists():
        return JsonResponse({"error": "Este usuario no tiene huellas registradas"}, status=400)

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=bytes.fromhex(cred.credential_id))
        for cred in user_credentials
    ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
    )

    request.session['webauthn_login_challenge'] = base64.b64encode(options.challenge).decode('utf-8')
    request.session['webauthn_login_userid'] = user.id

    return JsonResponse(json.loads(options_to_json(options)))

@csrf_exempt
def login_webauthn_complete(request):
    """Fase 2: Django verifica la firma del Touch ID e inicia la sesión"""
    if request.method != "POST":
        return JsonResponse({"error": "Método no permitido"}, status=405)

    challenge_b64 = request.session.get('webauthn_login_challenge')
    user_id = request.session.get('webauthn_login_userid')

    if not challenge_b64 or not user_id:
        return JsonResponse({"error": "No hay un inicio de sesión activo"}, status=400)

    expected_challenge = base64.b64decode(challenge_b64)

    try:
        body = request.body.decode('utf-8')
        
        parsed_credential = parse_authentication_credential_json(body)
        
        # AHORA: Convertimos el texto a bytes, y luego los bytes a hexadecimal
        raw_id_bytes = base64url_to_bytes(parsed_credential.id)
        credential_id_hex = raw_id_bytes.hex()
        
        credential = WebAuthnCredential.objects.get(credential_id=credential_id_hex)

        verification = verify_authentication_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=bytes.fromhex(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )

        credential.sign_count = verification.new_sign_count
        credential.save()

        # Iniciamos sesión usando el modelo User nativo
        user = User.objects.get(id=user_id)
        login(request, user)

        return JsonResponse({"status": "ok", "message": f"¡Bienvenido de nuevo, {user.username}!"})

    except InvalidAuthenticationResponse as e:
        return JsonResponse({"error": f"Fallo en la validación: {str(e)}"}, status=400)
    except WebAuthnCredential.DoesNotExist:
        return JsonResponse({"error": "La credencial no coincide con nuestros registros"}, status=404)