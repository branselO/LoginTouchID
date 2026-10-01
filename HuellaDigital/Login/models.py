from django.db import models
from django.contrib.auth.models import User

class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    # El ID único de la credencial generada por el Touch ID
    credential_id = models.CharField(max_length=255, unique=True)
    # La llave pública (se guarda como bytes codificados o string dependiendo de la librería)p
    public_key = models.TextField()
    # Un contador de firmas para evitar ataques de repetición (replay attacks)
    sign_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Credencial Touch ID de {self.user.username}"