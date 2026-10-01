from django.contrib import admin
from .models import WebAuthnCredential

@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    # Mostramos las columnas reales que sí existen en WebAuthnCredential
    list_display = ['id', 'user', 'created_at', 'sign_count']
    
    # Agregamos una barra de búsqueda para buscar por el nombre de usuario de la llave
    search_fields = ['user__username', 'credential_id']
    
    # Filtros laterales
    list_filter = ['created_at']