from redgnat.techniques.identity.credential_stuffing import CredentialStuffingTechnique
from redgnat.techniques.identity.mfa_fatigue import MFAFatigueTechnique
from redgnat.techniques.identity.oauth_abuse import OAuthAbuseTechnique
from redgnat.techniques.identity.password_spray import PasswordSprayTechnique
from redgnat.techniques.identity.token_theft import TokenTheftTechnique

__all__ = [
    "PasswordSprayTechnique",
    "CredentialStuffingTechnique",
    "MFAFatigueTechnique",
    "OAuthAbuseTechnique",
    "TokenTheftTechnique",
]
