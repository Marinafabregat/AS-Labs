from fastapi.security.oauth2 import OAuth2, OAuthFlowsModel
from fastapi import Request, HTTPException, status
from fastapi.security.utils import get_authorization_scheme_param

from typing import Optional, Dict
import logging

log = logging.getLogger(__name__)
class OAuth2PasswordBearerWithCookie(OAuth2):
    """
    Follow the OAUTH2 Model to maintain compatibility with tokens
    and cookies.

    Essentially we overload the OAUTH2 Model to allow cookie based
    authentication to also be used.

    I have disabled auto_error by default,
    as it causes issues when we try to get a user or none 
    (ie if there is a user return info, for example letting the homepage show either user or login pages)

    Error handing and 40x codes are handled in the requires authenticated user etc methods
    """

    def __init__(
        self,
        tokenUrl: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        auto_error: bool = False,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        # Allow authorization scheme to be either cookie or header based
        log.debug("===== AUTH CALL ====")

        # Deal with cookie based authentication
        authorization: str = request.cookies.get("access_token")
        if authorization:
            # Beacuse I found the bearer prefix in the cookie ugly We dont actually have one.
            # Therefore just return whatever is in the access token field.
            log.debug("Auth via Cookie %s", authorization)
            return authorization

        # If we dont have a cookie try the request header
        if not authorization:
            log.debug("--> Auth Via Token")
            authorization: str = request.headers.get("Authorization")

        scheme, param = get_authorization_scheme_param(authorization)
        log.debug("scheme is %s", scheme)
        log.debug("params %s", param)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None

        return param

oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="token", auto_error=False)