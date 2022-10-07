from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .auth_handler import decodeJWT


class JWTBearer(HTTPBearer):
    
    def __init__(self, auto_error: bool = True):
        # set automatic error reporting by setting the boolean auto_error:
        super(JWTBearer, self).__init__(auto_error=auto_error)


    # Define a variable called credentials of type HTTPAuthorizationCredentials, which is created when 
    # the JWTBearer class is invoked. When invoked check if the credentials passed in during the course 
    # of invoking the class are valid:
    # 1) If the credential scheme isn't a bearer scheme, we raise an exception for an invalid token scheme;
    # 2) If a bearer token is passed, we verify that the JWT is valid;
    # 3) If no credentials are received, we raise an invalid authorization error.
    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")


    #  verifies whether a token is valid:
    def verify_jwt(self, jwtoken: str) -> bool:
        isTokenValid: bool = False

        try:
            payload = decodeJWT(jwtoken)
        except:
            payload = None
        if payload:
            isTokenValid = True
        return isTokenValid
    