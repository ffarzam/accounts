from typing import Any
import jwt

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from utils.token_utils import decode_token
from db.redisdb import get_auth_redis

redis = get_auth_redis()


class AccessJWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(AccessJWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(AccessJWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authentication scheme.")

            try:
                payload = await decode_token(credentials.credentials)
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Expired access token")
            except Exception:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid access token")
            result = await self.validate_jti_token(payload)
            if not result:
                HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid access token")
            return payload
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access token found")

    @staticmethod
    async def validate_jti_token(payload: dict) -> Any:
        jti = payload.get('jti')
        user_id = payload.get('user_id')
        return await redis.keys(f"user_{user_id} || {jti}")


access_jwt_auth = AccessJWTBearer()


def get_access_jwt_aut():
    return access_jwt_auth
