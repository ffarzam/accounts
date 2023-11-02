import jwt

from config.config import get_settings


settings = get_settings()


async def decode_token(token: str) -> dict:
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    return payload




