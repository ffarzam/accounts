from bson import ObjectId
from pymongo import ReturnDocument
from redis import Redis

from fastapi import APIRouter, HTTPException, Depends, status, Request

from config.jwt_authentication import get_access_jwt_aut
from db.mongodb import get_db
from db.redisdb import get_notif_redis
from schemas.user import UserSignUp, UserSignIn, UserInfo, UserProfileUpdate, ShowUserProfile, ChangePassword, BaseUser, \
    ResetPassword, Verify
from services.notification_microservice import notification_client
from utils.user_utils import get_password_hash, verify_password

routers = APIRouter(prefix="/v1")


@routers.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserSignUp, db=Depends(get_db)):
    users = db["accounts"]
    result = await users.find_one({"email": user.email})

    if result:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    doc = {"email": user.email, "password": hashed_password, "is_account_enable": user.is_account_enable}
    await users.insert_one(doc)
    _id = str(doc["_id"])
    user_info = UserInfo(id=_id, email=user.email)

    return user_info


@routers.post("/verify", status_code=status.HTTP_200_OK)
async def verify(verification_info: Verify, db=Depends(get_db), redis: Redis = Depends(get_notif_redis)):

    email = await redis.get(verification_info.code)
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    users = db["accounts"]
    result = await users.find_one({"email": email}, {"is_account_enable": 1})
    if result["is_account_enable"]:
        return {"your account is enabled"}

    await users.find_one_and_update(
        filter={"email": email},
        update={"$set": {"is_account_enable": True}},
    )

    # publisher to delete code from redis
    return {"your account was enabled successfully"}


@routers.post("/login", status_code=status.HTTP_200_OK)
async def login(request: Request, user: UserSignIn, db=Depends(get_db)):

    users = db["accounts"]
    result = await users.find_one({"email": user.email}, {"_id": 1, "email": 1, "password": 1, "is_account_enable": 1})

    if not result:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is wrong")
    if not verify_password(user.password, result["password"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password is wrong")
    if not result["is_account_enable"]:
        raise HTTPException(status_code=455,
                            detail="your account has not been verified yet, we sent you the verification code")

    user_id = str(result["_id"])
    data = {"id": user_id, "email": user.email}
    return data


@routers.get("/show_profile", status_code=status.HTTP_200_OK)
async def show_profile(request: Request, payload: dict = Depends(get_access_jwt_aut()), db=Depends(get_db)):
    users = db["accounts"]
    result = await users.find_one({"_id": ObjectId(payload["id"])}, {"_id": 0, "password": 0})
    result["id"] = payload["id"]
    # setattr(request.state, "user_id", payload["id"])
    result = ShowUserProfile(**result).model_dump(exclude_none=True)
    return result


@routers.patch("/update_profile", status_code=status.HTTP_200_OK)
async def profile_update(user_data: UserProfileUpdate, payload: dict = Depends(get_access_jwt_aut()),
                         db=Depends(get_db)):

    users = db["accounts"]
    result = await users.find_one_and_update(
        filter={"_id": ObjectId(payload["id"])},
        update={"$set": user_data.model_dump(exclude_unset=True)},
        projection={"_id": 0, "password": 0, "is_account_enable": 0},
        return_document=ReturnDocument.AFTER)
    result["id"] = payload["id"]
    result = ShowUserProfile(**result).model_dump(exclude_none=True)
    return result


@routers.patch("/change_password", status_code=status.HTTP_200_OK)
async def profile_update(user_data: ChangePassword, payload: dict = Depends(get_access_jwt_aut()), db=Depends(get_db)):

    users = db["accounts"]
    result = await users.find_one({"_id": ObjectId(payload["id"])}, {"password": 1})
    if not verify_password(user_data.old_password, result["password"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password is wrong")
    await users.find_one_and_update(
        filter={"_id": ObjectId(payload["id"])},
        update={"$set": {"password": get_password_hash(user_data.new_password)}},
    )
    return {"password changed successfully"}


@routers.post("/reset_password_request", status_code=status.HTTP_200_OK)
async def reset_password_request(request: Request, user_email: BaseUser, db=Depends(get_db)):

    users = db["accounts"]
    result = await users.find_one({"email": user_email.email}, {"email": 1})
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email does not exist")

    await notification_client.code_call({"email": result["email"], "action": "reset password"}, request)
    return {"A code was sent to your email"}


@routers.patch("/reset_password", status_code=status.HTTP_200_OK)
async def reset_password(reset_password_info: ResetPassword, db=Depends(get_db),
                         redis: Redis = Depends(get_notif_redis)):

    email = await redis.get(reset_password_info.code)
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    users = db["accounts"]
    await users.find_one_and_update(
        filter={"email": email},
        update={"$set": {"password": get_password_hash(reset_password_info.new_password)}},
    )
    # publisher to delete code from redis
    return {"password changed successfully"}
