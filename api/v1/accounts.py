from bson import ObjectId
from pymongo import ReturnDocument

from fastapi import APIRouter, HTTPException, Depends, status
from redis import Redis

from config.jwt_authentication import get_access_jwt_aut
from db.mongodb import get_db
from db.redisdb import get_notif_redis

from schemas.user import UserSignUp, UserSignIn, UserInfo, UserProfileUpdate, ShowUserProfile, ChangePassword, BaseUser, \
    ResetPassword, Verify
from services.notification_microservice import notification_client

from utils.token_utils import decode_token
from utils.user_utils import get_password_hash, verify_password

routers = APIRouter(prefix="/v1")


@routers.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserSignUp, db=Depends(get_db)):
    """
    The register function creates a new user in the database.
        It takes a UserSignUp object as input and returns an UserInfo object.
        The password is hashed before it is stored in the database.

    :param user: UserSignUp: Get the data from the request body
    :param db: Access the database, and the user parameter is used to get the data from request body
    :return: A userinfo object
    :doc-author: Trelent
    """
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
    """
    The verify function is used to verify the user's email address.
        It takes in a Verify object, which contains an email and code field.
        The function then checks if the code matches with what was sent to the user's email address,
        and if it does, it enables their account.

    :param verification_info: Verify: Get the email and code from the request body
    :param db: Access the database
    :param redis: Redis: Get the redis connection
    :return: A dict
    """

    users = db["accounts"]
    result = await users.find_one({"email": verification_info.email}, {"is_account_enable": 1})
    if result["is_account_enable"]:
        return {"your account is enabled"}

    code = await redis.get(verification_info.email)
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or expired code")
    if code != verification_info.code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    await users.find_one_and_update(
        filter={"email": verification_info.email},
        update={"$set": {"is_account_enable": True}},
    )

    # publisher to delete code from redis
    return {"your account was enabled successfully"}


@routers.post("/login", status_code=status.HTTP_200_OK)
async def login(user: UserSignIn, db=Depends(get_db)):
    """
    The login function takes a user's email and password,
        checks if the account is enabled,
        verifies the password against the hashed version in MongoDB.

    :param user: UserSignIn: Get the user's email and password
    :param db: Get the database connection
    :return: The user id and email, which are used to create a jwt token
    """
    users = db["accounts"]
    result = await users.find_one({"email": user.email}, {"_id": 1, "email": 1, "password": 1, "is_account_enable": 1})

    if not result:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is wrong")
    if not verify_password(user.password, result["password"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password is wrong")
    if not result["is_account_enable"]:
        await notification_client.code_call({"email": user.email, "action": "verify account"})
        raise HTTPException(status_code=455,
                            detail="your account has not been verified yet, we sent you the verification code")

    user_id = str(result["_id"])
    data = {"id": user_id, "email": user.email}
    return data


@routers.get("/show_profile", status_code=status.HTTP_200_OK, response_model=ShowUserProfile)
async def show_profile(payload: dict = Depends(get_access_jwt_aut()), db=Depends(get_db)):
    """
    The show_profile function returns the user's profile information.

    :param payload: dict: Get the jwt payload
    :param db: Access the database
    :return: A dict containing the user's information
    """
    users = db["accounts"]
    result = await users.find_one({"_id": ObjectId(payload["id"])}, {"_id": 0, "password": 0})
    result["id"] = payload["id"]
    return result


@routers.patch("/update_profile", status_code=status.HTTP_200_OK, response_model=ShowUserProfile)
async def profile_update(user_data: UserProfileUpdate, payload: dict = Depends(get_access_jwt_aut()),
                         db=Depends(get_db)):
    """
    The profile_update function is used to update the user's profile.
    The function takes in a UserProfileUpdate object and returns a dict of the updated user's data.

    :param user_data: UserProfileUpdate: Validate the data that is passed in
    :param payload: dict: Get the user id from the token
    :param db: Get the database connection
    :return: The updated user profile
    """
    users = db["accounts"]
    result = await users.find_one_and_update(
        filter={"_id": ObjectId(payload["id"])},
        update={"$set": user_data.model_dump(exclude_unset=True)},
        projection={"_id": 0, "password": 0, "is_account_enable": 0},
        return_document=ReturnDocument.AFTER)
    result["id"] = payload["id"]
    return result


@routers.patch("/change_password", status_code=status.HTTP_200_OK)
async def profile_update(user_data: ChangePassword, payload: dict = Depends(get_access_jwt_aut()), db=Depends(get_db)):
    """
    The profile_update function allows a user to change their password.
        The function takes in the old and new passwords, as well as the payload from get_access_jwt_auth().
        It then finds the user's account in MongoDB using their id from the payload.
        If it can't find an account with that id, it raises a HTTPException with status code 403 (Forbidden).
        Otherwise, if it does find an account with that id, but its password doesn't match what was entered by the user:
            - It raises another HTTPException with status code 403 (Forbidden) and

    :param user_data: ChangePassword: Get the data from the request body
    :param payload: dict: Get the id of the user from the token
    :param db: Access the database
    :return: A dictionary of the password change successfully

    """
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
async def reset_password_request(user_email: BaseUser, db=Depends(get_db)):
    """
    The reset_password_request function is used to send a reset password code to the user's email.
        The function takes in an email and checks if it exists in the database. If it does, then a code will be sent
        to that email address.

    :param user_email: BaseUser: Get the email of the user
    :param db: Access the database
    :return: A string, which is the message that will be sent to the user
    """
    users = db["accounts"]
    result = await users.find_one({"email": user_email.email}, {"_id": 1, "email": 1})
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email does not exist")

    await notification_client.code_call({"email": result["email"], "action": "reset password"})
    return {"A code was sent to your email"}


@routers.patch("/reset_password", status_code=status.HTTP_200_OK)
async def reset_password(reset_password_info: ResetPassword, db=Depends(get_db)):
    """
    The reset_password function takes in a ResetPassword object and returns a string.
    The function decodes the token, finds the user with that id, and updates their password to be the new_password.

    :param reset_password_info: ResetPassword: Validate the data that is sent to the function
    :param db: Access the database
    :return: A dictionary with a key-value pair
    """
    reset_password_info = reset_password_info.model_dump()
    try:
        payload = await decode_token(reset_password_info["token"])
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    users = db["accounts"]
    await users.find_one_and_update(
        filter={"_id": ObjectId(payload["id"])},
        update={"$set": {"password": get_password_hash(reset_password_info["new_password"])}},
    )
    # publisher to delete code from redis
    return {"password changed successfully"}
