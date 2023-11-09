import re
from typing import List

from fastapi import HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator, model_validator


class BaseUser(BaseModel):
    email: EmailStr


class UserSignUp(BaseUser):
    password: str
    confirmed_password: str
    is_account_enable: bool = False


class UserSignIn(BaseUser):
    password: str


class UserInfo(BaseUser):
    id: str


class UserProfileUpdate(BaseModel):
    email: EmailStr | None = None
    first_name: str | None = None
    last_name: str | None = None


class ShowUserProfile(UserInfo, UserProfileUpdate):
    pass


class PasswordMixins(BaseModel):
    new_password: str
    confirmed_new_password: str

    @model_validator(mode='after')
    def check_passwords_match(self):
        password = self.new_password
        confirmed_password = self.confirmed_new_password
        if password is not None and password != confirmed_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords don't match")
        return self

    @field_validator("new_password", mode="before")
    def validate_password(cls, value: str) -> str:
        PASSWORD_PATTERN = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-_]).{8,}$"
        if re.match(PASSWORD_PATTERN, value):
            return value
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Passwords must be at least 8 characters in length, '
                                   'and it must include at least one capital letter (or uppercase), '
                                   'one lowercase, one number and one special character')


class ChangePassword(PasswordMixins):
    old_password: str


class ResetPassword(PasswordMixins):
    code: str


class Verify(BaseModel):
    code: str


class UserIdList(BaseModel):
    data: List
