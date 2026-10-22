from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from ..config import get_settings
from ..db import Doc, find_one, get_db, insert
from ..ratelimit import rate_limit
from ..schemas import ForgotPasswordIn, LoginIn, ResetPasswordIn, RegisterIn, TokenOut, UserOut, UserUpdate
from ..security import (
    create_access_token, create_reset_token, get_current_user, hash_password, user_from_reset_token, verify_password,
)
from ..services.alerts import send_password_reset

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit("register", 5, 3600))])
def register(body: RegisterIn, db: Database = Depends(get_db)) -> TokenOut:
    email = body.email.lower()
    if find_one(db, "users", {"email": email}):
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    try:
        user = insert(db, "users", {
            "email": email, "full_name": body.full_name.strip(), "organization": body.organization.strip(),
            "password_hash": hash_password(body.password), "alerts_enabled": True, "alert_min_severity": "high",
        })
    except DuplicateKeyError:  # two sign-ups racing for the same address
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    return TokenOut(access_token=create_access_token(user.id), user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenOut, dependencies=[Depends(rate_limit("login", 10, 300))])
def login(body: LoginIn, db: Database = Depends(get_db)) -> TokenOut:
    user = find_one(db, "users", {"email": body.email.lower()})
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    return TokenOut(access_token=create_access_token(user.id), user=UserOut.model_validate(user))


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(rate_limit("forgot", 5, 3600))])
def forgot_password(body: ForgotPasswordIn, tasks: BackgroundTasks, db: Database = Depends(get_db)) -> dict:
    # Same response whether or not the account exists, so this can't be used to discover registered emails.
    user = find_one(db, "users", {"email": body.email.lower()})
    if user is not None:
        if get_settings().run_scans_inline:
            send_password_reset(user, create_reset_token(user))  # serverless: finish before the function is frozen
        else:
            tasks.add_task(send_password_reset, user, create_reset_token(user))
    return {"message": "If an account exists for that email, a reset link is on its way."}


@router.post("/reset-password", dependencies=[Depends(rate_limit("reset", 10, 3600))])
def reset_password(body: ResetPasswordIn, db: Database = Depends(get_db)) -> dict:
    user = user_from_reset_token(body.token, db)
    if user is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This reset link is invalid or has expired. Request a new one.")
    db.users.update_one({"_id": user.id}, {"$set": {"password_hash": hash_password(body.password)}})
    return {"message": "Password updated. You can sign in now."}


@router.get("/me", response_model=UserOut)
def me(user: Doc = Depends(get_current_user)) -> Doc:
    return user


@router.patch("/me", response_model=UserOut)
def update_me(body: UserUpdate, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    changes = body.model_dump(exclude_none=True)
    if changes:
        db.users.update_one({"_id": user.id}, {"$set": changes})
        user.update(changes)
    return user
