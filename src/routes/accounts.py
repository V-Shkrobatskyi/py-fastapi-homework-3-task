from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from datetime import datetime, timezone, timedelta

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

router = APIRouter(tags=["accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    registration_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserRegistrationResponseSchema:
    """
    Register a new user.

    Args:
        registration_data: User registration data
        db: Database session
        settings: Application settings

    Returns:
        UserRegistrationResponseSchema: Response containing user's email and message

    Raises:
        HTTPException: If user already exists or an error occurred during creation
    """
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == registration_data.email)
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {registration_data.email} already exists.",
        )
    try:
        user_group = await db.scalar(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User group not found.",
            )

        new_user = UserModel.create(
            email=registration_data.email,
            raw_password=registration_data.password,
            group_id=user_group.id,
        )
        new_user.is_active = False
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(
            user_id=new_user.id,
            token=f"activate_{new_user.id}_{datetime.now(timezone.utc).timestamp()}",
            expires_at=datetime.now(timezone.utc) + settings.ACTIVATION_TOKEN_LIFETIME,
        )

        db.add(activation_token)

        await db.commit()

        # TODO: Sending email with activation token to user's email address.

        return UserRegistrationResponseSchema(
            id=new_user.id,
            email=new_user.email,
            message="Please check your email address for activation link.",
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_account(
    activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    token = await db.scalar(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == activation_data.token)
        .where(ActivationTokenModel.user.has(UserModel.email == activation_data.email))
        .options(joinedload(ActivationTokenModel.user))
    )

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if token.expires_at.tzinfo is None:
        token_expires_at = token.expires_at.replace(tzinfo=timezone.utc)
    else:
        token_expires_at = token.expires_at

    if token_expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if token.user.is_active:
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token.user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> UserLoginResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == login_data.email))

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        token_record = RefreshTokenModel(
            user_id=user.id,
            token=refresh_token,
            expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=jwt_manager._REFRESH_KEY_TIMEDELTA_MINUTES),
        )
        db.add(token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    reset_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
) -> MessageResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == reset_data.email))

    if not user or not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    token = PasswordResetTokenModel(
        user_id=user.id,
        token=f"reset_{user.id}_{datetime.now(timezone.utc).timestamp()}",
        expires_at=datetime.now(timezone.utc) + settings.PASSWORD_RESET_TOKEN_LIFETIME,
    )
    db.add(token)
    await db.commit()

    # TODO: Send email with reset instructions

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password(
    reset_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == reset_data.email)
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        existing_token = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        token = await db.scalar(
            select(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.token == reset_data.token)
            .where(PasswordResetTokenModel.user_id == user.id)
            .options(joinedload(PasswordResetTokenModel.user))
        )

        if not token:
            if existing_token:
                await db.delete(existing_token)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        token_expires_at = (
            token.expires_at.replace(tzinfo=timezone.utc)
            if token.expires_at.tzinfo is None
            else token.expires_at
        )
        current_time = datetime.now(timezone.utc)

        if token_expires_at < current_time:
            await db.delete(token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        token.user.password = reset_data.password
        await db.delete(token)
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_token(
    refresh_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        token_data = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        user_id = token_data.get("user_id")
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token."
        )

    token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_data.refresh_token,
            RefreshTokenModel.user_id == user_id,
        )
    )

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user = await db.get(UserModel, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return TokenRefreshResponseSchema(access_token=access_token)
