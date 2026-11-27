# OrderFlow: Authentication module
# Handles token creation, verification, and the login endpoint.

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Configuration (do not modify)

SECRET_KEY = "orderflow-secret-key-do-not-use-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

router = APIRouter(prefix="/auth", tags=["auth"])

# Simulated user store — passwords are bcrypt hash of "secret"
USERS_DB = {
    "alice@orderflow.com": {
        "email": "alice@orderflow.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "admin",
    },
    "bob@orderflow.com": {
        "email": "bob@orderflow.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "viewer",
    },
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Pydantic models (do not modify)

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None


class User(BaseModel):
    email: str
    role: str


# Helper utilities (do not modify)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_user(email: str) -> Optional[dict]:
    """Return the user dict from USERS_DB or None if not found."""
    return USERS_DB.get(email)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
   to_encode = data.copy()
   expire = datetime.utcnow() + (
       expires_delta
       if expires_delta is not None
       else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
   )
   to_encode.update({"exp": expire})
   return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> TokenData:
   credentials_exception = HTTPException(
       status_code=status.HTTP_401_UNAUTHORIZED,
       detail="Could not validate credentials",
       headers={"WWW-Authenticate": "Bearer"},
   )
   try:
       payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
       email: Optional[str] = payload.get("sub") or payload.get("email")
       role: Optional[str] = payload.get("role")
       if email is None:
           raise credentials_exception
       return TokenData(email=email, role=role)
   except JWTError:
       raise credentials_exception

decode_token = verify_token

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
   token_data = verify_token(token)
   user_dict = get_user(token_data.email)
   if user_dict is None:
       raise HTTPException(
           status_code=status.HTTP_401_UNAUTHORIZED,
           detail="Could not validate credentials",
           headers={"WWW-Authenticate": "Bearer"},
       )
   return User(email=user_dict["email"], role=user_dict["role"])

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
   user = get_user(form_data.username)
   if not user or not verify_password(form_data.password, user["hashed_password"]):
       raise HTTPException(
           status_code=status.HTTP_401_UNAUTHORIZED,
           detail="Incorrect email or password",
           headers={"WWW-Authenticate": "Bearer"},
       )
   access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
   access_token = create_access_token(
       data={"sub": user["email"], "email": user["email"], "role": user["role"]},
       expires_delta=access_token_expires,
   )
   return {"access_token": access_token, "token_type": "bearer"}

