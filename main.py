import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext

from database import db

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr


# Utility functions

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.get("/health")
async def health():
    return {"status": "ok"}


# Auth routes
@app.post("/auth/register", response_model=UserPublic)
def register(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    existing = db["authuser"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": get_password_hash(payload.password),
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    res = db["authuser"].insert_one(user_doc)
    return {"id": str(res.inserted_id), "name": payload.name, "email": payload.email}


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    email = form_data.username
    password = form_data.password

    user = db["authuser"].find_one({"email": email})
    if not user or not verify_password(password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    token = create_access_token({"sub": str(user["_id"]), "email": user["email"], "name": user["name"]})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/me", response_model=UserPublic)
def me(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        if db is None:
            raise HTTPException(status_code=500, detail="Database not configured")
        user = db["authuser"].find_one({"email": email})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {"id": str(user["_id"]), "name": user["name"], "email": user["email"]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    
    try:
        # Try to import database module
        from database import db as dbref
        
        if dbref is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = dbref.name if hasattr(dbref, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            
            # Try to list collections to verify connectivity
            try:
                collections = dbref.list_collection_names()
                response["collections"] = collections[:10]  # Show first 10 collections
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
            
    except ImportError:
        response["database"] = "❌ Database module not found (run enable-database first)"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    
    # Check environment variables
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
