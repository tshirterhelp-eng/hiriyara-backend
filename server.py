from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import uuid
import logging
import bcrypt
import jwt as pyjwt
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBearer
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, ConfigDict


# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("hiriyara")


# ---------- DB ----------
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]


# ---------- App ----------
app = FastAPI(title="Hiriyara Mane API")
api_router = APIRouter(prefix="/api")


# ---------- Auth utilities ----------
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 8


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
        "type": "access",
    }
    return pyjwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(request: Request) -> dict:
    token: Optional[str] = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = pyjwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user.pop("_id", None)
        user.pop("password_hash", None)
        return user
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------- Models ----------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthUser(BaseModel):
    id: str
    email: EmailStr
    name: str
    role: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: AuthUser


class EnquiryCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=6, max_length=30)
    email: Optional[EmailStr] = None
    message: str = Field(min_length=5, max_length=2000)
    relation: Optional[str] = Field(default=None, max_length=80)


class Enquiry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    phone: str
    email: Optional[str] = None
    message: str
    relation: Optional[str] = None
    status: str = "new"
    created_at: str


class EnquiryStatusUpdate(BaseModel):
    status: str


# ---------- Routes: Public ----------
@api_router.get("/")
async def root():
    return {"message": "Hiriyara Mane API", "status": "ok"}


@api_router.get("/healthz")
async def healthz():
    return {"ok": True}


@api_router.post("/enquiries", response_model=Enquiry, status_code=201)
async def create_enquiry(payload: EnquiryCreate):
    doc = {
        "id": str(uuid.uuid4()),
        "name": payload.name.strip(),
        "phone": payload.phone.strip(),
        "email": payload.email.lower().strip() if payload.email else None,
        "message": payload.message.strip(),
        "relation": payload.relation.strip() if payload.relation else None,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.enquiries.insert_one(doc)
    doc.pop("_id", None)
    return Enquiry(**doc)


# ---------- Routes: Auth ----------
@api_router.post("/auth/login", response_model=AuthResponse)
async def login(payload: LoginRequest, response: Response):
    email = payload.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(user["id"], user["email"])
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        path="/",
    )
    return AuthResponse(
        access_token=token,
        user=AuthUser(id=user["id"], email=user["email"], name=user["name"], role=user["role"]),
    )


@api_router.get("/auth/me", response_model=AuthUser)
async def me(current_user: dict = Depends(get_current_user)):
    return AuthUser(
        id=current_user["id"],
        email=current_user["email"],
        name=current_user["name"],
        role=current_user["role"],
    )


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


# ---------- Routes: Admin (protected) ----------
@api_router.get("/admin/enquiries", response_model=List[Enquiry])
async def list_enquiries(current_user: dict = Depends(get_current_user)):
    cursor = db.enquiries.find({}, {"_id": 0}).sort("created_at", -1)
    items = await cursor.to_list(length=1000)
    return [Enquiry(**i) for i in items]


@api_router.patch("/admin/enquiries/{enquiry_id}", response_model=Enquiry)
async def update_enquiry_status(
    enquiry_id: str,
    payload: EnquiryStatusUpdate,
    current_user: dict = Depends(get_current_user),
):
    allowed = {"new", "contacted", "closed"}
    if payload.status not in allowed:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(allowed)}")
    result = await db.enquiries.find_one_and_update(
        {"id": enquiry_id},
        {"$set": {"status": payload.status}},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Enquiry not found")
    result.pop("_id", None)
    return Enquiry(**result)


@api_router.delete("/admin/enquiries/{enquiry_id}")
async def delete_enquiry(enquiry_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.enquiries.delete_one({"id": enquiry_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Enquiry not found")
    return {"ok": True}


@api_router.get("/admin/stats")
async def admin_stats(current_user: dict = Depends(get_current_user)):
    total = await db.enquiries.count_documents({})
    new = await db.enquiries.count_documents({"status": "new"})
    contacted = await db.enquiries.count_documents({"status": "contacted"})
    closed = await db.enquiries.count_documents({"status": "closed"})
    return {"total": total, "new": new, "contacted": contacted, "closed": closed}


# ---------- Startup ----------
@app.on_event("startup")
async def on_startup():
    # Indexes
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.enquiries.create_index("id", unique=True)
    await db.enquiries.create_index("created_at")

    # Seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@hiriyaramane.com").lower().strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        await db.users.insert_one(
            {
                "id": str(uuid.uuid4()),
                "email": admin_email,
                "password_hash": hash_password(admin_password),
                "name": "Hiriyara Mane Admin",
                "role": "admin",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.info("Seeded admin user: %s", admin_email)
    else:
        # Keep admin password in sync with .env (idempotent)
        if not verify_password(admin_password, existing["password_hash"]):
            await db.users.update_one(
                {"email": admin_email},
                {"$set": {"password_hash": hash_password(admin_password)}},
            )
            logger.info("Updated admin password from .env for: %s", admin_email)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


# ---------- Mount + CORS ----------
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)
