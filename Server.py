from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from datetime import datetime, timedelta
import uvicorn
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import logging

from databasemanager import DatabaseManager

# ==========================================
# LOGGING CONFIGURATION
# ==========================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==========================================
# ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
PORT = int(os.getenv("PORT", 9090))

if not SECRET_KEY:
    logger.error("SECRET_KEY not set in environment variables")
    raise ValueError("SECRET_KEY must be set")

# ==========================================
# DATABASE
# ==========================================

db = DatabaseManager()

# ==========================================
# FASTAPI
# ==========================================

app = FastAPI(
    title="FastAPI with Neon PostgreSQL",
    description="Production-ready FastAPI application with Neon PostgreSQL",
    version="1.0.0"
)

# ==========================================
# CORS
# ==========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# PASSWORD HASHING
# ==========================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# ==========================================
# JWT SECURITY
# ==========================================

security = HTTPBearer()

def create_access_token(data: dict):
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    payload.update({"exp": expire})
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

# ==========================================
# PYDANTIC MODELS
# ==========================================

class UserLoginModel(BaseModel):
    email: str
    password: str

class UserRegisterModel(BaseModel):
    email: str
    password: str
    name: str

class UserResponseModel(BaseModel):
    id: int
    email: str
    name: str

class TokenResponseModel(BaseModel):
    access_token: str
    token_type: str
    user: UserResponseModel

class MessageResponseModel(BaseModel):
    message: str

# ==========================================
# DATABASE FUNCTIONS
# ==========================================

def get_customers():
    conn = None
    cursor = None

    try:
        conn, cursor = db.get_connection()

        if conn is None or cursor is None:
            logger.error("Database connection failed")
            raise HTTPException(
                status_code=500,
                detail="Database connection error"
            )

        cursor.execute("SELECT * FROM customers")
        customers = cursor.fetchall()
        return customers

    except Exception as e:
        logger.error(f"Error fetching customers: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error fetching customers"
        )

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def get_user_by_email(email: str):
    conn = None
    cursor = None

    try:
        conn, cursor = db.get_connection()

        if conn is None or cursor is None:
            logger.error("Database connection failed")
            raise HTTPException(
                status_code=500,
                detail="Database connection error"
            )

        cursor.execute(
            "SELECT * FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()
        return user

    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error fetching user"
        )

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def create_user(user: UserRegisterModel):
    conn = None
    cursor = None

    try:
        conn, cursor = db.get_connection()

        if conn is None or cursor is None:
            logger.error("Database connection failed")
            raise HTTPException(
                status_code=500,
                detail="Database connection error"
            )

        hashed_password = hash_password(user.password)

        cursor.execute(
            """
            INSERT INTO users (email, _password, name)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (
                user.email,
                hashed_password,
                user.name
            )
        )

        user_id = cursor.fetchone()['id']
        conn.commit()
        
        logger.info(f"User created successfully with ID: {user_id}")
        return user_id

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="Error creating user"
        )

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ==========================================
# AUTHENTICATE USER
# ==========================================

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    
    if user:
        if verify_password(password, user["_password"]):
            return user
    
    return None

# ==========================================
# GET CURRENT USER FROM TOKEN
# ==========================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )

        email = payload.get("sub")

        if email is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        user = get_user_by_email(email)

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="User not found"
            )

        return user

    except JWTError as e:
        logger.error(f"JWT Error: {e}")
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

# ==========================================
# HEALTH CHECK ENDPOINT
# ==========================================

@app.get("/health", response_model=MessageResponseModel)
async def health_check():
    """
    Health check endpoint to verify service status
    """
    try:
        # Test database connection
        conn, cursor = db.get_connection()
        if conn and cursor:
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()
            return {"message": "Service is healthy"}
        else:
            raise HTTPException(status_code=503, detail="Database connection failed")
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service is unhealthy")

# ==========================================
# ROOT ENDPOINT
# ==========================================

@app.get("/")
async def root():
    """
    Root endpoint with API information
    """
    return {
        "message": "Welcome to FastAPI with Neon PostgreSQL",
        "docs": "/docs",
        "redoc": "/redoc",
        "version": "1.0.0"
    }

# ==========================================
# CUSTOMERS ROUTE
# ==========================================

@app.get("/customers")
async def read_customers():
    """
    Get all customers (Public endpoint)
    """
    customers = get_customers()
    return {
        "customers": customers,
        "count": len(customers)
    }

# ==========================================
# LOGIN ROUTE
# ==========================================

@app.post("/login", response_model=TokenResponseModel)
def login(login_data: UserLoginModel):
    """
    Authenticate user and return access token
    """
    user = authenticate_user(
        login_data.email,
        login_data.password
    )

    if user is None:
        logger.warning(f"Failed login attempt for email: {login_data.email}")
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    access_token = create_access_token({
        "sub": user["email"]
    })

    logger.info(f"User logged in successfully: {user['email']}")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"]
        }
    }

# ==========================================
# REGISTER ROUTE
# ==========================================

@app.post("/register", response_model=MessageResponseModel)
def register(user: UserRegisterModel):
    """
    Register a new user
    """
    # Check if user already exists
    existing_user = get_user_by_email(user.email)

    if existing_user:
        logger.warning(f"Registration attempt with existing email: {user.email}")
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # Validate input
    if not user.email or not user.password or not user.name:
        raise HTTPException(
            status_code=400,
            detail="Email, password, and name are required"
        )

    # Create user
    create_user(user)

    logger.info(f"User registered successfully: {user.email}")

    return {
        "message": "User registered successfully"
    }

# ==========================================
# PROTECTED PROFILE ROUTE
# ==========================================

@app.get("/profile", response_model=UserResponseModel)
def profile(
    current_user: dict = Depends(get_current_user)
):
    """
    Get current user profile (Protected endpoint)
    """
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "name": current_user["name"]
    }

# ==========================================
# PROTECTED ADMIN ROUTE (Example)
# ==========================================

@app.get("/protected")
def protected_route(
    current_user: dict = Depends(get_current_user)
):
    """
    Example protected route (Protected endpoint)
    """
    return {
        "message": "You have accessed a protected route",
        "user": {
            "id": current_user["id"],
            "email": current_user["email"],
            "name": current_user["name"]
        },
        "timestamp": datetime.utcnow().isoformat()
    }

# ==========================================
# ERROR HANDLERS
# ==========================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """
    Custom HTTP exception handler for better error responses
    """
    return {
        "error": True,
        "status_code": exc.status_code,
        "detail": exc.detail,
        "timestamp": datetime.utcnow().isoformat()
    }

# ==========================================
# RUN SERVER
# ==========================================

if __name__ == "__main__":
    logger.info(f"Starting server on port {PORT}")
    logger.info(f"API Documentation available at http://localhost:{PORT}/docs")
    
    uvicorn.run(
        "Server:app",
        host="0.0.0.0",
        port=PORT,
        reload=False  # Set to False for production
    )
