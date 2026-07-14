from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Initialize FastAPI App
app = FastAPI(
    title="SecureFin API",
    description="Backend for the SecureFin Portal",
    version="1.0.0"
)

# whitelist frontend and localhost
ORIGINS = [
    "https://secure-fin-auth-frontend-production.up.railway.app",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)

@app.get("/health")
async def health_check():
    """Basic health check route to verify deployment."""
    return {"status": "healthy", "service": "SecureFinBackend"}