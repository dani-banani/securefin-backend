import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv

load_dotenv()

import os
import os

def get_private_key():
    raw_key = os.getenv("PRIVATE_KEY_CONTENT")
    if raw_key:
        return raw_key.replace("\\n", "\n")
    if os.path.exists("private.pem"):
        with open("private.pem", "r") as f:
            return f.read()
    raise ValueError("Private key not found in environment or file system.")

PRIVATE_KEY = get_private_key()
if os.path.exists("private.pem"):
    with open("private.pem", "r") as f:
        PRIVATE_KEY = f.read()
else:
    PRIVATE_KEY = os.getenv("PRIVATE_KEY_CONTENT").replace("\\n", "\n")
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

# Hash password
def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    salt = bcrypt.gensalt()
    # bcrypt requires bytes, so we encode and decode
    hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_bytes.decode('utf-8')
# verify the hashed password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored bcrypt hash."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict) -> str:
    """Creates a stateless JWT signed with the Private RSA Key."""
    if not PRIVATE_KEY:
        raise RuntimeError("JWT_PRIVATE_KEY environment variable is not set.")
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt
# verify the access token
def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception as e:
        print(f"JWT Verification Failed: {e}") 
        raise ValueError("Invalid authentication token.")
    
