from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re

# AUTHENTICATION MODELS
class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Alphanumeric username")
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters")

class UserCreate(UserLogin):
    """Extends UserLogin with strict password complexity rules for registration."""
    
    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v

    @field_validator('username')
    @classmethod
    def validate_username_safe(cls, v):
        if not v.isalnum():
            raise ValueError("Username can only contain alphanumeric characters (prevents basic injection)")
        return v

class UserUpdate(BaseModel):
    username: Optional[str] = None

# TRANSACTION MODELS
class TransactionCreate(BaseModel):
    recipient_account: str = Field(..., description="6 to 8 digit account number")
    amount: float = Field(..., gt=0, description="Amount must be strictly greater than 0")
    description: Optional[str] = Field(None, max_length=255)
    @field_validator('recipient_account')
    @classmethod
    def validate_recipient(cls, v):
        if not re.match(r"^[1-9][0-9]{5,7}$", v):
            raise ValueError("Recipient account must be a valid 6-8 digit account number.")
        return v
    
class TransactionResponse(BaseModel):
    """Schema for returning data to the frontend without exposing internal database fields."""
    id: str
    amount: float
    recipient_account: str
    status: str
    created_at: str

class FundRequest(BaseModel):
    amount: float = Field(..., gt=0, description="Amount must be strictly greater than 0")