from fastapi import FastAPI, Depends, HTTPException, status, Response, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyCookie
from fastapi.responses import RedirectResponse, JSONResponse
from supabase import Client
from app.database import get_db
from app.models import FundRequest, UserCreate, UserLogin, UserUpdate, TransactionCreate, TransactionResponse
from app.auth import hash_password, verify_password, create_access_token, verify_access_token
import random
from fastapi.exceptions import HTTPException as StarletteHTTPException 
from fastapi.exceptions import RequestValidationError


def raise_error(message: str, type: str, status_code: int = 400):
    raise HTTPException(
        status_code=status_code,
        detail={"message": message, "type": type}
    )

oauth2_scheme = APIKeyCookie(name="access_token", auto_error=False)

app = FastAPI(
    title="SecureFin API",
    description="Backend for the SecureFin Portal",
    version="1.0.0"
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error = exc.errors()[0]
    error_type = str(error["loc"][-1]) 
    message = error["msg"].replace("Value error, ", "")
    return JSONResponse(
        status_code=422,
        content={"message": message, "type": error_type},
    )


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"message": str(exc.detail), "type": "general"}},
    )

ORIGINS = [
    "https://secure-fin-auth-frontend-production.up.railway.app",
    "http://localhost:5173",
    "http://localhost:5174",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", include_in_schema=False)
async def root():
    """Redirects the base URL straight to the API documentation."""
    return RedirectResponse(url="/docs")

@app.get("/health")
async def health_check():
    """Basic health check route to verify deployment."""
    return {"status": "healthy", "service": "SecureFinBackend"}

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, db: Client = Depends(get_db)):
    #check if user already exists
    existing_user = db.table("users").select("*").eq("username", user.username).execute()
    if existing_user.data:
        raise_error("username already exist", "username")
    formatted_name = user.name.upper()
    #hash the password securely using bcrypt
    hashed_pw = hash_password(user.password)
    account_num = str(random.randint(10000000, 99999999))
    #insert into Supabase database
    new_user = {
        "username": user.username,
        "name": formatted_name,
        "password_hash": hashed_pw,
        "role": "user",
        "account_number": account_num
    }
    
    insert_response = db.table("users").insert(new_user).execute()
    
    if not insert_response.data:
        raise HTTPException(status_code=500, detail="Failed to create user")
        
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
async def login_user(credentials: UserLogin, response: Response, db: Client = Depends(get_db)):
    #fetch user from Supabase
    user_response = db.table("users").select("*").eq("username", credentials.username).execute()
    
    if not user_response.data:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    user = user_response.data[0]

    #verify password against the stored bcrypt hash
    if not verify_password(credentials.password, user["password_hash"]):
        raise_error("Invalid password or username", "auth", status_code=401)

    #generate Asymmetric JWT Token
    token_data = {"sub": user["id"], "role": user["role"], "username": user["username"]}
    token = create_access_token(token_data)

    #set the Secure HttpOnly Cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=15 * 60
    )

    #return only safe data to the frontend
    return {
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }

@app.post("/api/auth/logout")
async def logout_user(response: Response):
    """Clears the secure HttpOnly cookie to log the user out."""
    response.delete_cookie(
        key="access_token",
        httponly=True,
        secure=False,
        samesite="lax"
    )
    return {"message": "Logged out successfully"}

def get_current_user(request: Request, token: str = Security(oauth2_scheme)):
    """
    Dependency to extract the JWT from the secure HttpOnly cookie 
    and verify the user's session.
    """
    token = request.cookies.get("access_token") or token
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated. Please log in.")
    
    try:
        # verify the token using our asym public key
        payload = verify_access_token(token)
        return payload
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

def require_admin(current_user: dict = Depends(get_current_user)):
    """
    Dependency to enforce Role-Based Access Control (RBAC) for admin routes.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Insufficient privileges. Admin access required.")
    return current_user

@app.post("/api/transactions", status_code=status.HTTP_201_CREATED)
async def create_transaction(
    transaction: TransactionCreate, 
    current_user: dict = Depends(get_current_user), 
    db: Client = Depends(get_db)
):
    """
    Creates a transaction with Overdraft Protection and Account Number verification.
    """
    #overdraft protection
    user_record = db.table("users").select("balance").eq("id", current_user["sub"]).execute()
    if not user_record.data:
        raise HTTPException(status_code=404, detail="User account not found")
        
    current_balance = user_record.data[0]["balance"]

    if transaction.amount > current_balance:
        raise_error(f"Insufficient funds. Your balance is ${current_balance:.2f}", "funds")

    recipient_check = db.table("users").select("id").eq("account_number", transaction.recipient_account).execute()
    
    if not recipient_check.data:
        raise HTTPException(status_code=404, detail="Invalid routing. Account number does not exist.")

    if recipient_check.data[0]["id"] == current_user["sub"]:
        raise HTTPException(status_code=400, detail="You cannot send money to your own account.")
    new_tx = {
        "sender_id": current_user["sub"],
        "recipient_account": transaction.recipient_account,
        "amount": transaction.amount,
        "description": transaction.description,
        "status": "pending"
    }

    response = db.table("transactions").insert(new_tx).execute()

    if not response.data:
        raise HTTPException(status_code=500, detail="Database failed to create transaction")

    return {"message": "Transaction submitted", "transaction_id": response.data[0]["id"]}

@app.patch("/api/transactions/{transaction_id}/approve")
async def approve_transaction(
    transaction_id: str, 
    admin_user: dict = Depends(require_admin),
    db: Client = Depends(get_db)
):
    """
    Admin endpoint to approve a pending transaction
    """
    #verify the transaction exists and is pending
    tx_check = db.table("transactions").select("*").eq("id", transaction_id).execute()
    if not tx_check.data or tx_check.data[0]["status"] != "pending":
        raise HTTPException(status_code=400, detail="Transaction not found or already processed")

    #update the transaction status
    update_response = db.table("transactions").update({"status": "approved"}).eq("id", transaction_id).execute()
    
    if not update_response.data:
        raise HTTPException(status_code=500, detail="Database error during approval")

    #write to the Immutable Audit Log (OWASP Requirement)
    audit_entry = {
        "actor_id": admin_user["sub"],
        "action": "APPROVED_TRANSACTION",
        "target_transaction_id": transaction_id
    }
    db.table("audit_logs").insert(audit_entry).execute()

    return {"message": f"Transaction {transaction_id} successfully approved."}

@app.patch("/api/transactions/{transaction_id}/reject")
async def reject_transaction(
    transaction_id: str,
    current_user: dict = Depends(get_current_user),
    db: Client = Depends(get_db)
):
    """
    rejection endpoint
    """
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Unauthorized: Admin access required.")

    response = db.table("transactions")\
        .update({"status": "rejected"})\
        .eq("id", transaction_id)\
        .execute()

    if not response.data:
        raise HTTPException(status_code=404, detail="Transaction not found.")

    #logging
    db.table("audit_logs").insert({
        "actor_id": current_user["sub"],
        "action": "REJECT",
        "target_transaction_id": transaction_id,
        "timestamp": "now()"
    }).execute()

    return {"message": "Transaction has been successfully rejected."}

@app.get("/api/users/{user_id}")
async def get_user_profile(
    user_id: str, 
    current_user: dict = Depends(get_current_user), 
    db: Client = Depends(get_db)
):
    """Fetch a user's profile."""
    if current_user["sub"] != user_id and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to view this profile")

    # Fetch data
    response = db.table("users").select("id, username, name, role, balance, account_number").eq("id", user_id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="User not found")
        
    return response.data[0]

@app.get("/api/transactions/me")
async def get_my_transactions(
    current_user: dict = Depends(get_current_user), 
    db: Client = Depends(get_db)
):
    """
    Fetch all transactions for the currently logged in user 
    """
    user_record = db.table("users").select("account_number").eq("id", current_user["sub"]).execute()
    
    if not user_record.data:
        raise HTTPException(status_code=404, detail="User account not found")
    
    user_account_num = user_record.data[0]["account_number"]

    response = db.table("transactions") \
        .select("sender_id, recipient_account, amount, status, created_at") \
        .or_(f"sender_id.eq.{current_user['sub']},recipient_account.eq.{user_account_num}") \
        .execute()
    return {"transactions": response.data}

@app.patch("/api/users/{user_id}")
async def update_user(
    user_id: str, 
    update_data: UserUpdate,
    current_user: dict = Depends(get_current_user), 
    db: Client = Depends(get_db)
):
    """update user information"""
    # Security Check
    if current_user["sub"] != user_id and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to modify this profile")

    # Only update fields that were actually provided in the request
    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    
    if not update_dict:
        raise HTTPException(status_code=400, detail="No data provided to update")

    response = db.table("users").update(update_dict).eq("id", user_id).execute()
    
    if not response.data:
        raise HTTPException(status_code=500, detail="Failed to update user")
        
    return {"message": "User updated successfully", "user": response.data[0]}

@app.get("/api/auth/me")
async def get_current_session(
    current_user: dict = Depends(get_current_user), 
    db: Client = Depends(get_db)
):
    """
    check for who is logged in
    """
    return {
        "user_id": current_user["sub"],
        "username": current_user["username"],
        "role": current_user.get("role", "user"),
        # Now 'db' exists so this line will work perfectly!
        "account_number": db.table("users").select("account_number").eq("id", current_user["sub"]).execute().data[0]["account_number"]
    }

@app.post("/api/transactions/deposit")
async def deposit_funds(
    request: FundRequest, 
    current_user: dict = Depends(get_current_user), 
    db: Client = Depends(get_db)
):
    """Adds money to user balance"""
    #fetch current balance
    user_record = db.table("users").select("balance").eq("id", current_user["sub"]).execute()
    
    if not user_record.data:
        raise HTTPException(status_code=404, detail="User account not found")
        
    new_balance = user_record.data[0]["balance"] + request.amount

    #update database
    response = db.table("users").update({"balance": new_balance}).eq("id", current_user["sub"]).execute()

    if not response.data:
        raise HTTPException(status_code=500, detail="Failed to process deposit")

    return {
        "message": f"Successfully deposited ${request.amount:.2f}", 
        "new_balance": response.data[0]["balance"]
    }

@app.get("/api/admin/transactions")
async def get_all_transactions(
    current_user: dict = Depends(get_current_user), 
    db: Client = Depends(get_db)
):
    """
    Returns the entire transaction log
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403, 
            detail="Access Denied: Administrative privileges required."
        )

    response = db.table("transactions").select("*").execute()

    return {"transactions": response.data}