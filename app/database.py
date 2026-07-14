import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Supabase environment variables are missing.")
db: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_db() -> Client:
    """Dependency function"""
    return db