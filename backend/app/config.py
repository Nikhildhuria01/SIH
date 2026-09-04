import os
from dotenv import load_dotenv
load_dotenv()
SUPABASE_URL=os.getenv('SUPABASE_URL','')
SUPABASE_PUBLISHABLE_KEY=os.getenv('SUPABASE_PUBLISHABLE_KEY','')
SUPABASE_SERVICE_ROLE_KEY=os.getenv('SUPABASE_SERVICE_ROLE_KEY','')
