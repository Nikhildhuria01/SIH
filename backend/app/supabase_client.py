import httpx
from supabase import create_client, ClientOptions
from .config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    supabase = None
else:
    # supabase-py's internal postgrest/auth/storage clients hardcode
    # http2=True. Some campus/hostel networks, VPNs and inspection
    # proxies silently break long-lived HTTP/2 streams, which surfaces
    # as a raw httpcore read error (not an HTTPException) and crashes
    # the ASGI connection before CORS headers can be attached — the
    # browser then misreports it as a CORS failure. Forcing HTTP/1.1
    # here avoids that class of failure.
    _http1_client = httpx.Client(http2=False, timeout=30)
    supabase = create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY,
        options=ClientOptions(httpx_client=_http1_client),
    )
