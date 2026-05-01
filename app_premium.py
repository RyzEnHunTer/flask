"""
PREMIUM SIGNAL GENERATOR
Fixed: duplicate pairs, real pair payout matching, deduplication
+ CloudFlare Bypass: TLS fingerprinting, proper headers, persistent connection
"""

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import secrets
import time
import os
import traceback
import asyncio
import threading
import logging
from market_analyzer import MarketAnalyzer
import cf_bypass  # MUST be imported BEFORE pyquotex — patches TLS/headers/WS
from pyquotex.stable_api import Quotex

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
CORS(app)

app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

# Suppress Flask/Werkzeug access logs (they pollute terminal during OTP input)
logging.getLogger('werkzeug').setLevel(logging.ERROR)

ROOT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings")
os.makedirs(ROOT_PATH, exist_ok=True)

quotex_client   = None
analyzer        = None
is_connected    = False
cached_pairs    = []
last_cache_time = 0

# ----- WEB-BASED OTP SYSTEM -----
# Shared bridge so Flask and pyquotex login.py use the SAME queue object.
import otp_bridge

# ─────────────────────────────────────────────────────────────
# FIX #5: PERSISTENT ASYNC EVENT LOOP
# Instead of creating a new event loop per request (which floods
# Quotex with connections), we run ONE persistent loop in a
# background daemon thread. All async work is dispatched to it.
# ─────────────────────────────────────────────────────────────
_bg_loop = asyncio.new_event_loop()

def _start_bg_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

_bg_thread = threading.Thread(target=_start_bg_loop, args=(_bg_loop,), daemon=True)
_bg_thread.start()


def run_async(coro, timeout=120):
    """Submit a coroutine to the persistent background event loop.
    This prevents creating new event loops per request (which caused
    duplicate WebSocket connections and Cloudflare rate limiting)."""
    future = asyncio.run_coroutine_threadsafe(coro, _bg_loop)
    return future.result(timeout=timeout)


@app.after_request
def add_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


# ─────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────

@app.route('/admin')
def admin_panel():
    return render_template('admin.html')

@app.route('/')
def dashboard():
    if not is_connected:
        return render_template('admin.html')
    return render_template('user_dashboard.html')


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    global quotex_client, analyzer, is_connected
    data     = request.json or {}
    email    = data.get('email', '').strip()
    password = data.get('password', '').strip()
    if not email or not password:
        return jsonify({"success": False, "message": "Email and password required"})

    async def do_connect():
        global quotex_client, analyzer, is_connected
        try:
            client = Quotex(email=email, password=password, lang="en", root_path=ROOT_PATH)
            check, reason = await client.connect()
            if check:
                quotex_client = client
                analyzer      = MarketAnalyzer(quotex_client)
                is_connected  = True
                return True, "Connected"
            return False, str(reason)
        except SystemExit:
            return False, "OTP failed or login cancelled"
        except Exception as e:
            traceback.print_exc()
            return False, str(e)

    try:
        success, message = run_async(do_connect(), timeout=300)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)})

    if success:
        session['admin'] = True
        return jsonify({"success": True, "message": message})
    return jsonify({"success": False, "message": message})


@app.route('/api/admin/otp/status', methods=['GET'])
def otp_status():
    """Check if the login flow is waiting for OTP."""
    return jsonify({"otp_needed": otp_bridge.otp_needed, "prompt": otp_bridge.otp_prompt})


@app.route('/api/admin/otp', methods=['POST'])
def submit_otp():
    """Submit OTP code from the web UI."""
    data = request.json or {}
    code = data.get('code', '').strip()
    if not code or not code.isdigit() or len(code) < 4:
        return jsonify({"success": False, "message": "Enter a valid numeric PIN code"})
    otp_bridge.otp_queue.put(code)
    otp_bridge.otp_needed = False
    return jsonify({"success": True, "message": "OTP submitted"})


@app.route('/api/admin/status', methods=['GET'])
def admin_status():
    return jsonify({"connected": is_connected})


@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    global quotex_client, analyzer, is_connected
    is_connected = False; quotex_client = None; analyzer = None
    session.clear()
    return jsonify({"success": True})


@app.route('/api/system/status', methods=['GET'])
def system_status():
    return jsonify({"online": is_connected})


# ─────────────────────────────────────────────────────────────
# PAIRS — fixed deduplication + payout matching
# ─────────────────────────────────────────────────────────────

@app.route('/api/pairs', methods=['GET'])
def get_pairs():
    global cached_pairs, last_cache_time
    if not is_connected or not quotex_client:
        return jsonify({"error": "System offline"}), 503
    if cached_pairs and (time.time() - last_cache_time) < 300:
        return jsonify({"pairs": cached_pairs})

    async def fetch():
        all_assets   = await quotex_client.get_all_assets()
        payment_data = quotex_client.get_payment()

        # ── DEBUG: print a sample to understand real data structure ──
        sample_keys = list(payment_data.keys())[:5]
        print(f"Sample payment keys: {sample_keys}")
        for k in sample_keys:
            print(f"  {k}: {payment_data[k]}")

        # ── Build payment lookup: cleaned_key → (display_name, pay_info) ──
        payment_lookup = {}
        for pay_name, pay_info in payment_data.items():
            if not isinstance(pay_info, dict):
                continue
            # Store under multiple cleaned variants for better matching
            clean = pay_name.replace('(OTC)', '').replace(' ', '').replace('/', '').replace('-', '').strip().upper()
            payment_lookup[clean] = (pay_name, pay_info)

        pairs_dict = {}  # keyed by base_code to deduplicate

        for asset_code, asset_info in all_assets.items():
            asset_str   = str(asset_code)
            is_otc_code = '_otc' in asset_str.lower()

            # Base code without _otc suffix
            base_code = asset_str.replace('_otc', '').replace('_OTC', '').upper()

            # ── Match payment data ──
            display_name = None
            payout       = 0.0
            is_open      = False

            # Try multiple clean variants
            for variant in [
                base_code,
                base_code.replace('_', ''),
                asset_str.upper().replace('_OTC', '').replace('_', ''),
            ]:
                if variant in payment_lookup:
                    display_name, pay_info = payment_lookup[variant]
                    is_open = pay_info.get('open', False)
                    payout  = _extract_payout(pay_info)
                    break

            # Fuzzy fallback
            if not display_name:
                for clean_key, (pay_name, pay_info) in payment_lookup.items():
                    if clean_key in base_code or base_code in clean_key:
                        display_name = pay_name
                        is_open      = pay_info.get('open', False)
                        payout       = _extract_payout(pay_info)
                        break

            if not display_name:
                display_name = asset_str

            # ── Fix display name for OTC ──
            if is_otc_code and '(OTC)' not in display_name:
                display_name = display_name.rstrip() + ' (OTC)'

            # ── Deduplication: prefer OTC version ──
            if base_code in pairs_dict:
                existing = pairs_dict[base_code]
                # Only replace if this is OTC and existing is not, or if better payout
                if is_otc_code and not existing['is_otc']:
                    pass  # replace with OTC version below
                elif payout <= existing['payout']:
                    continue  # keep existing

            pairs_dict[base_code] = {
                "code":     asset_str,
                "name":     display_name,
                "payout":   round(payout, 1),
                "is_open":  is_open,
                "is_otc":   is_otc_code,
                "category": _categorize(asset_str, display_name),
            }

        pairs = list(pairs_dict.values())
        # Filter out 0.0% pairs that have no display name match (junk assets)
        pairs = [p for p in pairs if p['payout'] > 0 or any(
            c.isalpha() for c in p['name'].replace('(OTC)', '').strip()
        )]
        pairs.sort(key=lambda x: x['payout'], reverse=True)
        return pairs

    try:
        pairs = run_async(fetch())
        cached_pairs    = pairs
        last_cache_time = time.time()
        print(f"Loaded {len(pairs)} pairs")
        return jsonify({"pairs": pairs})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


def _extract_payout(pay_info: dict) -> float:
    """Extract payout percentage from payment info dict"""
    # FIX: Try 'payment' FIRST (most reliable, never broken by API updates)
    for key in ['payment', 'percent', 'payout', 'profit_percent']:
        val = pay_info.get(key)
        if val:
            v = float(val)
            return v if v > 1 else v * 100

    # Try turbo_payment second
    turbo = pay_info.get('turbo_payment') or pay_info.get('turboPayment') or 0
    if turbo and float(turbo) > 0:
        v = float(turbo)
        return v if v > 1 else v * 100

    # Try profit dict (LAST — these indices are often broken in upstream pyquotex)
    profit = pay_info.get('profit') or {}
    if isinstance(profit, dict):
        for key in ['1M', '1m', '60', 'M1', 'm1']:
            val = profit.get(key)
            if val:
                v = float(val)
                return v if v > 1 else v * 100

    return 0.0


def _categorize(asset_code: str, display_name: str) -> str:
    a = asset_code.upper()
    d = display_name.upper()
    if any(x in a or x in d for x in ['BTC','ETH','LTC','XRP','DOGE','ADA','DOT','LINK','UNI','SOL','MATIC','SHIB','AVAX','ATOM','TON','APT']):
        return "Crypto"
    if any(x in a or x in d for x in ['GOLD','SILVER','OIL','GAS','CRUDE','BRENT','COPPER','PLATINUM','NATURAL']):
        return "Commodities"
    if any(x in a or x in d for x in ['AAPL','GOOGL','TSLA','MSFT','AMZN','META','NFLX','NVDA','AMD','INTEL','NIKE','DISNEY']):
        return "Stocks"
    return "Currency"


# ─────────────────────────────────────────────────────────────
# ANALYSIS
# ─────────────────────────────────────────────────────────────

@app.route('/api/analyze/<path:asset_identifier>', methods=['GET'])
def analyze_asset(asset_identifier):
    if not is_connected or not analyzer:
        return jsonify({"error": "System offline"}), 503

    async def do_analysis():
        asset_code = asset_identifier
        if ' ' in asset_identifier or '(' in asset_identifier:
            for pair in cached_pairs:
                if pair['name'] == asset_identifier:
                    asset_code = pair['code']
                    break
        return await analyzer.get_comprehensive_analysis(asset_code)

    try:
        analysis = run_async(do_analysis())
        if "error" in analysis:
            return jsonify({"error": analysis["error"]}), 400
        return jsonify(analysis)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/api/candles', methods=['GET'])
def get_candles():
    if not is_connected or not quotex_client:
        return jsonify({"error": "System offline"}), 503
    asset = request.args.get('asset', 'EURUSD_otc')

    async def fetch_candles():
        raw = await quotex_client.get_candles(asset, time.time(), 6000, 60)
        if not raw:
            return []
        result = []
        for c in raw[-50:]:
            o = float(c.get('open')  or c.get('o') or 0)
            cl= float(c.get('close') or c.get('c') or 0)
            h = float(c.get('high')  or c.get('h') or cl)
            l = float(c.get('low')   or c.get('l') or cl)
            d = 'CALL' if cl > o else ('PUT' if cl < o else 'NEUTRAL')
            result.append({"open":round(o,6),"close":round(cl,6),"high":round(h,6),"low":round(l,6),"direction":d})
        return result

    try:
        data = run_async(fetch_candles())
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/news', methods=['GET'])
def get_news():
    return jsonify([
        {"title": "Markets update: Volatility continues across major pairs"},
        {"title": "OTC markets active — momentum signals detected"},
        {"title": "Technical analysis: Key support levels being tested"},
    ])


if __name__ == '__main__':
    print("="*60)
    print("PREMIUM SIGNAL GENERATOR")
    print("Admin : http://localhost:5000/admin")
    print("="*60)
    app.run(host='0.0.0.0', port=5000, debug=False)
