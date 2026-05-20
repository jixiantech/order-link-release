"""
cancel_order.py - 苹果订单取消

流程:
1. xc → guest → order/detail → signIn/orders（拿 callBackUrl + stk）
2. Shield
3. SRP 登录
4. POST callBackUrl (authX) → 建立 Store session
5. GET order/detail → 拿 cancelItem URL + stk
6. POST cancelItem → 拿 confirm URL
7. POST confirm → 取消完成 ✅
"""

import os, re, math, hashlib, base64, time, random, string, warnings, json
from curl_cffi import requests
from bs4 import BeautifulSoup
from urllib.parse import quote, unquote
from typing import Optional

warnings.filterwarnings('ignore')

# ── GSA SRP ───────────────────────────────────────────────────────
N = int(
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050"
    "a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50"
    "e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8"
    "55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773b"
    "ca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748"
    "544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6"
    "af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb6"
    "94b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73",
    16)
G = 2
N_LEN = 256

def _sha256(*args):
    h = hashlib.sha256()
    for a in args: h.update(a)
    return h.digest()

def _sha256_int(*args):
    return int.from_bytes(_sha256(*args), 'big')

def _bytes_from_bigint(x):
    if x == 0: return b'\x00'
    return x.to_bytes(math.ceil(x.bit_length() / 8), 'big')

def _pad(x, length=N_LEN):
    b = _bytes_from_bigint(x)
    return b'\x00' * (length - len(b)) + b if len(b) < length else b

def _derive_password(protocol, password, salt, iterations):
    ph = hashlib.sha256(password.encode()).digest()
    if protocol == 's2k_fo':
        ph = ph.hex().encode()
    return hashlib.pbkdf2_hmac('sha256', ph, salt, iterations, 32)

class GSASRPClient:
    def __init__(self, username):
        self.username = username.lower()
        self._a = int.from_bytes(os.urandom(N_LEN), 'big') % N
        self.A = pow(G, self._a, N)
        self._k = _sha256_int(_bytes_from_bigint(N), _pad(G))
        self._K = self._M = None

    def get_A_b64(self):
        return base64.b64encode(_bytes_from_bigint(self.A)).decode()

    def process(self, protocol, password, salt, B_bytes, iterations):
        B = int.from_bytes(B_bytes, 'big')
        u = _sha256_int(_pad(self.A), _pad(B))
        derived = _derive_password(protocol, password, salt, iterations)
        x = _sha256_int(salt, _sha256(b'' + b':' + derived))
        S = pow((B - pow(G, x, N) * self._k) % N, self._a + u * x, N)
        self._K = _sha256(_bytes_from_bigint(S))
        hNg = bytes(a ^ b for a, b in zip(_sha256(_bytes_from_bigint(N)), _sha256(_pad(G))))
        self._M = _sha256(hNg, _sha256(self.username.encode()), salt,
                          _bytes_from_bigint(self.A), B_bytes, self._K)

    def get_M1_b64(self): return base64.b64encode(self._M).decode()
    def get_M2_b64(self):
        return base64.b64encode(_sha256(_bytes_from_bigint(self.A), self._M, self._K)).decode()

# ── Hashcash ──────────────────────────────────────────────────────
def _compute_hc(bits, challenge):
    ts = time.strftime('%Y%m%d%H%M%S', time.gmtime())
    prefix = f"1:{bits}:{ts}:{challenge}::"
    zeros = bits // 4
    for nonce in range(10_000_000):
        attempt = f"{prefix}{nonce}"
        if hashlib.md5(attempt.encode()).hexdigest()[:zeros] == '0' * zeros:
            return attempt
    return f"{prefix}0"

# ── Shield ────────────────────────────────────────────────────────
def get_shield_cookies(session):
    session.get("https://www.apple.com/shop/bag", timeout=10)
    r = session.get("https://www.apple.com/shop/shld/work/v1/q",
                    params={"jr": 30},
                    headers={"Referer": "https://www.apple.com/shop/bag"}, timeout=10)
    if r.status_code != 200:
        return False
    d = r.json()

    def bt(rem, n, mn, cur, deadline):
        if time.time() > deadline: return None
        if n == 0: return cur[:] if rem == 1 else None
        for v in range(mn, int(d["high"]) + 1):
            if v < int(d["low"]) or rem % v != 0: continue
            cur.append(v)
            res = bt(rem // v, n - 1, v, cur, deadline)
            if res is not None: return res
            cur.pop()
        return None

    numbers = bt(int(d["result"]), int(d["parts"]), int(d["low"]), [], time.time() + 2) or []
    session.post("https://www.apple.com/shop/shld/work/v1/q",
                 params={"jr": 30},
                 json={**d, "number": numbers, "took": 0, "flagskv": {"patSkip": True}},
                 headers={"Referer": "https://www.apple.com/shop/bag",
                          "Content-Type": "application/json"}, timeout=10)
    ok = "shld_bt_ck" in {c.name for c in session.cookies}
    print(f"[Shield] {'✅' if ok else '❌'}")
    return ok

# ── Constants ─────────────────────────────────────────────────────
WIDGET_KEY = "a797929d224abb1cc663bb187bbcd02f7172ca3a84df470380522a7c6092118b"
CLIENT_INFO = '{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"Ca44j1e3NlY5BNlY5BSs5uQ32SCVggjLzgua_8umrk5i.uJtHoqvynx9MsFyxY25CCokg91kNscI_Fe0iyKyaKyaMrgNNlY5BNp55BNlan0Os5Apw.BAY"}'
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

def _rand_state():
    chars = string.ascii_lowercase + string.digits
    return 'auth-' + '-'.join(''.join(random.choices(chars, k=l)) for l in [8,4,4,4,12])

def _ui_fetch_call():
    chars = string.ascii_lowercase + string.digits
    p1 = ''.join(random.choices(chars, k=10))
    p2 = ''.join(random.choices(chars, k=8))
    return f"{p1}-{p2}"

# ── SRP Login ─────────────────────────────────────────────────────
def srp_login(session, username, password, redirect_url):
    state = _rand_state()
    r = session.get(
        "https://idmsa.apple.com/appleauth/auth/authorize/signin",
        params={"frame_id": state, "skVersion": "7", "iframeId": state,
                "client_id": WIDGET_KEY, "redirect_uri": redirect_url,
                "response_type": "code", "response_mode": "web_message",
                "state": state, "authVersion": "latest"},
        headers={"User-Agent": UA, "Referer": redirect_url,
                 "sec-fetch-dest": "iframe", "sec-fetch-mode": "navigate",
                 "sec-fetch-site": "cross-site"}, timeout=10)
    if r.status_code != 200:
        print(f"[SRP] authorize failed: {r.status_code}")
        return None

    scnt = r.headers.get("scnt", "")
    attributes = r.headers.get("x-apple-auth-attributes", "")
    session_id = r.headers.get("x-apple-id-session-id", "")
    hc_bits = int(r.headers.get("x-apple-hc-bits", "10"))
    hc_challenge = r.headers.get("x-apple-hc-challenge", "")
    domain_id = "39"
    m = re.search(r'"domainId"\s*:\s*(\d+)', r.text)
    if m: domain_id = m.group(1)
    print(f"[SRP] authorize OK, domain_id={domain_id}")

    ctx = {"scnt": scnt, "attributes": attributes, "sessionId": session_id,
           "hcBits": hc_bits, "hcChallenge": hc_challenge,
           "domainId": domain_id, "frameId": state}

    def _h(extra=None):
        h = {"Accept": "application/json",
             "Content-Type": "application/json; charset=UTF-8",
             "User-Agent": UA, "scnt": ctx["scnt"],
             "x-apple-auth-attributes": ctx["attributes"],
             "x-apple-frame-id": ctx["frameId"],
             "x-apple-domain-id": ctx["domainId"],
             "x-apple-i-fd-client-info": CLIENT_INFO,
             "x-apple-id-session-id": ctx["sessionId"],
             "x-apple-oauth-client-id": WIDGET_KEY,
             "x-apple-oauth-client-type": "firstPartyAuth",
             "x-apple-oauth-redirect-uri": redirect_url,
             "x-apple-oauth-response-mode": "web_message",
             "x-apple-oauth-response-type": "code",
             "x-apple-oauth-state": ctx["frameId"],
             "x-apple-widget-key": WIDGET_KEY,
             "x-requested-with": "XMLHttpRequest",
             "Origin": "https://idmsa.apple.com",
             "Referer": "https://idmsa.apple.com/"}
        if extra: h.update(extra)
        return h

    # Federate
    r = session.post(
        "https://idmsa.apple.com/appleauth/auth/federate?isRememberMeEnabled=true",
        json={"accountName": username, "rememberMe": False},
        headers=_h(), timeout=10)
    if r.status_code == 200:
        ctx["scnt"] = r.headers.get("scnt", ctx["scnt"])
    print(f"[SRP] federate: {r.status_code}")

    # Init
    srp = GSASRPClient(username)
    r = session.post(
        "https://idmsa.apple.com/appleauth/auth/signin/init",
        json={"a": srp.get_A_b64(), "accountName": username.lower(),
              "protocols": ["s2k", "s2k_fo"]},
        headers=_h(), timeout=10)
    if r.status_code != 200:
        print(f"[SRP] init failed: {r.status_code}")
        return None
    ctx["scnt"] = r.headers.get("scnt", ctx["scnt"])
    d = r.json()
    salt = base64.b64decode(d["salt"])
    B_bytes = base64.b64decode(d["b"])
    iterations = d["iteration"]
    protocol = d["protocol"]
    c = d["c"]
    print(f"[SRP] init OK, protocol={protocol}, iter={iterations}")

    # Complete
    srp.process(protocol, password, salt, B_bytes, iterations)
    hc = _compute_hc(hc_bits, hc_challenge)
    r = session.post(
        "https://idmsa.apple.com/appleauth/auth/signin/complete",
        params={"isRememberMeEnabled": "true"},
        json={"accountName": username, "rememberMe": False,
              "m1": srp.get_M1_b64(), "c": c, "m2": srp.get_M2_b64()},
        headers=_h({"x-apple-hc": hc}), timeout=10)
    print(f"[SRP] complete: {r.status_code}, authType={r.json().get('authType','')}")
    if r.status_code not in (200, 409):
        return None
    ctx["scnt"] = r.headers.get("scnt", ctx["scnt"])
    return ctx

# ── AuthX ─────────────────────────────────────────────────────────
def post_authx(session, callback_url, secure_base, stk):
    r = session.post(
        callback_url, data="grantCode=",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Origin": secure_base, "User-Agent": UA,
                 "x-aos-stk": stk, "x-aos-model-page": "signInPage",
                 "x-requested-with": "Fetch", "syntax": "graviton",
                 "Accept": "*/*", "Referer": secure_base + "/"},
        timeout=10)
    print(f"[AuthX] status: {r.status_code}")
    if r.status_code == 200:
        try:
            redirect_url = r.json().get("head", {}).get("data", {}).get("url", "")
            if "%25" in redirect_url:
                redirect_url = unquote(redirect_url)
            print(f"[AuthX] redirect → {redirect_url[:80]}")
            return redirect_url
        except Exception:
            pass
    return None

# ── Helpers ───────────────────────────────────────────────────────
def _parse_init_data(html):
    soup = BeautifulSoup(html, 'html.parser')
    el = soup.find('script', id='init_data')
    if not el: return None
    try: return json.loads(el.string)
    except Exception: return None

def _extract_ssi(text):
    m = re.search(r'[?&]ssi=([^&"\'>\s]+)', text)
    return m.group(1) if m else None

def _aos_headers(secure_base, stk, detail_url):
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "connection": "close",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "syntax": "graviton",
        "modelversion": "v2",
        "x-aos-model-page": "OrderStatusDetail",
        "x-aos-stk": stk,
        "x-requested-with": "Fetch",
        "Accept": "application/json, */*",
        "Origin": secure_base,
        "Referer": detail_url,
        "User-Agent": UA,
    }

# ── Main ──────────────────────────────────────────────────────────
def cancel_order(order_number, order_email, apple_id, apple_password,
                 phone, proxy=None, max_retries=3):
    for attempt in range(max_retries):
        try:
            result = _cancel_order_once(order_number, order_email, apple_id,
                                        apple_password, phone, proxy=make_proxy())
            if result.get("success"):
                return result
            err = result.get("error", "")
            if any(k in err for k in ["连接失败", "超时", "proxy", "timeout", "502", "503"]):
                print(f"[Cancel] 代理失效，重试 {attempt+1}/{max_retries}")
                continue
            return result
        except Exception as e:
            err = str(e)
            if any(k in err.lower() for k in ["timeout", "connection", "proxy", "502", "503"]):
                print(f"[Cancel] 代理异常，重试 {attempt+1}/{max_retries}")
                continue
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "代理多次失效，请检查代理设置"}


def _cancel_order_once(order_number, order_email, apple_id, apple_password,
                 phone, proxy=None):
    import time as _time
    _start = _time.time()

    import requests as _std_requests
    session = _std_requests.Session()
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})

    try:
        ip = session.get("https://api.ipify.org", timeout=10).text.strip()
        print(f"[Cancel] 代理 IP: {ip}")
    except Exception as e:
        print(f"[Cancel] IP: {e}")

    # Step 1: xc → secure_base
    print("[Cancel] Step 1: xc")
    r = session.get(
        f"https://www.apple.com/xc/us/vieworder/{order_number}/{order_email}",
        allow_redirects=False, timeout=10)
    location = r.headers.get("location", "")
    m = re.match(r'(https://secure[\w]*\.store\.apple\.com)/shop/order/guest/[^/]+/([a-f0-9]+)', location)
    if not m:
        return {"success": False, "error": f"订单链接无效或已过期"}
    secure_base = m.group(1)
    token = m.group(2)
    if secure_base == "https://secure.store.apple.com":
        r2 = session.get(location, allow_redirects=False, timeout=10)
        m2 = re.match(r'(https://secure[\w]+\.store\.apple\.com)',
                      r2.headers.get("location", ""))
        if m2: secure_base = m2.group(1)
    print(f"[Cancel] secure_base: {secure_base}")

    # Step 2: guest → 建立 _cs cookie
    print("[Cancel] Step 2: guest")
    session.get(f"{secure_base}/shop/order/guest/{order_number}/{token}?e=true", timeout=10)
    print(f"[Cancel] guest OK")

    # Step 3: order/detail → 302 → signIn/orders?ssi=...
    print("[Cancel] Step 3: order/detail → ssi")
    r = session.get(
        f"{secure_base}/shop/order/detail/10078/{order_number}",
        allow_redirects=False, timeout=10,
        headers={"sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
                 "sec-fetch-site": "same-origin", "upgrade-insecure-requests": "1"})
    print(f"[Cancel] detail status: {r.status_code}")

    location3 = r.headers.get("location", "")
    ssi = _extract_ssi(location3)
    if not ssi:
        return {"success": False, "error": f"订单未绑定苹果账号，无法取消"}
    m3 = re.match(r'(https://secure[\w]+\.store\.apple\.com)', location3)
    if m3: secure_base = m3.group(1)
    print(f"[Cancel] ssi OK, secure_base: {secure_base}")

    # Step 4: GET signIn/orders → callBackUrl + stk
    print("[Cancel] Step 4: GET signIn/orders")
    r = session.get(f"{secure_base}/shop/signIn/orders?hgl=t&ssi={ssi}", timeout=10)
    print(f"[Cancel] signIn/orders: {r.status_code}")
    init_data = _parse_init_data(r.text)
    if not init_data:
        return {"success": False, "error": "登录页面解析失败，请重试"}

    callback_url = (init_data.get("signIn", {})
                    .get("customerLoginIDMS", {})
                    .get("d", {})
                    .get("callbackSignInUrl"))
    stk = init_data.get("meta", {}).get("h", {}).get("x-aos-stk")
    print(f"[Cancel] callbackURL: {callback_url[:60] if callback_url else 'None'}")
    print(f"[Cancel] stk: {stk[:20] if stk else 'None'}")

    # 注入 JS cookie (as_sfa 等)
    try:
        soup = BeautifulSoup(r.text, 'html.parser')
        for script in soup.find_all('script'):
            st = script.get_text()
            if 'document.cookie' in st:
                for cl in re.findall(r'document\.cookie\s*=\s*["\']([^"\']+)["\']', st):
                    parts = cl.split(';')
                    if parts and '=' in parts[0]:
                        n, v = parts[0].strip().split('=', 1)
                        session.cookies.set(n.strip(), v.strip(), domain='.apple.com')
                        print(f"[Cancel] 注入 cookie: {n.strip()}")
    except Exception as e:
        print(f"[Cancel] cookie inject error: {e}")

    if not callback_url or not stk:
        return {"success": False, "error": "登录信息获取失败，请重试"}

    # Step 5: Shield
    print("[Cancel] Step 5: Shield")
    get_shield_cookies(session)

    # Step 6: SRP 登录
    print("[Cancel] Step 6: SRP 登录")
    ctx = srp_login(session, apple_id, apple_password, secure_base)
    if not ctx:
        return {"success": False, "error": "苹果账号登录失败，请检查账号密码"}

    # Step 7: POST callBackUrl (authX)
    print("[Cancel] Step 7: POST callBackUrl")
    authx_url = post_authx(session, callback_url, secure_base, stk)
    if not authx_url:
        return {"success": False, "error": "登录授权失败，请重试"}

    # Step 8: GET order/detail → cancelItem URL + stk
    print("[Cancel] Step 8: GET order/detail")
    detail_url = f"{secure_base}/shop/order/detail/10078/{order_number}"
    r = session.get(detail_url, timeout=10,
                    headers={"sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
                             "sec-fetch-site": "same-origin", "sec-fetch-user": "?1",
                             "upgrade-insecure-requests": "1"})
    print(f"[Cancel] detail status: {r.status_code}")

    init_data = _parse_init_data(r.text)
    if not init_data:
        return {"success": False, "error": "订单详情页解析失败，请重试"}

    stk = init_data.get("meta", {}).get("h", {}).get("x-aos-stk")
    order_items = init_data.get("orderDetail", {}).get("orderItems", {}).get("c", [])
    print(f"[Cancel] order_items: {order_items}")

    cancel_urls = {}
    for item in order_items:
        item_data = init_data.get("orderDetail", {}).get("orderItems", {}).get(item, {})
        cancel_url = item_data.get("a", {}).get("cancelItem", {}).get("url")
        if cancel_url:
            cancel_urls[item] = cancel_url

    print(f"[Cancel] cancel_urls: {cancel_urls}")
    if not cancel_urls:
        return {"success": False, "error": "订单不支持取消，可能已发货或已取消"}

    # Step 9: POST cancelItem → confirm URL
    for item, cancel_url in cancel_urls.items():
        print(f"[Cancel] Step 9: POST cancelItem - {item}")
        r = session.post(cancel_url, data="",
                         headers=_aos_headers(secure_base, stk, detail_url),
                         timeout=10)
        print(f"[Cancel] cancelItem: {r.status_code}")
        print(f"[Cancel] cancelItem body: {r.text[:300]}")

        try:
            data = r.json()
            confirm_url = (data.get("body", {})
                           .get("orderDetail", {})
                           .get("orderItems", {})
                           .get(item, {})
                           .get("cancelOverlay", {})
                           .get("a", {})
                           .get("continue", {})
                           .get("url"))
            print(f"[Cancel] confirm_url: {confirm_url}")
            if not confirm_url:
                return {"success": False, "error": "取消确认链接获取失败，请重试"}

            # Step 10: POST confirm
            print(f"[Cancel] Step 10: POST confirm")
            r2 = session.post(confirm_url, data="",
                              headers=_aos_headers(secure_base, stk, detail_url),
                              timeout=10)
            print(f"[Cancel] confirm: {r2.status_code}")
            print(f"[Cancel] confirm body: {r2.text[:200]}")

        except Exception as e:
            return {"success": False, "error": f"error: {e}"}

    elapsed = _time.time() - _start
    print(f"[Cancel] ✅ 取消成功！耗时 {elapsed:.1f}s")
    return {"success": True, "order_number": order_number}


def make_proxy(session_id=None):
    if not session_id:
        session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return (f"http://smart-dn74k2mg6pjy_area-US_state-newyork_life-5_session-{session_id}"
            f":xejt59l0aseF8eBz@proxy.smartproxy.net:3120")


if __name__ == "__main__":
    result = cancel_order(
        order_number="W1831585427",
        order_email="qibiaowe@gmail.com",
        apple_id="alvesmaria864@yahoo.com",
        apple_password="Yx1992.1992",
        phone="9293105497",
        proxy=make_proxy(),
    )
    print("\n最终结果:", result)