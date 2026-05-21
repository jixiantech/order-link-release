"""
apple_srp.py - 苹果订单绑定（完整复刻 Java 流程）

流程:
1. GET /us/shop/order/list → 跟随重定向 → 200页面含 callBackUrl + stk
2. Shield
3. SRP 登录（GSA 模式）
4. POST callBackUrl (grantCode=) → 绑定 Store session
5. GET link/verify → 200 含新 stk
6. POST linkx/verify → detail ✅
"""

import os, re, math, hashlib, base64, time, random, string, warnings, json
from curl_cffi import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, quote
from typing import Optional

warnings.filterwarnings('ignore')

# ── 2048-bit prime (GSA) ──────────────────────────────────────────
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
    length = math.ceil(x.bit_length() / 8)
    return x.to_bytes(length, 'big')

def _pad(x, length=N_LEN):
    b = _bytes_from_bigint(x)
    if len(b) >= length: return b
    return b'\x00' * (length - len(b)) + b

def _derive_password(protocol, password, salt, iterations):
    pass_hash = hashlib.sha256(password.encode('utf-8')).digest()
    if protocol == 's2k_fo':
        pass_hash = pass_hash.hex().encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', pass_hash, salt, iterations, 32)

class GSASRPClient:
    def __init__(self, username):
        self.username = username.lower()
        self._a = int.from_bytes(os.urandom(N_LEN), 'big') % N
        self.A = pow(G, self._a, N)
        N_bytes = _bytes_from_bigint(N)
        g_padded = _pad(G, N_LEN)
        self._k = _sha256_int(N_bytes, g_padded)
        self._K = None
        self._M = None

    def get_A_b64(self):
        return base64.b64encode(_bytes_from_bigint(self.A)).decode()

    def process(self, protocol, password, salt, B_bytes, iterations):
        B = int.from_bytes(B_bytes, 'big')
        if B % N == 0: raise ValueError("Invalid B")
        A_bytes = _bytes_from_bigint(self.A)
        u = _sha256_int(_pad(self.A, N_LEN), _pad(B, N_LEN))
        if u == 0: raise ValueError("u = 0")
        derived = _derive_password(protocol, password, salt, iterations)
        inner = b'' + b':' + derived
        hashed = _sha256(inner)
        x = _sha256_int(salt, hashed)
        gx = pow(G, x, N)
        t0 = (gx * self._k) % N
        t1 = (B - t0) % N
        t2 = self._a + u * x
        S = pow(t1, t2, N)
        K = _sha256(_bytes_from_bigint(S))
        self._K = K
        hN = _sha256(_bytes_from_bigint(N))
        hg = _sha256(_pad(G, N_LEN))
        hNg = bytes(a ^ b for a, b in zip(hN, hg))
        hi = _sha256(self.username.encode('utf-8'))
        M1 = _sha256(hNg, hi, salt, A_bytes, B_bytes, K)
        self._M = M1

    def get_M1_b64(self):
        return base64.b64encode(self._M).decode()

    def get_M2_b64(self):
        A_bytes = _bytes_from_bigint(self.A)
        M2 = _sha256(A_bytes, self._M, self._K)
        return base64.b64encode(M2).decode()

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
def _find_factors(result, parts, low, high, timeout_ms=2000):
    """迭代版本，比递归快"""
    deadline = time.time() + timeout_ms / 1000
    # 用栈模拟递归：(rem, n, min_val, current_list)
    stack = [(result, parts, low, [])]
    while stack:
        if time.time() > deadline:
            return None
        rem, n, mn, cur = stack.pop()
        if n == 0:
            if rem == 1:
                return cur
            continue
        for v in range(high, mn - 1, -1):  # 从大到小，让大因子先试（更快收敛）
            if v < low or rem % v != 0:
                continue
            stack.append((rem // v, n - 1, v, cur + [v]))
    return None

def get_shield_cookies(session, proxy=None):
    """Shield 用普通 requests 处理，然后把 cookie 同步到 curl_cffi session"""
    import requests as _std_requests
    import warnings
    warnings.filterwarnings('ignore')

    std_session = _std_requests.Session()
    std_session.verify = False
    if proxy:
        std_session.proxies = {"http": proxy, "https": proxy}
    elif session.proxies:
        try:
            std_session.proxies = dict(session.proxies)
        except Exception:
            pass
    std_session.headers.update({"User-Agent": UA})

    # 把 curl session 的 cookies 复制过来
    try:
        for c in session.cookies:
            std_session.cookies.set(c.name, c.value)
    except Exception:
        pass

    std_session.get("https://www.apple.com/shop/bag", timeout=10)
    r = std_session.get("https://www.apple.com/shop/shld/work/v1/q",
                    params={"jr": 30},
                    headers={"Referer": "https://www.apple.com/shop/bag"},
                    timeout=10)
    if r.status_code != 200:
        print(f"[Shield] failed: {r.status_code}")
        return False
    d = r.json()
    numbers = _find_factors(int(d["result"]), int(d["parts"]),
                            int(d["low"]), int(d["high"])) or []
    rp = std_session.post("https://www.apple.com/shop/shld/work/v1/q",
                 params={"jr": 30},
                 json={**d, "number": numbers, "took": 0, "flagskv": {"patSkip": True}},
                 headers={"Referer": "https://www.apple.com/shop/bag",
                          "Content-Type": "application/json"},
                 timeout=10)
    print(f"[Shield] POST status: {rp.status_code}")

    # 把 Shield cookies 同步回 curl session
    for c in std_session.cookies:
        try:
            session.cookies.set(c.name, c.value)
        except Exception:
            pass

    ok = "shld_bt_ck" in {c.name for c in std_session.cookies}
    print(f"[Shield] {'✅' if ok else '❌'}")
    return ok

# ── Constants ─────────────────────────────────────────────────────
WIDGET_KEY = "a797929d224abb1cc663bb187bbcd02f7172ca3a84df470380522a7c6092118b"
CLIENT_INFO = '{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"Ca44j1e3NlY5BNlY5BSs5uQ32SCVggjLzgua_8umrk5i.uJtHoqvynx9MsFyxY25CCokg91kNscI_Fe0iyKyaKyaMrgNNlY5BNp55BNlan0Os5Apw.BAY"}'

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

def _rand_state():
    parts = [8, 4, 4, 4, 12]
    chars = string.ascii_lowercase + string.digits
    return 'auth-' + '-'.join(''.join(random.choices(chars, k=l)) for l in parts)

def _ui_fetch_call():
    """生成随机 x-aos-ui-fetch-call-1，格式如 rfb3ncdd54-mp7nzl76"""
    chars = string.ascii_lowercase + string.digits
    p1 = ''.join(random.choices(chars, k=10))
    p2 = ''.join(random.choices(chars, k=8))
    return f"{p1}-{p2}"

# ── SRP Login ─────────────────────────────────────────────────────
def srp_login(session, username, password, redirect_url):
    state = _rand_state()

    # Authorize
    r = session.get(
        "https://idmsa.apple.com/appleauth/auth/authorize/signin",
        params={"frame_id": state, "skVersion": "7", "iframeId": state,
                "client_id": WIDGET_KEY, "redirect_uri": redirect_url,
                "response_type": "code", "response_mode": "web_message",
                "state": state, "authVersion": "latest"},
        headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                 "User-Agent": UA, "Referer": redirect_url,
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
           "domainId": domain_id, "frameId": state,
           "clientId": WIDGET_KEY, "redirectURL": redirect_url}

    def _h(extra=None):
        h = {"Accept": "application/json, text/javascript, */*; q=0.01",
             "Content-Type": "application/json; charset=UTF-8",
             "User-Agent": UA, "Accept-Language": "zh-CN,zh;q=0.9",
             "scnt": ctx["scnt"],
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
        print(f"[SRP] init failed: {r.status_code} {r.text[:200]}")
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
              "m1": srp.get_M1_b64(), "c": c,
              "m2": srp.get_M2_b64()},
        headers=_h({"x-apple-hc": hc}), timeout=10)

    print(f"[SRP] complete: {r.status_code}")
    if r.status_code not in (200, 409):
        print(f"[SRP] failed: {r.text[:300]}")
        return None

    ctx["scnt"] = r.headers.get("scnt", ctx["scnt"])
    ctx["attributes"] = r.headers.get("X-Apple-Auth-Attributes", ctx["attributes"])
    auth_type = r.json().get("authType", "")
    print(f"[SRP] authType={auth_type}")
    return ctx

# ── Parse init_data ───────────────────────────────────────────────
def _parse_init_data(html):
    soup = BeautifulSoup(html, 'html.parser')
    el = soup.find('script', id='init_data')
    if not el:
        return None
    try:
        return json.loads(el.string)
    except Exception:
        return None

def _extract_cs(text):
    try:
        qs = parse_qs(urlparse(text).query, keep_blank_values=True)
        if '_cs' in qs: return qs['_cs'][0]
    except Exception:
        pass
    m = re.search(r'[?&]_cs=([^&"\'>\s]+)', text)
    return m.group(1) if m else None

def _extract_ssi(text):
    m = re.search(r'[?&]ssi=([^&"\'>\s]+)', text)
    return m.group(1) if m else None

# ── AuthX ─────────────────────────────────────────────────────────
def post_authx(session, callback_url, secure_base, stk):
    r = session.post(
        callback_url,
        data="grantCode=",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Origin": secure_base, "User-Agent": UA,
                 "x-aos-stk": stk,
                 "x-aos-model-page": "signInPage",
                 "x-requested-with": "Fetch",
                 "syntax": "graviton",
                 "Accept": "*/*",
                 "Referer": secure_base + "/"},
        timeout=10)
    print(f"[AuthX] status: {r.status_code}, body: {r.text[:150]}")
    if r.status_code == 200:
        try:
            from urllib.parse import unquote
            redirect_url = r.json().get("head", {}).get("data", {}).get("url", "")
            # 如果有双重编码（%25 开头），先 decode 一次
            if "%25" in redirect_url:
                redirect_url = unquote(redirect_url)
            print(f"[AuthX] redirect_url: {redirect_url[:100]}")
            return redirect_url  # 返回完整 URL
        except Exception:
            pass
    return None

# ── Main ──────────────────────────────────────────────────────────
def link_order(order_number, order_email, apple_id, apple_password,
               phone, proxy=None, max_retries=3):
    """自动重试，代理失效时换新代理重试"""
    for attempt in range(max_retries):
        try:
            result = _link_order_once(order_number, order_email, apple_id,
                                      apple_password, phone, proxy=make_proxy())
            if result.get("success"):
                return result
            # 如果是代理问题，重试
            err = result.get("error", "")
            if any(k in err for k in ["连接失败", "超时", "proxy", "timeout", "502", "503"]):
                print(f"[Link] 代理失效，重试 {attempt+1}/{max_retries}")
                continue
            return result
        except Exception as e:
            err = str(e)
            if any(k in err.lower() for k in ["timeout", "connection", "proxy", "502", "503"]):
                print(f"[Link] 代理异常，重试 {attempt+1}/{max_retries}: {err[:50]}")
                continue
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "代理多次失效，请检查代理设置"}


def _link_order_once(order_number, order_email, apple_id, apple_password,
               phone, proxy=None):
    import time as _time
    _start = _time.time()
    phone = re.sub(r'[\s\-\(\)]', '', phone)

    import requests as _std_requests
    session = _std_requests.Session()
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({"User-Agent": UA, "Accept-Language": "zh-CN,zh;q=0.9"})

    # 打印代理 IP
    try:
        ip = session.get("https://api.ipify.org", timeout=10).text.strip()
        print(f"[Link] 代理 IP: {ip}")
    except Exception as e:
        print(f"[Link] IP 获取失败: {e}")

    # Step 1: xc → secure_base + token
    print("[Link] Step 1: xc")
    r = session.get(f"https://www.apple.com/xc/us/vieworder/{order_number}/{order_email}",
                    allow_redirects=False, timeout=10)
    location = r.headers.get("location", "")
    print(f"[Link] xc → {location[:100]}")

    m = re.match(r'(https://secure[\w]*\.store\.apple\.com)/shop/order/guest/[^/]+/([a-f0-9]+)', location)
    if not m:
        return {"success": False, "error": "订单链接无效或已过期"}
    secure_base = m.group(1)
    token = m.group(2)

    # 如果 secure_base 没有数字，跟进重定向
    if secure_base == "https://secure.store.apple.com":
        r2 = session.get(location, allow_redirects=False, timeout=10)
        loc2 = r2.headers.get("location", "")
        m2 = re.match(r'(https://secure[\w]+\.store\.apple\.com)', loc2)
        if m2: secure_base = m2.group(1)
    print(f"[Link] secure_base: {secure_base}")

    # Step 2: guest → _cs
    print("[Link] Step 2: guest")
    r = session.get(f"{secure_base}/shop/order/guest/{order_number}/{token}?e=true", timeout=10)
    cs = _extract_cs(r.text) or _extract_cs(str(r.url))
    if not cs:
        return {"success": False, "error": "无法获取订单会话，请重试"}
    cs_enc = quote(cs, safe='')
    print(f"[Link] _cs OK")

    # Step 3: link/verify → 拿 ssi
    print("[Link] Step 3: link/verify")
    r = session.get(f"{secure_base}/shop/order/link/verify?_cs={cs_enc}&csf=false&_w={order_number}",
                    allow_redirects=False, timeout=10)
    print(f"[Link] link/verify status: {r.status_code}")

    callback_url = None
    stk = None

    if r.status_code == 200:
        # 已登录
        ct = r.headers.get("Content-Type", "")
        if "application/json" in ct:
            try:
                body = r.json()
                stk = body["body"]["meta"]["h"]["x-aos-stk"]
                action_url = body["body"]["orderLinkModule"]["a"]["submit"]["url"]
                cs = _extract_cs(action_url) or cs
                cs_enc = quote(cs, safe='')
                print(f"[Link] 已登录（JSON），stk OK")
            except Exception as e:
                return {"success": False, "error": "绑定页面数据解析失败"}
        else:
            init_data = _parse_init_data(r.text)
            if init_data:
                stk = init_data.get("meta", {}).get("h", {}).get("x-aos-stk")
                print(f"[Link] 已登录（HTML），stk OK")
            else:
                return {"success": False, "error": "页面解析失败，请重试"}

    elif r.status_code in (302, 303):
        location2 = r.headers.get("location", "")
        ssi = _extract_ssi(location2)

        # 更新 secure_base
        m3 = re.match(r'(https://secure[\w]+\.store\.apple\.com)', location2)
        if m3: secure_base = m3.group(1)

        if not ssi:
            return {"success": False, "error": "登录跳转失败，请检查订单状态"}
        print(f"[Link] ssi OK")

        # Step 4: GET signIn/orders → 拿订单绑定专用的 callBackUrl + stk
        print("[Link] Step 4: GET signIn/orders")
        r = session.get(f"{secure_base}/shop/signIn/orders?hgl=t&ssi={ssi}",
                        headers={"x-aos-ui-fetch-call-1": _ui_fetch_call()},
                        timeout=10)
        print(f"[Link] signIn/orders status: {r.status_code}")
        init_data = _parse_init_data(r.text)
        if init_data:
            callback_url = (init_data.get("signIn", {})
                            .get("customerLoginIDMS", {})
                            .get("d", {})
                            .get("callbackSignInUrl"))
            stk = (init_data.get("meta", {}).get("h", {}).get("x-aos-stk"))
        print(f"[Link] callbackURL: {callback_url[:80] if callback_url else 'None'}")
        print(f"[Link] page_stk: {stk[:20] if stk else 'None'}")

        # 从页面 JS 里提取 document.cookie 设置的 cookies（跟 Java parseThirdStepResp 一样）
        try:
            soup = BeautifulSoup(r.text, 'html.parser')
            for script in soup.find_all('script'):
                script_text = script.get_text()
                if 'document.cookie' in script_text:
                    import re as _re
                    # 找所有 document.cookie = "..." 的设置
                    cookie_lines = _re.findall('document\.cookie\s*=\s*["\']([^"\']+)["\']', script_text)
                    for cookie_line in cookie_lines:
                        # 解析 cookie
                        parts = cookie_line.split(';')
                        if parts:
                            kv = parts[0].strip()
                            if '=' in kv:
                                name, value = kv.split('=', 1)
                                name = name.strip()
                                value = value.strip()
                                session.cookies.set(name, value, domain='.apple.com')
                                print(f"[Link] 注入 JS cookie: {name}={value[:20]}...")
        except Exception as e:
            print(f"[Link] JS cookie 提取失败: {e}")

        # Step 5: Shield
        print("[Link] Step 5: Shield")
        get_shield_cookies(session, proxy=proxy)

        # Step 6: SRP 登录
        print("[Link] Step 6: SRP 登录")
        ctx = srp_login(session, apple_id, apple_password, secure_base)
        if not ctx:
            return {"success": False, "error": "苹果账号登录失败，请检查账号密码"}

        # Step 7: POST callBackUrl
        if callback_url and stk:
            print("[Link] Step 7: POST callBackUrl")
            authx_redirect_url = post_authx(session, callback_url, secure_base, stk)
            if authx_redirect_url:
                new_cs = authx_redirect_url  # 保存完整 URL
                print(f"[Link] authX redirect: {authx_redirect_url[:80]}...")
            else:
                new_cs = None
                print("[Link] ⚠️ authX 没有返回 redirect URL")
        else:
            print("[Link] ⚠️ 没有 callBackUrl，跳过 authX")

        # Step 8: link/verify 第二次（直接用 authX 返回的 URL）
        print("[Link] Step 8: link/verify (after login)")
        # authX 返回的 URL 里已经有正确编码的 _cs，直接用
        if new_cs and new_cs.startswith("http"):
            link_verify_get_url = new_cs  # 整个 URL
        else:
            link_verify_get_url = f"{secure_base}/shop/order/link/verify?_cs={cs_enc}&csf=false&_w={order_number}"
        print(f"[Link] link/verify URL: {link_verify_get_url[:100]}")
        r = session.get(link_verify_get_url, timeout=10)
        print(f"[Link] link/verify status: {r.status_code}")
        print(f"[Link] Content-Type: {r.headers.get('Content-Type','')}")

        ct = r.headers.get("Content-Type", "")
        if r.status_code == 200:
            if "application/json" in ct:
                try:
                    body = r.json()
                    stk = body["body"]["meta"]["h"]["x-aos-stk"]
                    action_url = body["body"]["orderLinkModule"]["a"]["submit"]["url"]
                    cs = _extract_cs(action_url) or cs
                    cs_enc = quote(cs, safe='')
                    print(f"[Link] stk from JSON: {stk[:20]}...")
                except Exception as e:
                    return {"success": False, "error": "绑定页面数据解析失败"}
            else:
                init_data = _parse_init_data(r.text)
                if init_data:
                    stk = init_data.get("meta", {}).get("h", {}).get("x-aos-stk")
                    print(f"[Link] stk from HTML: {stk[:20] if stk else 'None'}...")
                    # 打印 singleOrderLookup 和 action url
                    sol = init_data.get("orderLinkModule", {}).get("d", {}).get("singleOrderLookup", "?")
                    action_url_from_init = init_data.get("orderLinkModule", {}).get("a", {}).get("submit", {}).get("url", "")
                    print(f"[Link] singleOrderLookup: {sol}")
                    print(f"[Link] action_url from init_data: {action_url_from_init[:100]}")
                    # 直接保存 action url（包含正确编码的 _cs）
                    try:
                        action_url = (init_data.get("orderLinkModule", {})
                                      .get("a", {}).get("submit", {}).get("url", ""))
                        if action_url:
                            linkx_action_url = action_url  # 直接用这个 URL
                            print(f"[Link] action_url from init_data: {action_url[:80]}...")
                    except Exception:
                        linkx_action_url = None
                else:
                    print(f"[Link] HTML snippet: {r.text[:500]}")
                    return {"success": False, "error": "登录后页面解析失败，请重试"}
        else:
            return {"success": False, "error": f"link/verify {r.status_code}: {r.text[:100]}"}

    if not stk:
        return {"success": False, "error": "登录后页面获取失败，请重试"}

    # Step 9: POST linkx/verify
    print(f"[Link] Step 9: linkx/verify, phone={phone}")

    # 用 init_data 里的 action URL（包含正确编码的 _cs）
    if 'linkx_action_url' in dir() and linkx_action_url:
        linkx_url = linkx_action_url
        link_verify_url = f"{secure_base}/shop/order/link/verify"
        print(f"[Link] 使用 init_data action_url")
    else:
        link_verify_url = f"{secure_base}/shop/order/link/verify?_cs={cs_enc}&csf=false&_w={order_number}"
        linkx_url = link_verify_url.replace("/link/", "/linkx/") + "&_a=submit&_m=orderLinkModule"
    
    linkx_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-aos-model-page": "orderLinkVerification",
        "syntax": "graviton",
        "modelversion": "v2",
        "x-aos-stk": stk,
        "x-aos-ui-fetch-call-1": f"{''.join(__import__('random').choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))}-mp{''.join(__import__('random').choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))}",
        "x-requested-with": "Fetch",
        "Accept": "*/*",
        "Origin": secure_base,
        "Referer": link_verify_url,
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "connection": "close",
    }

    # 先发手机号
    r = session.post(linkx_url,
                     data=f"orderLinkModule.phoneNumber={phone}",
                     headers=linkx_headers, timeout=10)
    print(f"[Link] linkx status: {r.status_code}")
    print(f"[Link] linkx response: {r.text[:400]}")

    try:
        data = r.json()
        redirect = data.get("head", {}).get("data", {}).get("url", "")
        status = data.get("head", {}).get("status", 0)

        if "detail" in redirect and ("sol=true" in redirect or "_ols=true" in redirect):
            elapsed = _time.time() - _start
            print(f"[Link] ✅ 绑定成功！耗时 {elapsed:.1f}s")
            return {"success": True, "order_number": order_number}

        # 302 跳转到 signIn/orders，跟进处理
        if status == 302 and "signIn/orders" in redirect:
            print(f"[Link] 302 跳转 signIn/orders，跟进...")
            r_sso = session.get(redirect, allow_redirects=True, timeout=10)
            print(f"[Link] signIn/orders status: {r_sso.status_code}")
            print(f"[Link] signIn/orders url: {r_sso.url[:100]}")
            print(f"[Link] signIn/orders body: {r_sso.text[:200]}")
            # 检查是否已绑定成功
            final_url = str(r_sso.url)
            if "sol=true" in final_url or "_ols=true" in final_url or "detail" in final_url:
                elapsed = _time.time() - _start
                print(f"[Link] ✅ 绑定成功！耗时 {elapsed:.1f}s")
                return {"success": True, "order_number": order_number}
            # 检查 body 里有没有成功标志
            if "sol=true" in r_sso.text or "_ols=true" in r_sso.text:
                elapsed = _time.time() - _start
                print(f"[Link] ✅ 绑定成功！耗时 {elapsed:.1f}s")
                return {"success": True, "order_number": order_number}
            return {"success": False, "error": "跳转后未能确认绑定状态"}

        # 检查是否需要邮箱+订单号
        order_link_module = data.get("body", {}).get("orderLinkModule", {}).get("d", {})
        single_lookup = order_link_module.get("singleOrderLookup", True)
        
        if not single_lookup and status == 200:
            # 需要邮箱+订单号验证
            print(f"[Link] 需要邮箱+订单号验证，重新提交")
            
            # 更新 stk
            new_stk = data.get("body", {}).get("meta", {}).get("h", {}).get("x-aos-stk", stk)
            
            form_data = (f"orderLinkModule.emailAddress={order_email}"
                        f"&orderLinkModule.orderNumber={order_number}"
                        f"&orderLinkModule.phoneNumber={phone}")
            
            r2 = session.post(linkx_url,
                              data=form_data,
                              headers={**linkx_headers, "x-aos-stk": new_stk},
                              timeout=10)
            print(f"[Link] linkx2 status: {r2.status_code}")
            print(f"[Link] linkx2 response: {r2.text[:1000]}")
            
            try:
                data2 = r2.json()
                redirect2 = data2.get("head", {}).get("data", {}).get("url", "")
                if "detail" in redirect2:
                    elapsed = _time.time() - _start
                    print(f"[Link] ✅ 绑定成功！耗时 {elapsed:.1f}s")
                    return {"success": True, "order_number": order_number}
                return {"success": False, "error": f"绑定失败: {redirect2[:100]}"}
            except Exception as e:
                return {"success": False, "error": f"linkx2 parse: {e}"}

        return {"success": False, "error": "绑定失败，手机号可能不匹配"}
    except Exception as e:
        return {"success": False, "error": "提交手机号失败，请重试"}



# ── 取消订单 ──────────────────────────────────────────────────────
def cancel_order(order_number, order_email, apple_id, apple_password,
                 phone, proxy=None):
    import time as _time
    _start = _time.time()
    phone = re.sub(r'[\s\-\(\)]', '', phone)

    import requests as _std_requests
    session = _std_requests.Session()
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({"User-Agent": UA, "Accept-Language": "zh-CN,zh;q=0.9"})

    try:
        ip = session.get("https://api.ipify.org", timeout=10).text.strip()
        print(f"[Cancel] 代理 IP: {ip}")
    except Exception as e:
        print(f"[Cancel] IP 获取失败: {e}")

    # Step 1: xc → secure_base
    print("[Cancel] Step 1: xc")
    r = session.get(f"https://www.apple.com/xc/us/vieworder/{order_number}/{order_email}",
                    allow_redirects=False, timeout=10)
    location = r.headers.get("location", "")
    print(f"[Cancel] xc → {location[:100]}")

    m = re.match(r'(https://secure[\w]*\.store\.apple\.com)/shop/order/guest/[^/]+/([a-f0-9]+)', location)
    if not m:
        return {"success": False, "error": "订单链接无效或已过期"}
    secure_base = m.group(1)
    token = m.group(2)

    if secure_base == "https://secure.store.apple.com":
        r2 = session.get(location, allow_redirects=False, timeout=10)
        loc2 = r2.headers.get("location", "")
        m2 = re.match(r'(https://secure[\w]+\.store\.apple\.com)', loc2)
        if m2: secure_base = m2.group(1)
    print(f"[Cancel] secure_base: {secure_base}")

    # Step 2: guest → _cs
    print("[Cancel] Step 2: guest")
    r = session.get(f"{secure_base}/shop/order/guest/{order_number}/{token}?e=true", timeout=10)
    cs = _extract_cs(r.text) or _extract_cs(str(r.url))
    if not cs:
        return {"success": False, "error": "无法获取订单会话，请重试"}
    cs_enc = quote(cs, safe='')
    print(f"[Cancel] _cs OK")

    # Step 3: 访问订单详情页，拿 ssi
    print("[Cancel] Step 3: order detail")
    r = session.get(f"{secure_base}/shop/order/detail/10078/{order_number}",
                    allow_redirects=False, timeout=10)
    print(f"[Cancel] detail status: {r.status_code}")

    location3 = r.headers.get("location", "")
    ssi = _extract_ssi(location3)
    if not ssi:
        # 也许直接是 200（已登录），不太可能但处理一下
        return {"success": False, "error": f"no ssi from detail: {location3[:100]}"}

    m3 = re.match(r'(https://secure[\w]+\.store\.apple\.com)', location3)
    if m3: secure_base = m3.group(1)
    print(f"[Cancel] ssi OK")

    # Step 4: GET signIn/orders → 拿 callBackUrl + stk
    print("[Cancel] Step 4: GET signIn/orders")
    r = session.get(f"{secure_base}/shop/signIn/orders?hgl=t&ssi={ssi}", timeout=10)
    print(f"[Cancel] signIn/orders status: {r.status_code}")

    callback_url = None
    stk = None
    init_data = _parse_init_data(r.text)
    if init_data:
        callback_url = (init_data.get("signIn", {})
                        .get("customerLoginIDMS", {})
                        .get("d", {})
                        .get("callbackSignInUrl"))
        stk = init_data.get("meta", {}).get("h", {}).get("x-aos-stk")
    print(f"[Cancel] callbackURL: {callback_url[:60] if callback_url else 'None'}")
    print(f"[Cancel] stk: {stk[:20] if stk else 'None'}")

    # 注入 JS cookie
    try:
        soup = BeautifulSoup(r.text, 'html.parser')
        for script in soup.find_all('script'):
            st = script.get_text()
            if 'document.cookie' in st:
                import re as _re
                clines = _re.findall('document.cookie.+?=.+?["\']([^"\']+)["\']', st)
                for cl in clines:
                    parts = cl.split(';')
                    if parts and '=' in parts[0]:
                        n, v = parts[0].strip().split('=', 1)
                        session.cookies.set(n.strip(), v.strip(), domain='.apple.com')
    except Exception:
        pass

    # Step 5: Shield
    print("[Cancel] Step 5: Shield")
    get_shield_cookies(session, proxy=proxy)

    # Step 6: SRP 登录
    print("[Cancel] Step 6: SRP 登录")
    ctx = srp_login(session, apple_id, apple_password, secure_base)
    if not ctx:
        return {"success": False, "error": "苹果账号登录失败，请检查账号密码"}

    # Step 7: POST callBackUrl
    if not callback_url or not stk:
        return {"success": False, "error": "no callbackUrl or stk"}
    print("[Cancel] Step 7: POST callBackUrl")
    authx_redirect_url = post_authx(session, callback_url, secure_base, stk)
    if not authx_redirect_url:
        return {"success": False, "error": "authX failed"}
    from urllib.parse import unquote
    if "%25" in authx_redirect_url:
        authx_redirect_url = unquote(authx_redirect_url)
    print(f"[Cancel] authX → {authx_redirect_url[:80]}")

    # Step 8: GET order/detail → 拿 cancelItem URL 和 stk
    print("[Cancel] Step 8: GET order/detail")
    detail_url = f"{secure_base}/shop/order/detail/10078/{order_number}"
    r = session.get(detail_url, timeout=10,
                    headers={"sec-fetch-dest": "document",
                             "sec-fetch-mode": "navigate",
                             "sec-fetch-site": "same-origin",
                             "sec-fetch-user": "?1",
                             "upgrade-insecure-requests": "1"})
    print(f"[Cancel] detail status: {r.status_code}")

    init_data = _parse_init_data(r.text)
    if not init_data:
        return {"success": False, "error": "no init_data in detail"}

    stk = init_data.get("meta", {}).get("h", {}).get("x-aos-stk")
    order_items = (init_data.get("orderDetail", {})
                   .get("orderItems", {})
                   .get("c", []))
    print(f"[Cancel] order_items: {order_items}")

    cancel_urls = {}
    for item in order_items:
        item_data = (init_data.get("orderDetail", {})
                     .get("orderItems", {})
                     .get(item, {}))
        cancel_url = (item_data.get("a", {})
                      .get("cancelItem", {})
                      .get("url"))
        if cancel_url:
            cancel_urls[item] = cancel_url
    print(f"[Cancel] cancel_urls: {cancel_urls}")

    if not cancel_urls:
        return {"success": False, "error": "no cancelItem URL，订单可能不支持取消"}

    # Step 9: POST cancelItem → 拿 confirm URL
    all_ok = True
    for item, cancel_url in cancel_urls.items():
        print(f"[Cancel] Step 9: POST cancelItem for {item}")
        r = session.post(cancel_url,
                         data="",
                         headers={"Content-Type": "application/x-www-form-urlencoded",
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
                                  "Referer": detail_url},
                         timeout=10)
        print(f"[Cancel] cancelItem status: {r.status_code}")
        print(f"[Cancel] cancelItem response: {r.text[:300]}")

        try:
            data = r.json()
            # 从 response 拿 confirm URL
            confirm_url = (data.get("body", {})
                           .get("orderDetail", {})
                           .get("orderItems", {})
                           .get(item, {})
                           .get("cancelOverlay", {})
                           .get("a", {})
                           .get("continue", {})
                           .get("url"))
            if not confirm_url:
                print(f"[Cancel] no confirm URL for {item}")
                all_ok = False
                continue

            # Step 10: POST confirm
            print(f"[Cancel] Step 10: POST confirm for {item}")
            r2 = session.post(confirm_url,
                              data="",
                              headers={"Content-Type": "application/x-www-form-urlencoded",
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
                                       "Referer": detail_url},
                              timeout=10)
            print(f"[Cancel] confirm status: {r2.status_code}")
            print(f"[Cancel] confirm response: {r2.text[:200]}")
        except Exception as e:
            print(f"[Cancel] error: {e}")
            all_ok = False

    if all_ok:
        elapsed = _time.time() - _start
        print(f"[Cancel] ✅ 取消成功！耗时 {elapsed:.1f}s")
        return {"success": True, "order_number": order_number}
    return {"success": False, "error": "取消失败"}

def make_proxy(session_id=None):
    if not session_id:
        session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return (f"http://smart-dn74k2mg6pjy_area-US_state-newyork_life-5_session-{session_id}"
            f":xejt59l0aseF8eBz@proxy.smartproxy.net:3120")


if __name__ == "__main__":
    # 测试取消
    result = cancel_order(
        order_number="W1831585427",
        order_email="qibiaowe@gmail.com",
        apple_id="alvesmaria864@yahoo.com",
        apple_password="Yx1992.1992",
        phone="9293105497",
        proxy=make_proxy(),
    )
    print("\n最终结果:", result)