"""
最简单的代理测试 - 看 Smart Proxy 能不能用,出口 IP 是不是 New York
"""
import requests
import warnings
warnings.filterwarnings('ignore')

SMART_PROXY = "http://smart-dn74k2mg6pjy_area-US_state-newyork_life-5_session-dKvZ6SUA:xejt59l0aseF8eBz@proxy.smartproxy.net:3120"

print("Test 1: 不走代理,看你本机 IP")
try:
    r = requests.get("https://api.ipify.org?format=json", timeout=10)
    print(f"  本机 IP: {r.json()}")
except Exception as e:
    print(f"  失败: {e}")

print("\nTest 2: 走代理,看代理出口 IP")
try:
    r = requests.get(
        "https://api.ipify.org?format=json",
        proxies={"http": SMART_PROXY, "https": SMART_PROXY},
        timeout=15,
        verify=False,
    )
    print(f"  代理 IP: {r.json()}")
except Exception as e:
    print(f"  失败: {e}")

print("\nTest 3: 走代理访问苹果")
try:
    r = requests.get(
        "https://www.apple.com",
        proxies={"http": SMART_PROXY, "https": SMART_PROXY},
        timeout=15,
        verify=False,
    )
    print(f"  apple.com status: {r.status_code}")
except Exception as e:
    print(f"  失败: {e}")
