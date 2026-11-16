"""IP 검사 필터 — 외부 의존성(netaddr) 없이 파이썬 ipaddress 만 쓴다.

  "203.0.113.5" | is_ipv4                      → True
  "192.168.1.9" | ip_in_any(['192.168.0.0/16']) → True
"""
import ipaddress


def is_ipv4(value):
    try:
        return isinstance(ipaddress.ip_address(str(value).strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def ip_in_any(value, cidrs):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            if ip in ipaddress.ip_network(str(c).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


class FilterModule:
    def filters(self):
        return {"is_ipv4": is_ipv4, "ip_in_any": ip_in_any}
