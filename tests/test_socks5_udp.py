#!/usr/bin/env python3
"""端到端测试：通过 SOCKS5 UDP ASSOCIATE 向 1.1.1.1:53 查询 example.com 的 A 记录。

链路全通时返回的应当是 example.com 对应的 Cloudflare 反向代理 IP
（如 104.20.x.x / 172.66.x.x 等）。"""
import socket
import struct
import sys

PROXY = ("127.0.0.1", 1080)
DNS_SERVER = ("1.1.1.1", 53)

def build_dns_query(name="example.com"):
    """构造一个标准的 DNS A 记录查询报文"""
    tid = 0x1234
    flags = 0x0100  # 标准查询，递归
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    qtype_class = struct.pack("!HH", 1, 1)  # 类型=A，类别=IN
    return header + qname + qtype_class

def parse_dns_a_record(reply):
    """从 DNS 响应里抽出所有 A 记录"""
    if len(reply) < 12:
        return []
    qd_count = struct.unpack("!H", reply[4:6])[0]
    an_count = struct.unpack("!H", reply[6:8])[0]
    # 跳过报头
    offset = 12
    # 跳过 question section
    for _ in range(qd_count):
        while reply[offset] != 0:
            if reply[offset] & 0xc0 == 0xc0:
                offset += 1
                break
            offset += reply[offset] + 1
        offset += 1
        offset += 4
    # 遍历 answer section
    ips = []
    for _ in range(an_count):
        if reply[offset] & 0xc0 == 0xc0:
            offset += 2
        else:
            while reply[offset] != 0:
                offset += reply[offset] + 1
            offset += 1
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", reply[offset:offset+10])
        offset += 10
        rdata = reply[offset:offset+rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
    return ips

def main():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(10)
    tcp.connect(PROXY)

    # SOCKS5 握手 — 无鉴权
    tcp.send(b"\x05\x01\x00")
    if tcp.recv(2) != b"\x05\x00":
        print("handshake failed", file=sys.stderr)
        sys.exit(2)

    # UDP ASSOCIATE 请求 — 客户端尚不知道自身 UDP 端口，传 0.0.0.0:0
    tcp.send(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = tcp.recv(10)
    if len(resp) < 10 or resp[0] != 0x05 or resp[1] != 0x00:
        print("UDP ASSOCIATE failed:", resp.hex(), file=sys.stderr)
        sys.exit(3)
    bnd_port = struct.unpack("!H", resp[8:10])[0]
    bnd_ip = ".".join(str(b) for b in resp[4:8])
    print(f"[ok] relay bound at {bnd_ip}:{bnd_port}")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(15)

    # 组装 SOCKS5 UDP 头 + DNS 查询：目标 1.1.1.1:53
    dst_ip = bytes(int(x) for x in DNS_SERVER[0].split("."))
    socks_hdr = b"\x00\x00\x00\x01" + dst_ip + struct.pack("!H", DNS_SERVER[1])
    udp.sendto(socks_hdr + build_dns_query("example.com"), (bnd_ip, bnd_port))
    print("[..] sent DNS query for example.com to 1.1.1.1:53 via SOCKS5 UDP")

    reply, _src = udp.recvfrom(4096)
    print(f"[ok] got {len(reply)} bytes back")

    # 剥掉 SOCKS5 UDP 头：RSV RSV FRAG ATYP=0x01 4 字节 IP + 2 字节端口
    if len(reply) < 10 or reply[3] != 0x01:
        print("unexpected reply framing:", reply[:20].hex(), file=sys.stderr)
        sys.exit(4)
    src_ip = ".".join(str(b) for b in reply[4:8])
    src_port = struct.unpack("!H", reply[8:10])[0]
    dns_payload = reply[10:]
    print(f"[ok] payload {len(dns_payload)} bytes from {src_ip}:{src_port}")

    ips = parse_dns_a_record(dns_payload)
    print("[result] example.com →", ips)
    tcp.close()
    udp.close()
    sys.exit(0 if ips else 5)

if __name__ == "__main__":
    main()
