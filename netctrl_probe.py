#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netctrl_probe.py —— 网络管控(cmdType=500)纯发包/收包测试工具
=============================================================
用途：机房里确定“教师端管控载荷是否到达学生机 / 载荷格式差异”，
      帮你判断“网络管控没生效”到底卡在 网络层 还是 载荷/身份层。
仅做【发包 + 收包观测】，不真正断言学生端是否会执行“限制/解除”。

⚠️ 重要声明（读我一遍）：
  本文件里的“启用管控 / 关闭管控 / 完整格式 / apps 等字段”仅作为
  【打包测试的用例载荷】，绝不代表“这样做学生端就真会限制/解除”。
  协议的真义需结合你的逆向文档，并以机房实测为准。

运行：
  python netctrl_probe.py
  按数字选模式：
     1 = 发包测试    (向目标 IP:8040 发送特定载荷)
     2 = 收包测试    (在 0.0.0.0:8040 监听收到的 UDP 包)

所有 CLI 输出会同时写入日志文件 netctrl_probe.log，便于复盘。
"""

import socket
import struct
import json
import time
import sys
import os

# ───────────────────────── 可改常量 ─────────────────────────
DEFAULT_PORT = 8040          # 学生端管控 UDP 端口(UdpMessageControllerPort)
LISTEN_IP   = "0.0.0.0"      # 收包监听的绑定地址
LOG_FILE    = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "netctrl_probe.log")

# CtrlCode 位标志 (来自你的逆向: Teacher.exe FUN_005648c0 确认)
CTRL_NET       = 0x01   # 禁用网络
CTRL_KEYFILTER = 0x02   # 网络过滤
CTRL_APP       = 0x10   # 禁用程序
CTRL_USB       = 0x100 + 0x1000 + 0x10000   # USB 限制三档

# 测试用的两个“开关档”的 CtrlCode 组合（仅测试载荷，非协议结论）
#   若你要加“网络过滤(0x02)”或调值，改下面的表达式即可。
ENABLE_CTRL = CTRL_NET | CTRL_APP          # = 0x11 (网络+程序)
CLOSE_CTRL  = 0x00                         # = 0x00 (测试“关闭/清空”用)

# ───────────────────────── 报文构造 ─────────────────────────

def build_header(cmd_type, payload_len, flag1=0, flag2=0):
    """16 字节命令头, 小端: [cmdType][flag1][flag2][payloadLen]"""
    return struct.pack("<IIII", int(cmd_type) & 0xFFFFFFFF,
                       int(flag1) & 0xFFFFFFFF,
                       int(flag2) & 0xFFFFFFFF,
                       int(payload_len) & 0xFFFFFFFF)


# 当前精简格式:  /*//{"CtrlCode":XX,"sendState":1}
def payload_short(ctrl_code):
    body = json.dumps({"CtrlCode": int(ctrl_code),
                       "sendState": 1}, separators=(",", ":"))
    return b"/*//" + body.encode("utf-8")


# 完整格式(尽量贴逆向文档): /*//{"CtrlCode":XX,"apps":[],"cites":[],"keys":[],
#                                  "sendState":1,"tipInfo":"","serverIp":""}
def payload_full(ctrl_code, server_ip=""):
    obj = {
        "CtrlCode": int(ctrl_code),
        "apps":   [],          # 未填具体程序 -> 空数组(见文件头声明)
        "cites":  [],
        "keys":   [],
        "sendState": 1,
        "tipInfo": "",
        "serverIp": server_ip,  # 默认空串; 需要可传真实教师机IP验证
    }
    body = json.dumps(obj, separators=(",", ":"))
    return b"/*//" + body.encode("utf-8")


def make_packet(fmt, ctrl_code, server_ip="", cmd_type=500):
    """封装成完整报文 = 16B头 + 载荷"""
    if fmt == "short":
        pay = payload_short(ctrl_code)
    else:  # full
        pay = payload_full(ctrl_code, server_ip)
    header = build_header(cmd_type, len(pay))
    return header + pay, pay, len(header) + len(pay)


# ───────────────────────── 日志/输出 ─────────────────────────

_logfh = None


def _ensure_log():
    global _logfh
    if _logfh is None:
        try:
            _logfh = open(LOG_FILE, "a", encoding="utf-8")
        except Exception:
            _logfh = None
    return _logfh


def log(msg="", also_console=True):
    """输出到控制台 + 实时追加写入日志文件。"""
    if also_console:
        try:
            print(msg)
            sys.stdout.flush()
        except Exception:
            pass
    fh = _ensure_log()
    if fh:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            fh.write(f"[{ts}] {msg}\n")
            fh.flush()
        except Exception:
            pass


def close_log():
    global _logfh
    if _logfh:
        try:
            _logfh.close()
        except Exception:
            pass
        _logfh = None


# ───────────────────────── 收包测试 (模式2) ─────────────────────────

def mode_receive():
    log("")
    log("===== [模式2] 收包测试 =====")
    try:
        port = int(input("要监听的端口 [默认 %d]: " % DEFAULT_PORT).strip() or DEFAULT_PORT)
    except (ValueError, EOFError):
        port = DEFAULT_PORT

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_IP, port))
    except OSError as e:
        # 若端口被学生端进程占用, 提示(本身也是有效信息)
        log(f"[错误] 无法监听 {LISTEN_IP}:{port} -> {e}")
        log("      (若提示 10048/地址被占用, 说明该端口已被某进程占用,")
        log("       这本身提示: 8040 确实有进程在收; 可用 netstat -ano | findstr :%d 查看)" % port)
        return

    log(f"[监听中] {LISTEN_IP}:{port}  将持续 {60} 秒, 等待 UDP 包...")
    log("→ 现在去另一台机器/另一个终端, 用模式1(发包)向本机此IP:端口发一条, 然后回来看这里。")
    s.settimeout(60)
    count = 0
    t_end = time.time() + 60
    try:
        while time.time() < t_end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                log("(60 秒到, 没有再收到新包)")
                break
            count += 1
            log("-" * 64)
            log(f"[第 {count} 个包] 来自: {addr[0]}:{addr[1]}")
            log(f"包总长: {len(data)} 字节")
            log(f"HEX   : {data.hex()}")
            # 尝试解析 16B 头
            if len(data) >= 16:
                cmd_type, f1, f2, plen = struct.unpack_from("<IIII", data, 0)
                log(f"头解析: cmdType={cmd_type} flag1={f1} flag2={f2} payloadLen={plen}")
                payload = data[16:16 + plen]
                log(f"载荷({len(payload)}B): {payload.decode('utf-8', errors='replace')!r}")
    except KeyboardInterrupt:
        log("[已手动停止收包]")
    finally:
        s.close()
    log(f"[收包结束] 共收到 {count} 个 UDP 包")


# ───────────────────────── 发包测试 (模式1) ─────────────────────────

def ask_mode(text):
    while True:
        try:
            v = input(text).strip()
            if v == "":
                return None
            return int(v)
        except ValueError:
            log("输入无效, 请重新输入数字。")


def mode_send():
    log("")
    log("===== [模式1] 发包测试 =====")

    target = input("目标IP(学生机): ").strip()
    while not target:
        log("目标IP不能为空, 请重新输入。")
        target = input("目标IP(学生机): ").strip()
    try:
        port = int(input("目标端口 [默认 %d]: " % DEFAULT_PORT).strip() or DEFAULT_PORT)
    except ValueError:
        port = DEFAULT_PORT
    server_ip = input("完整格式的 serverIp(留空则不填; 想验证身份可用指向教师机的IP): ").strip()

    log("")
    log("选择载荷格式:")
    log("  1 = 精简格式  /*//{\"CtrlCode\":X,\"sendState\":1}")
    log("  2 = 完整格式  /*//{\"CtrlCode\":X,\"apps\":[],\"cites\":[],\"keys\":[],\"sendState\":1,\"tipInfo\":\"\",\"serverIp\":...}")
    fmt_key = ask_mode("请选择 [1/2]: ")
    fmt = "short" if fmt_key == 1 else "full"

    log("")
    log("选择开关档(CtrlCode):")
    log(f"  1 = 启用档  CtrlCode=0x{ENABLE_CTRL:X}({ENABLE_CTRL})  (测试: 网络+程序)")
    log(f"  2 = 关闭档  CtrlCode=0x{CLOSE_CTRL:X}({CLOSE_CTRL})  (测试: 清零)")
    sw = ask_mode("请选择 [1/2]: ")
    ctrl = ENABLE_CTRL if sw == 1 else CLOSE_CTRL
    sw_name = "启用档" if sw == 1 else "关闭档"

    # 组装并发送
    pkt, pay, totalsz = make_packet(fmt, ctrl, server_ip=server_ip)

    log("")
    log("-" * 64)
    log(f"[准备发送] -> {target}:{port}")
    log(f"  格式: {fmt}  |  档位: {sw_name}  |  CtrlCode=0x{ctrl:X}({ctrl})")
    log(f"  完整报文 hex({totalsz}B): {pkt.hex()}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.sendto(pkt, (target, port))
        log(f"[已发送] 到 {target}:{port} , {totalsz} 字节 (sendto 成功 = 已交给系统发出)")
        log("  ⚠️ 注意: sendto 成功只代表本机网卡发出, 不代表学生端一定收到。")
        log("  请到对端用 [模式2 收包] (同网段、同端口) 确认是否真正到达。")
    except OSError as e:
        log(f"[发送失败] {e}")
    finally:
        sock.close()


# ───────────────────────── 获取本机IP ─────────────────────────

def get_local_ips():
    """返回本机所有 IPv4 地址列表(保守可行时只列非回环的)。"""
    ips = []
    # 方式1: UDP connect 到公网可达的占位地址(不真正发包), 取发包网卡的源IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    # 方式2: 枚举所有网卡地址(补齐多网卡/离线时的信息)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    if not ips:
        ips = ["127.0.0.1"]
    return ips


# ───────────────────────── 主入口 ─────────────────────────

def main():
    _ensure_log()
    log("=" * 64)
    log("netctrl_probe —— 网络管控(cmdType=500) 发包/收包测试工具")
    log("（纯测试工具, 载荷不构成业务结论; log 实时写入 netctrl_probe.log）")
    # 启动时打印当前设备IP(多网卡会全部列出, 方便你在机房里挑对网段那张)
    local_ips = get_local_ips()
    log("本机当前 IP: %s" % (" / ".join(local_ips)))
    log("=" * 64)
    while True:
        log("")
        log("请选择模式:")
        log("  1 = 发包测试     (向目标IP发一条管控载荷)")
        log("  2 = 收包测试     (监听本机端口, 看别人发来的包)")
        log("  0 / q = 退出")
        m = ask_mode("输入数字: ")
        if m in (0, None):
            break
        if m == 1:
            mode_send()
        elif m == 2:
            mode_receive()
        else:
            log("未知选项, 请重新输入。")
    close_log()
    log("已退出。日志已保存: %s" % LOG_FILE)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("用户中断。")
        close_log()