# src/gui/pages/page_broadcast.py
# 广播管理页（页面 2）

import tkinter as tk
from tkinter import ttk, messagebox
import time
import threading

from src.utils.cmd import run_sigle_cmd
from src.gui.hotkey import get_hotkey_label
from src.gui.switch import PersistentSwitch
from src.modules.broadcast_handler import (
    replace_screen_render, restone_screen_render,
    check_replace_screen_render_status,
    force_screenrender_windowed,
    save_now_broadcast_cmd, extract_yc_cmd_from_log,
    handin_save_yc_cmd, generate_remote_cmd_and_save,
    start_log_monitor, stop_log_monitor, is_log_monitor_running,
)
from src.modules.teacher_control import listen_teacher_ip
from src.modules.service_manager import auto_stop_mmpc_if_needed


class PageBroadcast:

    def __init__(self, ui):
        self.ui = ui

    def build(self):
        ui = self.ui
        frame = ttk.Frame(ui.notebook)

        # ---- 上部：控件（可滚动） ----
        _, ctrl_frame = ui.make_scrollable(frame)

        info_frame = ttk.Frame(ctrl_frame)
        info_frame.pack(fill=tk.X, pady=2)
        btn_readme = ttk.Button(info_frame, text="点我查看此页面的使用说明",
                   command=self._show_readme)
        btn_readme.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn_readme, "FUNC_BC_README")

        status_frame = ttk.LabelFrame(ctrl_frame, text="替换状态", padding=5)
        status_frame.pack(fill=tk.X, pady=2)
        ui.replace_status = tk.StringVar(value="未知 (点我更新状态)")
        status_entry = ttk.Entry(status_frame, textvariable=ui.replace_status, state="readonly", justify=tk.CENTER)
        status_entry.pack(fill=tk.X, padx=2, pady=2)
        status_entry.bind("<FocusIn>", self.update_replace_status)
        ui.bind_tooltip(status_entry, "FUNC_BC_REPLACE_STATUS")

        bc_frame = ttk.LabelFrame(ctrl_frame, text="广播操作", padding=5)
        bc_frame.pack(fill=tk.X, pady=2)
        btn1 = ttk.Button(bc_frame, text="替换拦截命令程序", command=self.replace_SCR_loj)
        btn1.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn1, "FUNC_BC_REPLACE_SCR")
        btn2 = ttk.Button(bc_frame, text="运行窗口化广播命令", command=self.run_win_gbcmd_loj)
        btn2.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn2, "FUNC_BC_WIN_BROADCAST")
        fullsc_btn = ttk.Button(bc_frame, text="运行全屏广播命令（长按）")
        fullsc_btn.pack(fill=tk.X, padx=2, pady=2)
        fullsc_btn.bind("<Button-1>", lambda e: self._start_long_press(e, fullsc_btn))
        fullsc_btn.bind("<ButtonRelease-1>", lambda e: self._stop_long_press())
        ui.bind_tooltip(fullsc_btn, "FUNC_BC_FULLSC_BROADCAST")
        btn3 = ttk.Button(bc_frame, text="杀屏幕广播进程", command=ui.direct_kill_screen_render)
        btn3.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn3, "FUNC_BC_KILL_SCR")
        btn4 = ttk.Button(bc_frame, text="恢复原有屏幕广播程序", command=self.restone_SCR_loj)
        btn4.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn4, "FUNC_BC_RESTORE_SCR")

        hk_frame = ttk.LabelFrame(ctrl_frame, text="快捷键", padding=5)
        hk_frame.pack(fill=tk.X, pady=2)
        ui.runwindows_swc = PersistentSwitch(
            hk_frame, config_key="run_window_broadcast_hotkey",
            label=get_hotkey_label("run_window_broadcast") + " 运行窗口屏幕广播",
            verifier=lambda: ui.hotkeyManager.is_registered_by_name("run_window_broadcast", self.run_win_gbcmd_loj),
            on_toggle=lambda _: ui._on_run_window_broadcast_changed(),
        )
        ui.runwindows_swc.pack(fill=tk.X, padx=2, pady=1)
        ui.bind_tooltip(ui.runwindows_swc, "FUNC_HK_WIN_BROADCAST")
        ui.KillSCR_swc = PersistentSwitch(
            hk_frame, config_key="kill_screen_render_hotkey",
            label=get_hotkey_label("kill_screen_render") + " 杀屏幕广播进程",
            verifier=lambda: ui.hotkeyManager.is_registered_by_name("kill_screen_render", ui.direct_kill_screen_render),
            on_toggle=lambda _: ui._on_kill_screen_render_changed(),
        )
        ui.KillSCR_swc.pack(fill=tk.X, padx=2, pady=1)
        ui.bind_tooltip(ui.KillSCR_swc, "FUNC_HK_KILL_SCR")
        ui.RunFullSC_swc = PersistentSwitch(
            hk_frame, config_key="run_fullscreen_broadcast_hotkey",
            label=get_hotkey_label("run_fullscreen_broadcast") + " 运行广播命令",
            verifier=lambda: ui.hotkeyManager.is_registered_by_name("run_fullscreen_broadcast", ui.direct_run_fullscreen_broadcast_cmd),
            on_toggle=lambda _: ui._on_run_fullscreen_broadcast_changed(),
        )
        ui.RunFullSC_swc.pack(fill=tk.X, padx=2, pady=1)
        ui.bind_tooltip(ui.RunFullSC_swc, "FUNC_HK_FULLSC_BROADCAST")
        ui._restore_broadcast_hotkeys()

        # ---- 远程广播命令 ----
        cmd_frame = ttk.LabelFrame(ctrl_frame, text="远程广播命令", padding=5)
        cmd_frame.pack(fill=tk.X, pady=2)
        ttk.Label(cmd_frame, text="教师机IP地址:").pack(anchor=tk.W, padx=2)
        ip_row = ttk.Frame(cmd_frame)
        ip_row.pack(fill=tk.X, padx=2, pady=2)
        ui.teachIp_input = ttk.Entry(ip_row)
        ui.teachIp_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ui.bind_tooltip(ui.teachIp_input, "FUNC_CMD_TEACH_IP")
        self.btn_auto_teacher = ttk.Button(ip_row, text="自动获取教师端IP",
                                           command=self._do_auto_teacher_ip)
        self.btn_auto_teacher.pack(side=tk.LEFT, padx=4)
        ui.bind_tooltip(self.btn_auto_teacher,
                        "监听局域网 7777 教师广播，自动把教师机 IP 填入")
        btn_gen = ttk.Button(cmd_frame, text="由教师机IP生成远程命令",
                   command=lambda: generate_remote_cmd_and_save(ui.teachIp_input.get()))
        btn_gen.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn_gen, "FUNC_CMD_GEN_BY_IP")
        ttk.Label(cmd_frame, text="完整远程广播命令:").pack(anchor=tk.W, padx=2, pady=(5, 0))
        ui.conl_save_ycCmd_input = ttk.Entry(cmd_frame)
        ui.conl_save_ycCmd_input.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(ui.conl_save_ycCmd_input, "FUNC_CMD_REMOTE_CMD")
        btn_auto = ttk.Button(cmd_frame, text="自动替换本地IP并更新命令",
                   command=lambda: handin_save_yc_cmd(ui.conl_save_ycCmd_input.get(), True))
        btn_auto.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn_auto, "FUNC_CMD_AUTO_REPLACE_IP")
        btn_manual = ttk.Button(cmd_frame, text="手动更新完整远程广播命令",
                   command=lambda: handin_save_yc_cmd(ui.conl_save_ycCmd_input.get(), False))
        btn_manual.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn_manual, "FUNC_CMD_MANUAL_SAVE")

        log_frame = ttk.LabelFrame(ctrl_frame, text="日志操作", padding=5)
        log_frame.pack(fill=tk.X, pady=2)
        btn_extract = ttk.Button(log_frame, text="从日志文件获取远程命令",
                   command=lambda: extract_yc_cmd_from_log())
        btn_extract.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn_extract, "FUNC_CMD_EXTRACT_LOG")
        btn_read = ttk.Button(log_frame, text="读取已拦截的广播命令",
                   command=self.dev_read_lj_cmd_loj)
        btn_read.pack(fill=tk.X, padx=2, pady=2)
        ui.bind_tooltip(btn_read, "FUNC_CMD_READ_INTERCEPTED")

        mon_frame = ttk.LabelFrame(ctrl_frame, text="自动监控", padding=5)
        mon_frame.pack(fill=tk.X, pady=2)
        ui.monitor_swc = PersistentSwitch(
            mon_frame, config_key="log_monitor_enabled",
            label="自动监控广播日志 (全屏自动转窗口)",
            live_getter=is_log_monitor_running, verifier=is_log_monitor_running,
            on_toggle=self._on_monitor_toggle,
        )
        ui.monitor_swc.pack(fill=tk.X, padx=2, pady=1)
        ui.bind_tooltip(ui.monitor_swc, "FUNC_CMD_MONITOR")

        # ---- 下部：输出区域（固定底部） ----
        output_frame = ttk.Frame(frame)
        output_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=2)
        self.output_text = ui.make_output_text(output_frame, height=5)

        return frame

    def _do_auto_teacher_ip(self):
        """监听局域网 7777 教师广播，自动把教师机 IP 填入远程广播命令的目标框。"""
        ui = self.ui
        if getattr(self, "_auto_busy", False):
            ui.show_snakemessage("正在监听教师广播，请稍候…")
            return
        self._auto_busy = True
        self.btn_auto_teacher.config(state="disabled", text="监听中…")

        def _run():
            try:
                tip = listen_teacher_ip(timeout=8.0)
            except OSError as exc:
                err = str(exc)
                ui.root.after(0, lambda: self._auto_teacher_done(
                    None, f"无法监听 7777 端口：{err}\n（可能被学生端进程占用，需以管理员或改用 pktmon 确认）"))
                return
            ui.root.after(0, lambda: self._auto_teacher_done(tip))

        ui.clear_text(self.output_text)
        ui.append_text(self.output_text, "[自动获取] 正在监听局域网 7777 教师广播…", ui.root)
        ui._run_in_thread(_run, "自动获取教师端IP")

    def _auto_teacher_done(self, tip, msg=None):
        """主线程回调：把拿到的教师机 IP 填入 teachIp_input 并恢复按钮。"""
        self._auto_busy = False
        self.btn_auto_teacher.config(state="normal", text="自动获取教师端IP")
        if msg:
            self.ui.append_text(self.output_text, msg, self.ui.root)
            self.ui.show_snakemessage("自动获取教师端IP失败")
            return
        if tip:
            self.ui.teachIp_input.delete(0, tk.END)
            self.ui.teachIp_input.insert(0, tip)
            self.ui.append_text(self.output_text,
                                f"[自动获取] 已填入教师机 IP：{tip}", self.ui.root)
            self.ui.show_snakemessage(f"已填入教师机 IP：{tip}")
        else:
            self.ui.append_text(
                self.output_text,
                "[自动获取] 超时未捕获到教师广播（确认教师端在线且在同一网段）",
                self.ui.root,
            )
            self.ui.show_snakemessage("未获取到教师端IP（教师广播不可达）")

    def _show_readme(self):
        messagebox.showinfo(
            "控屏管理页使用说明",
            "在使用前请先使用解锁键盘锁&删除控屏锁定程序功能\n"
            "点击替换拦截程序后再恢复控屏软件\n"
            "等待老师控制屏幕后即完成拦截远程命令\n"
            "完成替换后即可重新删除控屏软件\n"
            "此时当老师处于控制状态时你可以主动运行命令弹出窗口化共享屏幕\n"
            "实现自由的同时不影响听课!!\n"
            "当老师来时你可以使用快捷键启动全屏参数的控制\n"
            "等待老师走后再用快捷键清理进程"
        )

    def _start_long_press(self, event, btn):
        self._long_press_timer = threading.Timer(0.5, self._do_long_press)
        self._long_press_timer.start()

    def _stop_long_press(self):
        if hasattr(self, '_long_press_timer') and self._long_press_timer:
            self._long_press_timer.cancel()

    def _do_long_press(self):
        self.ui.direct_run_fullscreen_broadcast_cmd()

    def run_win_gbcmd_loj(self, *e):
        ui = self.ui
        if force_screenrender_windowed():
            ui.show_snakemessage("已切换为窗口模式")
        else:
            ui.show_snakemessage("未找到广播窗口，可能尚未开始广播")

    def replace_SCR_loj(self, *e):
        ui = self.ui
        auto_stop_mmpc_if_needed()
        time.sleep(1)
        ui.show_snakemessage("开始替换程序 请稍等...\n这大约需要6秒左右")
        status = replace_screen_render()
        if not status:
            ui.show_snakemessage("替换拦截程序失败 未检测到可替换程序\n请确保ScreenRender_Helper.exe\n与工具箱处在同一目录")
        else:
            ui.show_snakemessage("理论上已经成功替换拦截程序\n可自行检查替换结果")

    def restone_SCR_loj(self, *e):
        ui = self.ui
        auto_stop_mmpc_if_needed()
        time.sleep(1)
        ui.show_snakemessage("开始还原替换程序 请稍等...")
        status = restone_screen_render()
        if not status:
            ui.show_snakemessage("尝试恢复拦截程序时失败\n未检测到被重命名的ScreenRender.exe")
        else:
            ui.show_snakemessage("理论上已经成功恢复原有程序")

    def update_replace_status(self, *e):
        ui = self.ui
        if check_replace_screen_render_status():
            ui.show_snakemessage("检测到目录下已有ScreenRender_Y.exe")
            ui.replace_status.set("已替换")
        else:
            ui.show_snakemessage("未检测到ScreenRender_Y.exe\n也许未执行替换或替换过程被打断")
            ui.replace_status.set("未替换")

    # ---- 以下为原广播命令页 (PageCommands) 方法 ----

    def _on_monitor_toggle(self, e=None):
        ui = self.ui
        if e.value:
            start_log_monitor(auto_windowed=True)
            ui.show_snakemessage("广播日志监控已启动")
        else:
            stop_log_monitor()
            ui.show_snakemessage("广播日志监控已停止")

    def dev_read_lj_cmd_loj(self, *e):
        ui = self.ui
        status = save_now_broadcast_cmd()
        if not status:
            ui.show_snakemessage("未拦截到控制命令参数")
        else:
            ui.show_snakemessage("保存拦截命令成功")