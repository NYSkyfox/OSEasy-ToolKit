# config.py
# 工具箱静态配置信息

# 基础信息
APP_NAME = "OsEasy-ToolKit"
APP_VERSION = "1.9.0"
RELEASE_NAME = f"{APP_NAME} v{APP_VERSION}"
SOURCE_NAME = "ToolKit"
AUTHOR = "NyxFox"
GITHUB_URL = "https://github.com/NYSkyfox/OsEasy-ToolKit"

# 构建日期（打包时由 build.py 写入）
BUILD_DATE = "2026-08-10 16:45:13"

# 默认字体（回退值，实际会按优先级探测可用字体）
DEFAULT_FONT_PATH = "C:\\Windows\\Fonts\\msyh.ttc"

# 工具箱数据根目录（用户文件夹下）
DATA_ROOT_TEMPLATE = "C:\\Users\\{username}\\OsEasy-ToolKit"

# 配置文件路径
CONFIG_FILE_PATH_TEMPLATE = DATA_ROOT_TEMPLATE + "\\config.json"

# 备份文件路径
BACKUP_PATH_TEMPLATE = DATA_ROOT_TEMPLATE + "\\backups"

# 生成的脚本文件夹路径
CMD_FILE_PATH_TEMPLATE = DATA_ROOT_TEMPLATE + "\\scripts"

# 日志文件夹路径
LOG_DIR_TEMPLATE = DATA_ROOT_TEMPLATE + "\\log"

# 截图保存路径
SCREENSHOT_PATH_TEMPLATE = DATA_ROOT_TEMPLATE + "\\screenshots"

# 默认学生端路径
DEFAULT_OSEASY_PATH = "C:\\Program Files (x86)\\Os-Easy\\os-easy multicast teaching system\\"

# 默认学生端进程名
DEFAULT_STUDENT_EXE_NAME = "Student.exe"

# 默认一言列表
DEFAULT_YIYAN_LIST = [
    "人生苦短,我用Python",
    "亻尔 女子",
    "《机房课时间管理》",
    "就让你看看...这葫芦里卖的什么药！",
    "让我来摸个鱼吧~",
    "代码没写完,Bug先写好了",
    "科技改变课堂"
]

# 默认显示的一言
DEFAULT_SHOW_YIYAN = "希君生羽翼，一化北溟鱼"

# ---- UI 主题色 ----
# 默认主题色（墨绿色），会在启动时尝试读取 Windows 系统主题色覆盖
DEFAULT_ACCENT_COLOR = "#3B8a67"

# ---- 脚本文件名 ----
KILLER_BAT = "Process-Killer_Student.bat"
KILLER_ALL_BAT = "Process-Killer_All.bat"
FILE_DEL_BAT = "Files-Delete.bat"
INSTALL_STUDENT_TEST_BAT = "Install_Student_test.bat"
UNINSTALL_STUDENT_TEST_BAT = "Uninstall_Student_test.bat"
UNLOCK_NET_BAT = "Unlock-Network.bat"
UNLOCK_USB_BAT = "Unlock-USB.bat"
UNLOCK_USB_PS1 = "Unlock-USB.ps1"
UNLOCK_KB_BAT = "Unlock-Keyboard.bat"
UNLOCK_ALL_BAT = "Unlock-All.bat"

# ---- 备份文件清单（相对于 OE 安装目录） ----
BACKUP_FILES = [
    # 锁定相关
    "LockKeyboard.dll",
    "LoadDriver.exe",
    "KbDriver.exe",
    # 黑屏/控屏
    "BlackSlient.exe",
    "MultiClient.exe",
    # 网络/USB
    "OeNetLimit.sys",
    "OeNetLimitSetup.exe",
    "oenetlimitx64.cat",
    "easyusbflt.sys",
    "ProcFireWall.sys",
    # 文件系统过滤（目录保护）
    "FbdATS.sys",
    # 嗅探
    "x86\\LISSNetInfoSniffer.exe",
]

# ──────────────────────────────────────────────
#  功能悬停提示（tooltip）
#  统一管理所有控件的状态栏说明文字
#  格式: "FUNC_XXXXXX" = "说明文字"
#  用法: ui.bind_tooltip(widget, "FUNC_XXXXXX")
#        ui.bind_tooltip(widget, "FUNC_BAK_RESTORE_ONE", filename="xxx.dll")
# ──────────────────────────────────────────────
TOOLTIPS = {
    # ── 概览页 ──
    "FUNC_OVERVIEW_REFRESH": "重新检测学生端服务、进程运行状态及功能劫持状态",

    # ── 服务管理页 ──
    "FUNC_SVC_REFRESH": "重新检测学生端相关服务（MMPC/网络/USB/键盘/防火墙）的运行状态",
    # ── 进程管理页 ──
    "FUNC_MMPC_STATUS":          "查看噢易多媒体根服务(MMPC)的运行状态，点击可刷新",
    "FUNC_MMPC_TOGGLE":          "启动或停止噢易多媒体根服务 MMPC",
    "FUNC_RESTART_STUDENT":      "结束当前学生端进程并重新启动",
    "FUNC_REFRESH_STUDENT_PATH": "自动检测学生端安装路径和运行版本",
    "FUNC_HIJACK_SETHC":         "用 cmd.exe 替换 sethc.exe，按5次Shift打开命令行（提权后门）",
    "FUNC_PROTECT_KILLER":       "启动守护进程保护杀手脚本，防止被教师端终止",
    "FUNC_SUSPEND_STUDENT":      "挂起学生端进程使其暂停运行，避免被教师端监控",
    "FUNC_LAUNCH_OE_TOOLKIT":    "启动噢易自带的管理工具 AssistHelper.exe",
    "FUNC_OPEN_OE_DIR":          "在资源管理器中打开噢易学生端的安装目录",
    "FUNC_OPEN_DATA_DIR":        "打开工具箱的数据目录 {data_dir}，查看备份、日志和配置文件",

    # ── 其他管理页 ──
    "FUNC_DEL_SCRIPTS":       "删除工具箱生成的临时脚本文件（cmd/bat等）",
    "FUNC_FAST_SCREENSHOT":   "使用快捷键快速截取屏幕并保存到 {data_dir}",
    "FUNC_HIJACK_SHUTDOWN":   "通过 IFEO 劫持 shutdown.exe，阻止教师端远程关机指令",
    "FUNC_HIJACK_RESTART":    "移除学生端进程的关机权限，阻止教师端远程重启",

    # ── 解锁管理页 ──
    "FUNC_UNLOCK_ALL":         "依次解锁网络、USB、键盘鼠标管控和屏幕广播/黑屏肃静",
    "FUNC_UNLOCK_KB":          "停止键盘过滤驱动并清理注册表，解除键盘鼠标锁定",
    "FUNC_UNLOCK_NET":         "停止 OeNetLimit 和 ProcFireWall 网络管控服务",
    "FUNC_UNLOCK_USB":         "关闭 easyusbflt USB 过滤驱动，解除USB设备管控",
    "FUNC_UNLOCK_BLACKSCREEN": "结束 BlackSlient 进程，解除教师端黑屏肃静控制",
    "FUNC_UNLOCK_SCREENCAST":  "结束 MultiClient 屏幕广播进程，解除教师端屏幕控制",

    # ── 广播管理页 ──
    "FUNC_BC_README":           "点击查看控屏管理功能的详细使用说明",
    "FUNC_BC_REPLACE_STATUS":   "查看 ScreenRender 程序是否已被替换为自定义程序，点击可刷新",
    "FUNC_BC_REPLACE_SCR":      "用自定义程序替换 ScreenRender，拦截教师端广播命令",
    "FUNC_BC_WIN_BROADCAST":    "以窗口模式运行拦截到的广播命令，自由切换窗口",
    "FUNC_BC_FULLSC_BROADCAST": "长按以全屏模式运行广播命令，松开即恢复窗口模式",
    "FUNC_BC_KILL_SCR":         "强制终止 ScreenRender 屏幕广播进程",
    "FUNC_BC_RESTORE_SCR":      "将 ScreenRender 恢复为原始程序，取消拦截",
    "FUNC_HK_WIN_BROADCAST":    "使用快捷键以窗口模式运行广播命令",
    "FUNC_HK_KILL_SCR":         "使用快捷键强制终止屏幕广播进程",
    "FUNC_HK_FULLSC_BROADCAST": "使用快捷键以全屏模式运行广播命令",

    # ── 广播命令页 ──
    "FUNC_CMD_TEACH_IP":       "输入教师机的 IP 地址，用于生成远程广播命令",
    "FUNC_CMD_GEN_BY_IP":      "根据教师机 IP 自动生成远程命令并保存到配置",
    "FUNC_CMD_REMOTE_CMD":     "输入完整的远程广播命令行参数",
    "FUNC_CMD_AUTO_REPLACE_IP": "自动替换命令中的 IP 为本机 IP 并保存",
    "FUNC_CMD_MANUAL_SAVE":    "直接保存手动编辑的远程广播命令，不自动替换 IP",
    "FUNC_CMD_EXTRACT_LOG":    "从 OsEasy 日志文件中提取教师端发送的远程命令",
    "FUNC_CMD_READ_INTERCEPTED": "读取并显示已被拦截保存的广播命令参数",
    "FUNC_CMD_MONITOR":        "持续监控广播日志，当检测到全屏广播时自动切换为窗口模式",

    # ── DLL 工具页 ──
    "FUNC_DLL_USB_STOP":   "调用 easyusbctrl.dll 停止 USB 管控，允许使用 USB 设备",
    "FUNC_DLL_USB_START":  "调用 easyusbctrl.dll 启动 USB 管控，限制 USB 设备使用",
    "FUNC_DLL_NET_ENABLE": "调用 OeNetlimit.dll 开启网络管控，限制网络访问",
    "FUNC_DLL_NET_DISABLE":"调用 OeNetlimit.dll 关闭网络管控，恢复网络访问",
    "FUNC_DLL_QUERY":      "查询当前 USB 和网络管控的运行状态",

    # ── 备份恢复页 ──
    "FUNC_BAK_ALL":        "备份噢易学生端所有关键 DLL 和驱动文件到 {backup_dir}",
    "FUNC_BAK_BACKUP_ONE": "备份 {filename} 到 {backup_dir}",
    "FUNC_BAK_RESTORE_ALL": "从备份目录恢复所有关键文件到 {student_dir}",
    "FUNC_BAK_RESTORE_ONE": "从备份中恢复 {filename} 到 {student_dir}",

    # ── 设置页 ──
    "FUNC_SET_BG":           "选择一张图片作为工具箱窗口背景",
    "FUNC_SET_FONT":         "选择自定义字体文件（需重启生效）",
    "FUNC_SET_YIYAN":        "从外部文本文件加载自定义一言列表",
    "FUNC_SET_RANDOM_YIYAN": "在标签页顶部随机显示一言，每次切换页面时刷新",
    "FUNC_SET_OPACITY":      "调整工具箱窗口背景图片的不透明度 (0=透明 ~ 1=不透明)",
    "FUNC_HK_HIDE_TOOLKIT":  "使用快捷键快速隐藏或显示工具箱窗口",
    "FUNC_SET_TOPMOST":      "让工具箱窗口始终显示在其他窗口之上",
    "FUNC_SET_TOAST":       "启用后，部分操作完成时会通过 Windows 桌面通知提醒",
    "FUNC_SET_RESET":        "清除工具箱所设置并恢复默认配置",

    # ── 远程崩溃页 ──
    "FUNC_CRASH_IP":      "输入目标 IP 地址或 CIDR 网段（如 192.168.1.0/24）",
    "FUNC_CRASH_PORT":    "目标端口号，默认为噢易 ConnectPort(9003)，教师端混合 TCP 服务",
    "FUNC_CRASH_PAYLOAD": "发送的崩溃载荷内容，默认为 oshack",
    "FUNC_CRASH_SEND":    "向目标 IP 发送崩溃载荷。逆向确认：9003 未监听(10061)自动重试；接收方强制关闭连接(10054)=解析线程崩溃，已触发",

    # ── 学生端安装测试 ──
    "FUNC_INSTALL_STUDENT_TEST": "在指定目录生成并运行学生端轻量安装脚本（注册 MMPC/装驱动/防火墙）",
    "FUNC_UNINSTALL_STUDENT_TEST": "在指定目录生成并运行学生端卸载脚本（停止/删除 MMPC 与管控驱动/删防火墙）",

    # ── 教师端管控指令模拟 ──
    "FUNC_TEACHER_CONTROL_SEND": "模拟教师端向学生端单播发送管控指令（UDP，UdpMessageControllerPort 默认 8040）",
}