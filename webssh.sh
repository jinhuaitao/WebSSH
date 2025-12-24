#!/bin/bash

# =========================================================
#  WebSSH Manager - One-Click Installer
#  System: Debian/Ubuntu (Systemd) & Alpine (OpenRC)
# =========================================================

# --- 基础配置 ---
# 已更新为你提供的真实下载地址
DOWNLOAD_URL="https://jht126.eu.org/https://github.com/jinhuaitao/WebSSH/releases/latest/download/webssh"
BIN_PATH="/usr/local/bin/webssh"
SERVICE_NAME="webssh"
# 数据持久化目录
DATA_DIR="/etc/webssh"
DATA_FILE="$DATA_DIR/data.json"

# --- 颜色与样式配置 ---
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
BOLD='\033[1m'
PLAIN='\033[0m'

# 图标定义
ICON_SUCCESS="✅"
ICON_FAIL="❌"
ICON_WARN="⚠️"
ICON_INFO="ℹ️"
ICON_ROCKET="🚀"
ICON_TRASH="🗑️"
ICON_GLOBE="🌍"

# --- UI 辅助函数 ---

clear_screen() {
    clear
}

print_line() {
    echo -e "${BLUE}————————————————————————————————————————————————————${PLAIN}"
}

print_logo() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo " _       __     __   _____ _____ __  __"
    echo "| |     / /__  / /_ / ___// ___// / / /"
    echo "| | /| / / _ \/ __ \\__ \ \__ \/ /_/ / "
    echo "| |/ |/ /  __/ /_/ /__/ /__/ / __  /  "
    echo "|__/|__/\___/_.___/____/____/_/ /_/   "
    echo -e "${PLAIN}"
    echo -e "   ${YELLOW}WebSSH 终端管理脚本${PLAIN}"
    print_line
}

log_info() {
    echo -e "${BLUE}[${ICON_INFO}] ${PLAIN} $1"
}

log_success() {
    echo -e "${GREEN}[${ICON_SUCCESS}] ${PLAIN} $1"
}

log_error() {
    echo -e "${RED}[${ICON_FAIL}] ${PLAIN} $1"
}

log_warn() {
    echo -e "${YELLOW}[${ICON_WARN}] ${PLAIN} $1"
}

# --- 系统检查 ---

check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "请使用 root 用户运行此脚本！"
        exit 1
    fi
}

check_dependencies() {
    local missing_deps=0
    if ! command -v wget >/dev/null; then missing_deps=1; fi
    # 如果是 Alpine，可能还需要 curl 或其他工具，这里主要检查 wget
    
    if [ $missing_deps -eq 1 ]; then
        log_info "正在安装必要组件 (wget)..."
        if [ -f /etc/alpine-release ]; then
            apk add --no-cache wget ca-certificates >/dev/null 2>&1
        elif [ -f /etc/debian_version ]; then
            apt-get update >/dev/null 2>&1 && apt-get install -y wget ca-certificates >/dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum install -y wget ca-certificates >/dev/null 2>&1
        fi
        log_success "组件安装完成"
    fi
}

# --- 核心功能 ---

install_webssh() {
    print_logo
    echo -e "${BOLD}正在开始安装 WebSSH...${PLAIN}\n"
    
    check_dependencies

    # 1. 准备目录和数据文件
    log_info "正在准备运行环境..."
    if [ ! -d "$DATA_DIR" ]; then
        mkdir -p "$DATA_DIR"
    fi
    
    # 关键步骤：确保 data.json 是文件而不是文件夹，且有权限
    if [ ! -f "$DATA_FILE" ]; then
        if [ -d "$DATA_FILE" ]; then
            rm -rf "$DATA_FILE"
        fi
        touch "$DATA_FILE"
        chmod 666 "$DATA_FILE"
        log_success "配置文件初始化成功"
    else
        log_info "检测到已有配置文件，保留现有配置"
        chmod 666 "$DATA_FILE" # 确保权限正确
    fi

    # 2. 下载二进制文件
    log_info "正在下载最新版本..."
    # 无论是否存在旧文件，都强制覆盖下载，实现“更新”功能
    wget -q --show-progress -O "$BIN_PATH" "$DOWNLOAD_URL"
    
    if [ $? -ne 0 ]; then
        echo ""
        log_error "下载失败！请检查服务器网络或下载链接有效性。"
        rm -f "$BIN_PATH"
        read -p "按回车键返回..."
        return
    fi
    
    chmod +x "$BIN_PATH"
    echo ""
    log_success "下载成功，安装路径: ${CYAN}$BIN_PATH${PLAIN}"

    # 3. 配置服务
    log_info "正在配置系统服务..."
    
    if [ -f /etc/alpine-release ]; then
        # --- Alpine OpenRC 配置 ---
        cat > /etc/init.d/$SERVICE_NAME <<EOF
#!/sbin/openrc-run
name="webssh"
command="$BIN_PATH"
command_background=true
pidfile="/run/${SERVICE_NAME}.pid"
# 切换到数据目录运行，确保能读取到 data.json
directory="$DATA_DIR"

depend() {
    need net
    after firewall
}
EOF
        chmod +x /etc/init.d/$SERVICE_NAME
        rc-update add $SERVICE_NAME default >/dev/null 2>&1
        service $SERVICE_NAME restart >/dev/null 2>&1
        log_success "OpenRC 服务已安装并启动"

    elif command -v systemctl >/dev/null; then
        # --- Systemd 配置 (Debian/Ubuntu/CentOS) ---
        cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=WebSSH Service
After=network.target

[Service]
Type=simple
# 关键：设置工作目录，程序会在这个目录下寻找 data.json
WorkingDirectory=$DATA_DIR
ExecStart=$BIN_PATH
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable $SERVICE_NAME >/dev/null 2>&1
        systemctl restart $SERVICE_NAME
        log_success "Systemd 服务已安装并启动"
    else
        log_warn "未识别到 Systemd 或 OpenRC，仅完成了文件下载，未配置自启。"
        log_info "你可以尝试手动运行: $BIN_PATH (需先 cd 到 $DATA_DIR)"
    fi

    # 4. 获取 IP 地址
    log_info "正在检测服务器 IP 地址..."
    SERVER_IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(wget -qO- -t1 -T2 ifconfig.me)
    fi
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="[你的服务器IP]"
    fi

    echo ""
    print_line
    echo -e " ${ICON_ROCKET} ${GREEN}WebSSH 安装完成！${PLAIN}"
    print_line
    echo -e " 运行状态: ${GREEN}Active${PLAIN}"
    echo -e " 安装位置: ${CYAN}$BIN_PATH${PLAIN}"
    echo -e " 数据文件: ${CYAN}$DATA_FILE${PLAIN}"
    echo -e " ${ICON_GLOBE} 访问地址: ${CYAN}${BOLD}http://${SERVER_IP}:8080${PLAIN}"
    print_line
    echo ""
    read -p "按回车键返回主菜单..."
}

uninstall_webssh() {
    print_logo
    echo -e "${BOLD}正在卸载 WebSSH...${PLAIN}\n"

    # 停止并删除服务
    if [ -f /etc/alpine-release ]; then
        if [ -f /etc/init.d/$SERVICE_NAME ]; then
            service $SERVICE_NAME stop >/dev/null 2>&1
            rc-update del $SERVICE_NAME default >/dev/null 2>&1
            rm -f /etc/init.d/$SERVICE_NAME
            log_success "服务已停止并移除 (OpenRC)"
        fi
    elif command -v systemctl >/dev/null; then
        if [ -f /etc/systemd/system/${SERVICE_NAME}.service ]; then
            systemctl stop $SERVICE_NAME >/dev/null 2>&1
            systemctl disable $SERVICE_NAME >/dev/null 2>&1
            rm -f /etc/systemd/system/${SERVICE_NAME}.service
            systemctl daemon-reload
            log_success "服务已停止并移除 (Systemd)"
        fi
    fi

    # 删除二进制文件
    if [ -f "$BIN_PATH" ]; then
        rm -f "$BIN_PATH"
        log_success "程序文件已删除"
    else
        log_warn "未找到程序文件 (可能已被删除)"
    fi

    # 询问是否删除数据
    echo ""
    echo -e "${YELLOW}是否同时删除配置文件和数据？${PLAIN}"
    echo -e "路径: ${CYAN}$DATA_DIR${PLAIN}"
    read -p "输入 y 确认删除，其他键保留: " confirm_del
    if [[ "$confirm_del" == "y" || "$confirm_del" == "Y" ]]; then
        rm -rf "$DATA_DIR"
        log_success "配置文件已彻底清除"
    else
        log_info "配置文件已保留，下次安装可直接使用"
    fi

    echo ""
    print_line
    echo -e " ${ICON_TRASH} ${GREEN}WebSSH 卸载完成。${PLAIN}"
    print_line
    echo ""
    read -p "按回车键返回主菜单..."
}

# --- 菜单系统 ---

show_menu() {
    check_root
    while true; do
        print_logo
        echo -e " ${GREEN}1.${PLAIN} 安装 / 更新 WebSSH ${YELLOW}(Install/Update)${PLAIN}"
        echo -e " ${GREEN}2.${PLAIN} 卸载 WebSSH ${YELLOW}(Uninstall)${PLAIN}"
        echo -e " ${GREEN}0.${PLAIN} 退出脚本 ${YELLOW}(Exit)${PLAIN}"
        echo ""
        print_line
        echo -e "${CYAN}说明: 支持 Debian/Ubuntu/Alpine 等常见 Linux 发行版${PLAIN}"
        echo ""
        read -p " 请输入选项 [0-2]: " choice
        
        case "$choice" in
            1) install_webssh ;;
            2) uninstall_webssh ;;
            0) exit 0 ;;
            *) echo -e "\n${RED}输入无效，请重新输入...${PLAIN}"; sleep 1 ;;
        esac
    done
}

# --- 入口处理 ---

if [ "$1" == "install" ]; then
    check_root
    install_webssh
    exit 0
elif [ "$1" == "uninstall" ]; then
    check_root
    uninstall_webssh
    exit 0
else
    show_menu
fi
