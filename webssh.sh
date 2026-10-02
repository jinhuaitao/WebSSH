#!/bin/bash

# =========================================================
#  WebSSH Manager - One-Click Installer / Updater
#  System: Debian/Ubuntu (Systemd) & Alpine (OpenRC)
#  Arch: AMD64 & ARM64 Auto-Detect
# =========================================================

# --- 基础配置 ---
# GitHub 代理前缀（设为空串则直连 GitHub）
GH_PROXY="${GH_PROXY:-https://jht126.eu.org/}"
# 仓库地址
GH_USER_REPO="jinhuaitao/WebSSH"
# 仓库发布地址根目录
GH_REPO="https://github.com/${GH_USER_REPO}/releases/latest/download"
# GitHub Releases API（用于检查最新版本）
GH_API="https://api.github.com/repos/${GH_USER_REPO}/releases/latest"

BIN_PATH="/usr/local/bin/webssh"
SERVICE_NAME="webssh"
# 数据持久化目录
DATA_DIR="/etc/webssh"
DATA_FILE="$DATA_DIR/data.json"
# 本地版本缓存（程序不可执行时兜底）
VERSION_FILE="$DATA_DIR/.version"

# 二进制最小合法大小 (1MB)，防止把错误页面当成程序安装
MIN_BIN_SIZE=1048576

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
ICON_CPU="🖥️"
ICON_SYNC="🔄"

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
    echo -e "   ${YELLOW}WebSSH 终端管理脚本 (多架构版)${PLAIN}"
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

check_arch() {
    local arch_raw=$(uname -m)
    case "${arch_raw}" in
        x86_64|amd64)
            ARCH="amd64"
            BINARY_NAME="webssh-linux-amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            BINARY_NAME="webssh-linux-arm64"
            ;;
        *)
            log_error "不支持的 CPU 架构: ${arch_raw}"
            exit 1
            ;;
    esac
    log_info "检测到系统架构: ${GREEN}${ARCH}${PLAIN}"
}

# --- 版本管理 ---

# 获取本地已安装版本（优先读取二进制自身输出，失败则读缓存文件）
get_local_version() {
    if [ -x "$BIN_PATH" ]; then
        local v=$("$BIN_PATH" -v 2>/dev/null | head -n1)
        if [ -n "$v" ]; then
            echo "$v"
            return
        fi
    fi
    if [ -f "$VERSION_FILE" ]; then
        cat "$VERSION_FILE"
        return
    fi
    echo "未安装"
}

# 从 GitHub API 获取最新发布版本号（代理优先，失败回退直连）
get_remote_version() {
    local body=""
    if [ -n "$GH_PROXY" ]; then
        body=$(wget -q -t1 -T10 -O - "${GH_PROXY}${GH_API}" 2>/dev/null)
    fi
    if ! echo "$body" | grep -q '"tag_name"'; then
        body=$(wget -q -t1 -T10 -O - "$GH_API" 2>/dev/null)
    fi
    local tag=$(echo "$body" | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name"[^"]*"\([^"]*\)".*/\1/')
    echo "${tag#v}"
}

# --- 服务管理 ---

service_cmd() {
    local action="$1"
    if [ -f /etc/alpine-release ] && [ -f /etc/init.d/$SERVICE_NAME ]; then
        service $SERVICE_NAME $action >/dev/null 2>&1
    elif command -v systemctl >/dev/null && [ -f /etc/systemd/system/${SERVICE_NAME}.service ]; then
        systemctl $action $SERVICE_NAME >/dev/null 2>&1
    else
        log_error "未找到已安装的 ${SERVICE_NAME} 服务，请先执行安装。"
        return 1
    fi
}

service_status() {
    if [ -f /etc/alpine-release ] && [ -f /etc/init.d/$SERVICE_NAME ]; then
        if service $SERVICE_NAME status >/dev/null 2>&1; then
            echo -e " 运行状态: ${GREEN}Active (OpenRC)${PLAIN}"
        else
            echo -e " 运行状态: ${RED}Inactive${PLAIN}"
        fi
    elif command -v systemctl >/dev/null && [ -f /etc/systemd/system/${SERVICE_NAME}.service ]; then
        if systemctl is-active --quiet $SERVICE_NAME; then
            echo -e " 运行状态: ${GREEN}Active (Systemd)${PLAIN}"
        else
            echo -e " 运行状态: ${RED}Inactive${PLAIN}"
        fi
    else
        echo -e " 运行状态: ${YELLOW}未注册为系统服务${PLAIN}"
    fi
}

# --- 核心功能 ---

prepare_data_dir() {
    log_info "正在准备运行环境..."
    if [ ! -d "$DATA_DIR" ]; then
        mkdir -p "$DATA_DIR"
    fi

    # 确保 data.json 是文件而不是文件夹，且有权限
    if [ ! -f "$DATA_FILE" ]; then
        if [ -d "$DATA_FILE" ]; then
            rm -rf "$DATA_FILE"
        fi
        touch "$DATA_FILE"
        chmod 666 "$DATA_FILE"
        log_success "配置文件初始化成功"
    else
        log_info "检测到已有配置文件，保留现有配置"
        chmod 666 "$DATA_FILE"
    fi
}

setup_service() {
    log_info "正在配置系统服务..."

    if [ -f /etc/alpine-release ]; then
        # --- Alpine OpenRC 配置 ---
        cat > /etc/init.d/$SERVICE_NAME <<EOF
#!/sbin/openrc-run
name="webssh"
command="$BIN_PATH"
command_background=true
pidfile="/run/${SERVICE_NAME}.pid"
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
        # --- Systemd 配置 ---
        cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=WebSSH Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$DATA_DIR
ExecStart=$BIN_PATH
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable $SERVICE_NAME >/dev/null 2>&1
        systemctl restart $SERVICE_NAME
        log_success "Systemd 服务已安装并启动"
    else
        log_warn "未识别到 Systemd 或 OpenRC，仅下载了文件。"
        log_info "手动运行: $BIN_PATH (需先 cd 到 $DATA_DIR)"
    fi
}

print_access_info() {
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
    echo -e " ${ICON_ROCKET} ${GREEN}WebSSH 部署完成！${PLAIN}"
    print_line
    echo -e " 架构版本: ${GREEN}${BINARY_NAME}${PLAIN}"
    echo -e " 当前版本: ${GREEN}$(get_local_version)${PLAIN}"
    service_status
    echo -e " 安装位置: ${CYAN}$BIN_PATH${PLAIN}"
    echo -e " 数据文件: ${CYAN}$DATA_FILE${PLAIN}"
    echo -e " ${ICON_GLOBE} 访问地址: ${CYAN}${BOLD}http://${SERVER_IP}:8080${PLAIN}"
    print_line
    echo ""
}

# 下载并原子替换二进制（先下载到临时文件，校验大小后再覆盖，失败自动回滚）
download_binary() {
    local download_url="${GH_PROXY}${GH_REPO}/${BINARY_NAME}"
    local tmp_path="${BIN_PATH}.download"

    log_info "正在下载: ${BINARY_NAME}"
    rm -f "$tmp_path"
    wget -q --show-progress -O "$tmp_path" "$download_url"
    if [ $? -ne 0 ] || [ ! -s "$tmp_path" ]; then
        echo ""
        log_error "下载失败！"
        log_error "链接: $download_url"
        rm -f "$tmp_path"
        return 1
    fi

    local size=$(wc -c < "$tmp_path" | tr -d ' ')
    if [ "$size" -lt "$MIN_BIN_SIZE" ]; then
        echo ""
        log_error "下载内容异常（仅 ${size} 字节，可能是代理返回了错误页面），已取消本次更新。"
        rm -f "$tmp_path"
        return 1
    fi

    # 备份旧版本，替换失败可回滚
    local backup=""
    if [ -f "$BIN_PATH" ]; then
        backup="${BIN_PATH}.bak"
        cp -f "$BIN_PATH" "$backup"
    fi

    chmod +x "$tmp_path"
    if ! mv -f "$tmp_path" "$BIN_PATH"; then
        log_error "替换二进制失败！"
        if [ -n "$backup" ]; then
            mv -f "$backup" "$BIN_PATH"
            log_info "已回滚到旧版本"
        fi
        rm -f "$tmp_path"
        return 1
    fi
    echo ""
    log_success "下载成功，安装路径: ${CYAN}$BIN_PATH${PLAIN} (${size} bytes)"
    return 0
}

install_webssh() {
    print_logo
    check_root
    check_dependencies

    # 1. 检测架构
    check_arch
    LOCAL_VER=$(get_local_version)
    echo -e "${BOLD}本地版本: ${GREEN}${LOCAL_VER}${PLAIN}"

    # 2. 版本对比
    log_info "正在检查最新版本..."
    REMOTE_VER=$(get_remote_version)
    if [ -n "$REMOTE_VER" ]; then
        echo -e "${BOLD}最新版本: ${GREEN}${REMOTE_VER}${PLAIN}"
        if [ "$LOCAL_VER" == "$REMOTE_VER" ]; then
            echo ""
            read -p "已是最新版本，是否仍要重新下载安装? [y/N]: " redo
            if [[ "$redo" != "y" && "$redo" != "Y" ]]; then
                log_info "已取消。"
                read -p "按回车键返回..."
                return
            fi
        else
            echo ""
            read -p "确认将 WebSSH 从 ${LOCAL_VER} 更新到 ${REMOTE_VER}? [Y/n]: " go
            if [[ "$go" == "n" || "$go" == "N" ]]; then
                log_info "已取消。"
                read -p "按回车键返回..."
                return
            fi
        fi
    else
        log_warn "无法获取最新版本信息，将继续下载 latest 版本"
    fi

    echo -e "\n${BOLD}正在开始安装 WebSSH (${ARCH})...${PLAIN}\n"

    # 3. 准备目录和数据文件
    prepare_data_dir

    # 4. 下载二进制文件（原子替换 + 校验 + 回滚）
    if ! download_binary; then
        read -p "按回车键返回..."
        return
    fi

    # 记录版本缓存
    if [ -n "$REMOTE_VER" ]; then
        echo "$REMOTE_VER" > "$VERSION_FILE"
    fi

    # 5. 配置并重启服务
    setup_service

    # 6. 输出访问信息
    print_access_info
    read -p "按回车键返回主菜单..."
}

check_update() {
    print_logo
    echo -e "${BOLD}正在检查更新...${PLAIN}\n"
    LOCAL_VER=$(get_local_version)
    log_info "本地版本: ${GREEN}${LOCAL_VER}${PLAIN}"
    log_info "正在查询最新版本..."
    REMOTE_VER=$(get_remote_version)
    if [ -z "$REMOTE_VER" ]; then
        log_error "获取最新版本失败，请检查网络或 GH_PROXY 配置"
        read -p "按回车键返回..."
        return
    fi
    log_info "最新版本: ${GREEN}${REMOTE_VER}${PLAIN}"
    print_line
    if [ "$LOCAL_VER" == "$REMOTE_VER" ]; then
        echo -e " ${ICON_SUCCESS} ${GREEN}当前已是最新版本，无需更新。${PLAIN}"
    else
        echo -e " ${ICON_SYNC} ${YELLOW}发现新版本: ${LOCAL_VER} -> ${REMOTE_VER}${PLAIN}"
        read -p " 是否立即更新? [Y/n]: " up
        if [[ "$up" != "n" && "$up" != "N" ]]; then
            install_webssh
            return
        fi
    fi
    print_line
    echo ""
    read -p "按回车键返回主菜单..."
}

control_service() {
    local action="$1"
    print_logo
    case "$action" in
        start)   service_cmd start   && log_success "WebSSH 已启动" ;;
        stop)    service_cmd stop    && log_success "WebSSH 已停止" ;;
        restart) service_cmd restart && log_success "WebSSH 已重启" ;;
    esac
    echo ""
    service_status
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
        rm -f "$BIN_PATH" "${BIN_PATH}.bak" "${BIN_PATH}.download"
        log_success "程序文件已删除"
    else
        log_warn "未找到程序文件"
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
        log_info "配置文件已保留"
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
        echo -e " ${GREEN}2.${PLAIN} 检查更新 ${YELLOW}(Check Update)${PLAIN}"
        echo -e " ${GREEN}3.${PLAIN} 启动服务 ${YELLOW}(Start)${PLAIN}"
        echo -e " ${GREEN}4.${PLAIN} 停止服务 ${YELLOW}(Stop)${PLAIN}"
        echo -e " ${GREEN}5.${PLAIN} 重启服务 ${YELLOW}(Restart)${PLAIN}"
        echo -e " ${GREEN}6.${PLAIN} 卸载 WebSSH ${YELLOW}(Uninstall)${PLAIN}"
        echo -e " ${GREEN}0.${PLAIN} 退出脚本 ${YELLOW}(Exit)${PLAIN}"
        echo ""
        print_line
        echo -e " 当前版本: ${GREEN}$(get_local_version)${PLAIN}"
        service_status
        echo -e "${CYAN}说明: 支持 AMD64/ARM64 架构，支持 Debian/Ubuntu/Alpine${PLAIN}"
        echo ""
        read -p " 请输入选项 [0-6]: " choice

        case "$choice" in
            1) install_webssh ;;
            2) check_update ;;
            3) control_service start ;;
            4) control_service stop ;;
            5) control_service restart ;;
            6) uninstall_webssh ;;
            0) exit 0 ;;
            *) echo -e "\n${RED}输入无效，请重新输入...${PLAIN}"; sleep 1 ;;
        esac
    done
}

# --- 入口处理 ---

case "$1" in
    install)
        check_root; install_webssh; exit 0 ;;
    update|check-update)
        check_root; check_update; exit 0 ;;
    start)
        check_root; service_cmd start && log_success "WebSSH 已启动"; exit 0 ;;
    stop)
        check_root; service_cmd stop && log_success "WebSSH 已停止"; exit 0 ;;
    restart)
        check_root; service_cmd restart && log_success "WebSSH 已重启"; exit 0 ;;
    status)
        check_root
        echo -e " 当前版本: ${GREEN}$(get_local_version)${PLAIN}"
        service_status
        exit 0 ;;
    uninstall)
        check_root; uninstall_webssh; exit 0 ;;
    *)
        show_menu ;;
esac
