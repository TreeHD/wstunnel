#!/bin/bash

# =================================================================
# WSTunnel-Go (TCP + UdpGw Proxy Mode) 全自动一键安装/更新脚本
# 作者: xiaoguidays 
# 版本: 7.0 (UdpGw Final)
# =================================================================

set -e 

# --- 脚本设置 ---
# ... (颜色和变量定义，保持不变) ...

# --- 脚本主逻辑 ---
# ... (1. 权限检查, 2. 安装工具, 3. 安装Go，都保持不变) ...

# 4. 拉取代码
info "第 4 步: 正在准备项目目录并拉取最新代码..."
rm -rf "$PROJECT_DIR" && mkdir -p "$PROJECT_DIR" && cd "$PROJECT_DIR" || error_exit "进入项目目录 '$PROJECT_DIR' 失败！"

# [核心修改] 文件列表现在是正确的2个Go文件
FILES=("main.go" "udpgw_handler.go" "admin.html" "login.html" "config.json")

for file in "${FILES[@]}"; do
    info "  -> 正在下载 ${file}..."
    wget -q -O "${file}" "https://raw.githubusercontent.com/${GITHUB_REPO}/${BRANCH}/${file}" || error_exit "下载 ${file} 失败！"
done
info "所有必需文件已成功拉取。" && echo " "

# 5. 编译项目
# ... (编译部分保持不变) ...

# 6. 部署文件
# ... (部署部分保持不变) ...

# 7. 配置 systemd 服务
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
info "第 7 步: 正在配置 systemd 服务..."
cat > "$SERVICE_FILE" <<EOT
[Unit]
Description=WSTunnel-Go Service (TCP + UdpGw Proxy Mode)
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${DEPLOY_DIR}
ExecStart=${DEPLOY_DIR}/${BINARY_NAME}
Restart=always
RestartSec=3
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOT
systemctl daemon-reload && systemctl enable ${SERVICE_NAME}.service || error_exit "systemd 配置失败！"
info "服务配置完成并已启用。" && echo " "

# 8. 启动服务
# ... (启动和状态检查部分保持不变) ...
