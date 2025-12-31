🎉 发布正式版：wstunnel-go

现正式发布 wstunnel-go 正式版 🚀

项目基于 Go（Golang） 语言开发，对连接方式与传输逻辑进行了重构，兼顾性能、稳定性与部署便捷性，适用于多种复杂网络环境。

✨ 项目特性

✅ Go 语言编写，单文件编译，跨平台运行

✅ 启动快、资源占用低

✅ 适合长期运行与服务端部署

🔧 已支持模式

Direct

Direct TLS

HTTP Payload

SNI Fronted（TLS + HTTP Payload）

可灵活应对直连、TLS 加密以及基于 SNI 的前置与中转场景。

📦 版本状态

当前版本：正式版（Stable Release）

已可用于实际环境部署

🔗 项目地址

GitHub：
https://github.com/xiaoguiday/xiyang110

欢迎测试、反馈问题与提交建议，一起完善项目 🙌
=======================

编译好的X86架构版本已经打包,打包里面包含了我原服务器的数据,你们自己删除,默认面板账号密码admin:@@123123@@

安装教程1

WSTunnel + UdpGw 部署说明文档
方案一：标准化一键安装（推荐）
此方案直接将文件放置在系统预期的 /usr/local/bin 目录中，无需修改服务文件，稳定性最高。

使用方法：
将 111.zip 上传到服务器 root 目录。
复制下方脚本，保存为 install.sh。
执行 bash install.sh。
 复制代码 隐藏代码
#!/bin/bash

# WSTunnel 一键部署脚本
echo "开始部署 WSTunnel + UdpGw..."

# 1. 基础准备
apt update && apt install -y unzip
mkdir -p ~/111_temp
unzip -o 111.zip -d ~/111_temp
cd ~/111_temp

# 2. 移动文件到标准路径 (消除路径修正需求)
chmod +x wstunnel-go badvpn-udpgw
cp wstunnel-go badvpn-udpgw config.json admin.html login.html traffic.json /usr/local/bin/

# 3. 部署服务文件
if [ -f "wstunnel.service" ] && [ -f "udpgw.service" ]; then
    cp *.service /etc/systemd/system/
else
    echo "错误：未在压缩包内找到 .service 文件"
    exit 1
fi

# 4. 启动服务
systemctl daemon-reload
systemctl enable --now wstunnel.service udpgw.service

echo "------------------------------------------------"
echo "部署完成！"
echo "管理面板: http://$(curl -s ifconfig.me):9090/login.html"
echo "默认账号: admin"
echo "默认密码: @@123123@@"
echo "------------------------------------------------"
安装教程2

WSTunnel + UdpGw 标准化部署指南（推荐方案）
本方案直接将文件部署至系统默认的路径 /usr/local/bin，以匹配 .service 文件的默认配置。

1. 环境准备
 复制代码 隐藏代码
apt update && apt install -y unzip
unzip 111.zip -d ~/111
cd ~/111
2. 一步到位部署（无需修正路径）
直接将所有文件移动到服务文件预期的 /usr/local/bin 路径下：

 复制代码 隐藏代码
# 1. 赋予执行权限
chmod +x wstunnel-go badvpn-udpgw

# 2. 直接分发到系统预设位置
# 程序、配置、网页模板必须放在一起，以确保面板能正常加载
cp wstunnel-go badvpn-udpgw config.json admin.html login.html traffic.json /usr/local/bin/

# 3. 部署服务文件
cp *.service /etc/systemd/system/
3. 启动服务
 复制代码 隐藏代码
systemctl daemon-reload
systemctl enable --now wstunnel.service udpgw.service
