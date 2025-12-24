🚀 WebSSH Manager
一款轻量级、现代化的 Web 端 SSH 运维管理工具

WebSSH Manager 是一个基于 Go 语言开发的单文件 WebSSH 解决方案。它无需复杂的配置和外部数据库依赖，通过浏览器即可提供功能完整的 SSH 终端和 SFTP 文件管理体验。特别针对移动端进行了深度优化，支持 PWA，是运维人员随时随地管理服务器的绝佳伴侣。

✨ 主要特性
🛠 轻量极简：基于 Go 编写，编译为单二进制文件，资源占用极低，无任何外部依赖。

📱 移动优先：精心设计的移动端 UI，底部导航栏操作，支持 PWA（可添加到手机主屏幕作为 App 使用）。

💻 全功能终端：集成 xterm.js，支持全彩显示、自定义行列、快捷指令（Snippet）发送。

📂 SFTP 文件管理：内置 SFTP 面板，支持文件列表、上传、下载以及在线编辑（支持语法高亮）。

🛡 安全保障：支持 2FA 双因素认证 (Google Authenticator)，保障账户安全；支持 Telegram 机器人 登录/连接通知。

⚡ 高效管理：支持服务器分组管理、凭证（密码/密钥）统一管理，新增服务器自动归类。

🌐 网络兼容：完美支持 IPv6 服务器连接。

🖥 界面预览
仪表盘：直观的服务器列表与分组展示。

终端：流畅的 SSH 会话体验。

手机端：适配移动操作习惯，随时随地应急响应。

🚀 快速部署
方法一：Docker 一键启动（推荐）
无需任何环境配置，一条命令即可启动：


```
touch data.json && chmod 666 data.json && docker run -d --name webssh --restart=always --network host -v $(pwd)/data.json:/app/data.json jhtone/webssh
```
说明：

容器默认使用 host 网络模式，直接监听宿主机端口（默认 8080），完美支持 IPv6。

数据文件 data.json 会挂载在当前目录下，迁移方便。

方法二：使用管理脚本
如果您使用的是 Linux 服务器，可以使用我们要提供的管理脚本进行安装、升级和卸载：

Bash

# 下载并运行脚本
```
wget -O webssh.sh https://raw.githubusercontent.com/jinhuaitao/WebSSH/main/webssh.sh && chmod +x webssh.sh && ./webssh.sh
```
(注：请根据您实际存放脚本的地址修改上述 URL)

⚙️ 功能配置
初始化：首次访问会自动跳转到初始化页面，设置管理员账号密码。

两步验证：在“设置”中开启 2FA，使用 Google Authenticator 扫描二维码即可绑定。

Telegram 通知：在“设置”中填入 Bot Token 和 Chat ID，即可接收登录告警。

🛠 技术栈
后端：Golang (原生 net/http, golang.org/x/crypto/ssh, github.com/pkg/sftp)

前端：HTML5, Bootstrap 5, xterm.js, Ace Editor

数据存储：本地 JSON 文件 (这也是为何它如此轻量的原因)

📄 开源协议
本项目采用 MIT 协议开源。
