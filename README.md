# WebSSH

一个基于Go语言和WebSocket的Web版SSH终端工具，提供美观现代的用户界面。

## 功能特点

- 用户注册和登录系统，保障安全访问
- 通过浏览器访问SSH终端
- 支持密码和SSH密钥认证
- 响应式设计，适配不同屏幕尺寸
- 实时终端体验，支持所有终端命令
- 保存最近连接历史
- 现代化UI界面，支持移动设备
- 数据持久化存储

## 快速开始

### 使用Docker（推荐）

**这是运行应用的首选方法，不需要安装Go环境**

1. 确保已安装Docker和Docker Compose
2. 克隆此仓库
3. 在项目根目录运行：
```bash
git clone https://github.com/jinhuaitao/WebSSH.git
```
```bash
cd WebSSH
```
```bash
docker-compose up -d
```
或
```bash
docker run -d --name webssh --restart=always --network host jhtone/webssh
```
4. 打开浏览器访问：http://localhost:8080


### 手动运行（需要Go环境）

如果您已经安装了Go 1.16+，可以直接运行：
```bash
git clone https://github.com/jinhuaitao/WebSSH.git
```
```bash
cd WebSSH
```
```bash
go mod tidy
```
```
go run main.go
```

使用 nohup 防止终端退出时进程被终止
```bash
nohup go run main.go > output.log 2>&1 &
```
然后打开浏览器访问：http://localhost:8080

## 使用方法

### 用户认证

1. 首次使用需要注册账号：
   - 点击"立即注册"链接
   - 填写用户名、电子邮箱（可选）和密码
   - 点击"注册"按钮创建账号

2. 使用已注册的账号登录系统：
   - 输入用户名和密码
   - 点击"登录"按钮

### SSH连接

1. 登录后，在SSH连接界面输入连接信息：
   - 主机地址
   - 端口（默认22）
   - 用户名
   - 选择认证方式（密码或SSH密钥）
   - 输入密码或粘贴私钥

2. 点击"连接"按钮

3. 使用Web终端，就像在本地终端一样操作

4. 完成后点击"断开连接"按钮或使用右上角的用户名旁的退出按钮登出系统

## 界面预览

应用提供了现代化的用户界面：

- 侧边栏：包含连接表单和最近连接历史
- 欢迎页：首次访问时显示
- 终端页：连接成功后显示，提供全功能终端体验
- 响应式设计：在移动设备上自动调整布局

## 使用方法

1. 在登录界面输入SSH连接信息：
   - 主机地址
   - 端口（默认22）
   - 用户名
   - 选择认证方式（密码或SSH密钥）
   - 输入密码或粘贴私钥

2. 点击"连接"按钮

3. 使用Web终端，就像在本地终端一样操作

4. 完成后点击"断开连接"按钮

## 安全说明

- 用户密码使用bcrypt算法加密存储，确保安全
- 用户会话使用安全Cookie管理
- 所有SSH连接都是在服务器端与目标主机之间建立的
- SSH密码和密钥不会被永久存储
- 数据库文件使用Docker卷持久化存储
- 建议在可信网络环境中使用
- 生产环境使用时，请考虑添加HTTPS支持

## 许可证

MIT
<img width="1647" height="1120" alt="image" src="https://github.com/user-attachments/assets/66e3f068-20b3-4f4f-851a-a62605d01c1a" />

<img width="1646" height="1117" alt="image" src="https://github.com/user-attachments/assets/067f745a-f095-4767-a5cc-cb632e184200" />
<img width="1652" height="1119" alt="38f6abb0-c3fb-478c-8ba1-dd3c707b543c" src="https://github.com/user-attachments/assets/ac0b2507-bbc1-42ee-97b1-644adfdea2a7" />
<img width="1644" height="1114" alt="dca45297-c3ed-402f-8164-5b6dcde27285" src="https://github.com/user-attachments/assets/70b49141-f747-4a36-b892-c901bf019a05" />
