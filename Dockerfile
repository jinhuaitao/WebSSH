# ==========================================
# 第一阶段：构建环境 (Builder)
# ==========================================
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /build

# 复制源代码到容器中
COPY main.go .

# 初始化 Go 模块并下载依赖
# 由于没有提供 go.mod，我们在这里动态生成
RUN go mod init webssh && \
    go mod tidy

# 编译 Go 源码
# CGO_ENABLED=0 确保编译出静态链接的二进制文件，方便在极简基础镜像中运行
# -ldflags="-s -w" 用于去除调试信息，进一步减小二进制文件体积
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webssh-app main.go


# ==========================================
# 第二阶段：运行环境 (Final)
# ==========================================
FROM alpine:latest

# 设置工作目录
WORKDIR /app

# 安装必要的系统组件
# tzdata: 用于保证时间准确（TOTP 2FA 强依赖时间）
# ca-certificates: 用于支持 HTTPS 请求（如 Telegram Bot API 通知）
RUN apk --no-cache add ca-certificates tzdata

# 设置默认时区（以亚洲/上海为例，可根据需要修改或在 run 时通过环境变量覆盖）
ENV TZ=Asia/Shanghai

# 从构建阶段复制编译好的二进制文件到当前阶段
COPY --from=builder /build/webssh-app .

# 声明应用运行的端口（代码中硬编码为 8080）
EXPOSE 8080

# 启动命令
CMD ["./webssh-app"]
