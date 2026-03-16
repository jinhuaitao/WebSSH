# ==========================================
# 第一阶段：构建环境 (Builder) - 升级到 1.24
# ==========================================
FROM golang:1.24-alpine AS builder

# 设置工作目录
WORKDIR /build

# 【修复 1】：安装 git，防止拉取 github 依赖时因为找不到 git 命令而报错退出
RUN apk add --no-cache git

# 【修复 2】：设置国内 GOPROXY 代理，解决 golang.org 依赖包拉取超时的问题
ENV GOPROXY=https://goproxy.cn,direct

# 复制源代码到容器中
COPY main.go .

# 初始化 Go 模块并下载依赖
RUN go mod init webssh && \
    go mod tidy

# 编译 Go 源码
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webssh-app main.go

# ==========================================
# 第二阶段：运行环境 (Final)
# ==========================================
FROM alpine:latest

# 设置工作目录
WORKDIR /app

# 安装必要的系统组件
RUN apk --no-cache add ca-certificates tzdata

# 设置默认时区（以亚洲/上海为例）
ENV TZ=Asia/Shanghai

# 从构建阶段复制编译好的二进制文件到当前阶段
COPY --from=builder /build/webssh-app .

# 声明应用运行的端口
EXPOSE 8080

# 启动命令
CMD ["./webssh-app"]
