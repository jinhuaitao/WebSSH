# ==========================================
# 第一阶段：构建环境 (Builder)
# 使用 golang:alpine 默认拉取最新稳定版，解决 crypto 依赖报错
# ==========================================
FROM golang:alpine AS builder

# 设置工作目录
WORKDIR /build

# 安装 git（Alpine 镜像精简，部分 go mod 拉取强依赖 git）
# 注意：GitHub 环境网络畅通，不需要配置 GOPROXY 代理
RUN apk add --no-cache git

# 先复制依赖清单，利用 Docker 层缓存（依赖不变时无需重新下载）
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY main.go .

# 构建参数：版本号（与源码默认值保持一致，CI 可通过 --build-arg VERSION 覆盖）
ARG VERSION=0.0.22

# 编译 Go 源码 (关闭 CGO，指定 Linux 系统，压缩体积)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o webssh-app .


# ==========================================
# 第二阶段：运行环境 (Final)
# ==========================================
FROM alpine:latest

# 设置工作目录
WORKDIR /app

# 安装必要的系统组件 (HTTPS 证书与时区数据)
RUN apk --no-cache add ca-certificates tzdata

# 设置默认时区（以亚洲/上海为例）
ENV TZ=Asia/Shanghai

# 从构建阶段复制编译好的二进制文件到当前阶段
COPY --from=builder /build/webssh-app .

# 声明应用运行的端口
EXPOSE 8080

# 启动命令（可通过 docker run ... -- 端口 覆盖，或设置环境变量 WEBSSH_PORT）
CMD ["./webssh-app"]
