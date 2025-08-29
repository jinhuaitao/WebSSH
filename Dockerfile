FROM golang:1.21 AS builder

WORKDIR /app

# 安装SQLite开发库
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    sqlite3 \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制所有源代码和模块文件
COPY . .

# 初始化模块并下载依赖
RUN go mod tidy && \
    go mod download

# 编译应用（启用CGO以支持SQLite）
RUN CGO_ENABLED=1 GOOS=linux go build -o webssh .

# 使用Ubuntu 22.04作为运行时基础镜像，它有更新的GLIBC版本
FROM ubuntu:22.04

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 从builder阶段复制编译好的应用
COPY --from=builder /app/webssh .

# 复制静态文件和模板
COPY --from=builder /app/static/ ./static/
COPY --from=builder /app/templates/ ./templates/
COPY --from=builder /app/controllers/ ./controllers/
COPY --from=builder /app/middleware/ ./middleware/
COPY --from=builder /app/models/ ./models/

# 创建数据目录并设置权限
RUN mkdir -p /app/data && \
    chmod 755 /app/data

# 设置工作目录
WORKDIR /app

# 暴露端口
EXPOSE 8080

# 运行应用
CMD ["./webssh"]
