# Docker-Pull

一个无需 Docker 环境即可拉取 Docker 镜像并保存为 tar 文件的 Go 工具。

## 功能特点

- 无需安装 Docker 即可拉取镜像
- 支持公共和私有 Docker Registry
- 支持身份验证
- 支持多架构镜像选择
- 将镜像保存为标准 Docker tar 格式

## 使用方法

### 基本用法

```bash
# 拉取镜像
dip --image nginx:latest

# 指定输出文件
dip --image nginx:latest --output nginx.tar

# 从自定义 Registry 拉取
dip --image registry.example.com/myapp:v1.0 --output myapp.tar

# 拉取私有仓库镜像（需要认证）
dip --image private-registry.com/myapp:v1.0 --username user --password pass

# 拉取指定架构的镜像
dip --image nginx:latest --arch arm64

# 允许不安全的HTTPS连接
dip --image insecure-registry.com/myapp:v1.0 --insecure
```

### 命令行参数

| 参数 | 描述 | 默认值 |
|------|------|--------|
| `--image` | Docker镜像名称 (格式: [registry/]repository[:tag]) | 无，必须指定 |
| `--output` | 输出文件路径 | repository-tag-arch.tar |
| `--registry` | Docker Registry地址 | registry-1.docker.io |
| `--username` | Registry用户名 | 空 |
| `--password` | Registry密码 | 空 |
| `--arch` | 镜像架构 (例如: amd64, arm64) | amd64 |
| `--insecure` | 允许不安全的HTTPS连接 | false |
| `--version` | 显示版本信息 | false |

### 镜像名称格式

镜像名称支持以下格式：

- `nginx` - 从 Docker Hub 拉取最新版本
- `nginx:1.19` - 从 Docker Hub 拉取指定标签版本
- `registry.example.com/nginx` - 从自定义 Registry 拉取最新版本
- `registry.example.com:5000/nginx:1.19` - 从带端口的自定义 Registry 拉取指定版本

## 示例

### 拉取 Nginx 镜像

```bash
dip --image nginx:latest
```

输出：

```
开始拉取镜像: library/nginx:latest 从 registry-1.docker.io
开始下载 3 个镜像层...
下载层 1/3: sha256:a76df3b4f1a4f34ab1f7f816ccd4a4f4354583747c7f93c0b7f32b696a5a9c41
下载层 2/3: sha256:4b704345c7e9c3c91d0f5e0d55a16c4ceb6f9c0c0c0d0e2e9ae8d9fe93a7c47c
下载层 3/3: sha256:992af3a24e9d8c382f9d8f23a7c4c4d1b5b2eef0a5e792e6b9b6b1c137c6d878
创建tar文件: nginx-latest-amd64.tar
镜像已成功保存到: nginx-latest-amd64.tar
```

### 拉取并加载到 Docker

虽然本工具不需要 Docker 环境来拉取镜像，但如果您有 Docker 环境，可以将拉取的镜像加载到 Docker 中：

```bash
# 拉取镜像
docker-pull --image nginx:latest

# 加载到 Docker
docker load -i nginx-latest-amd64.tar
```

### 从私有仓库拉取

```bash
# 使用用户名密码认证
dip --image private-registry.com/myapp:v1.0 \
           --username myuser \
           --password mypass

# 允许自签名证书
dip --image private-registry.com/myapp:v1.0 \
           --username myuser \
           --password mypass \
           --insecure
```

### 拉取多架构镜像

```bash
# 拉取 ARM64 架构的镜像
dip --image nginx:latest --arch arm64

# 拉取 AMD64 架构的镜像
dip --image nginx:latest --arch amd64
```