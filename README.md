# DIP - Docker Image Pull

一个无需 Docker 环境即可拉取 Docker 镜像并保存为 tar 文件的 Go 工具。

## ✨ 功能特点

- 🚀 **无需 Docker** - 无需安装 Docker 即可拉取镜像
- 🔄 **并发下载** - 支持多线程并发下载，大幅提升下载速度
- 🔁 **自动重试** - 网络不稳定时自动重试，确保下载成功
- ✅ **完整性验证** - 下载后自动校验摘要，确保文件完整性
- 🌐 **默认直连** - 直接访问原始镜像仓库，可按需配置自定义加速器
- 📦 **层缓存** - 智能缓存已下载的层，重复下载秒速完成
- 🔐 **身份验证** - 支持公共和私有 Docker Registry
- 🖥️ **多架构** - 支持 amd64、arm64 等多种架构

## 📦 安装

```bash
# 从源码编译
go build -o dip .
```

## 🚀 使用方法

### 基本用法

```bash
# 拉取镜像（默认直连，无需指定 -m）
dip -i nginx:latest

# 从 GitHub Container Registry 直连拉取
dip -i ghcr.io/jiayi-1994/ai-flowchart:sha-0520fbb

# 指定输出文件
dip -i nginx:latest -o nginx.tar

# 使用5个并发下载
dip -i nginx:latest -c 5

# 拉取指定架构的镜像
dip -i nginx:latest -a arm64

# 从私有仓库拉取（需要认证）
dip -i private-registry.com/myapp:v1.0 -u user -p pass
```

### 命令行参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `-i` | | Docker镜像名称 | 无，必须指定 |
| `-o` | | 输出文件路径 | repository-tag-arch.tar |
| `-r` | | Docker Registry地址 | registry-1.docker.io |
| `-u` | | Registry用户名 | 空 |
| `-p` | | Registry密码 | 空 |
| `-a` | | 镜像架构 (amd64, arm64等) | amd64 |
| `-c` | | 并发下载数 (1-10) | 3 |
| `-m` | | 镜像加速器地址列表，逗号分隔；`-m=` 强制直连 | 空（直连）；可由 `DOCKER_PULL_MIRRORS` 配置 |
| `-k` | | 允许不安全的HTTPS连接 | false |
| `--retry` | | 下载失败重试次数 | 3 |
| `--timeout` | | 下载超时时间（秒） | 300 |
| `--cache-dir` | | 层缓存目录 | ~/.docker-pull/cache |
| `--version` | | 显示版本信息 | - |

### 镜像名称格式

支持以下格式：

- `nginx` - 从 Docker Hub 拉取最新版本
- `nginx:1.19` - 从 Docker Hub 拉取指定标签版本
- `registry.example.com/nginx` - 从自定义 Registry 拉取
- `registry.example.com:5000/nginx:1.19` - 带端口的自定义 Registry

## 📋 示例

### 拉取 Nginx 镜像

```bash
dip -i nginx:latest
```

输出示例：

```
========================================
镜像: library/nginx:latest
架构: amd64
仓库: registry-1.docker.io
并发数: 3
重试次数: 3
========================================
正在获取镜像清单...
✓ 使用原始仓库: registry-1.docker.io
发现 7 个镜像层，使用 3 个并发下载
进度: [7/7层] 65.2 MB / 65.2 MB (12.50 MB/s)
✓ 所有 7 个层下载完成
正在创建镜像文件...
========================================
✓ 镜像已成功保存到: library_nginx-latest-amd64.tar
✓ 文件大小: 187.45 MB
========================================
```

### 加载到 Docker

```bash
# 拉取镜像
dip -i nginx:latest

# 加载到 Docker
docker load -i library_nginx-latest-amd64.tar
```

### 高级用法

```bash
# 使用5个并发，最多重试5次
dip -i nginx:latest -c 5 --retry 5

# 指定超时时间为10分钟
dip -i large-image:latest --timeout 600

# 强制直连，忽略环境变量中配置的镜像加速器
dip -i nginx:latest -m=

# 使用自定义加速器
dip -i nginx:latest -m "mirror1.example.com,mirror2.example.com"
```

默认不使用镜像加速器，已移除所有内置加速器地址。只有显式设置 `-m` 或 `DOCKER_PULL_MIRRORS` 时才会使用自定义加速器。

**PowerShell 用户**：旧版 PowerShell 可能丢弃 `-m ""` 中的空字符串，导致 `flag needs an argument: -m`。默认直连时省略 `-m` 即可；需要覆盖环境变量时使用 `-m=`，该写法也适用于其他 Shell。

## 🔧 环境变量

| 变量名 | 描述 |
|--------|------|
| `DOCKER_PULL_MIRRORS` | 可选的镜像加速器地址列表，逗号分隔；未设置时直连 |

命令行 `-m` 优先于环境变量，显式传入 `-m=` 会禁用环境变量中的加速器。列表中的空白项会被忽略。

## 📄 版本历史

### v2.0.1
- 默认直连原始镜像仓库，移除所有内置加速器地址
- 保留通过 `-m` 或 `DOCKER_PULL_MIRRORS` 配置自定义加速器
- 支持使用 `-m=` 强制直连并覆盖环境变量，更新 PowerShell 使用说明
- 新增镜像加速器配置和仓库选择回归测试
- 同步程序内版本号与 Release 版本号

### v0.2.0
- ✨ 新增并发下载功能
- ✨ 新增下载重试机制
- ✨ 新增镜像完整性验证
- ✨ 优化进度显示（总体进度）
- 🔧 优化 HTTP 客户端连接池配置
- 🔧 修复架构硬编码问题
- 🔧 统一错误信息为中文

### v0.1.0
- 🎉 初始版本发布
