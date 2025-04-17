package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// 版本信息
const version = "0.1.0"

// 配置选项
type Config struct {
	Image       string
	Output      string
	Registry    string
	Username    string
	Password    string
	Insecure    bool
	ShowVersion bool
	Arch        string
	CacheDir    string   // 添加缓存目录配置
	Mirrors     []string // 镜像加速器列表
}

// RegistryConfig 保存镜像仓库配置
type RegistryConfig struct {
	URL      string // 仓库地址
	Username string // 用户名
	Password string // 密码
	Insecure bool   // 是否允许不安全连接
}

// RegistryError 表示镜像仓库操作错误
type RegistryError struct {
	Registry string // 仓库地址
	Op       string // 操作类型
	Err      error  // 原始错误
}

func (e *RegistryError) Error() string {
	return fmt.Sprintf("registry %s: %s failed: %v", e.Registry, e.Op, e.Err)
}

// DownloadState 保存下载状态
type DownloadState struct {
	LayerDigest  string    `json:"layer_digest"`
	Downloaded   int64     `json:"downloaded"`
	TotalSize    int64     `json:"total_size"`
	LastModified time.Time `json:"last_modified"`
	PartialHash  string    `json:"partial_hash"`
}

// 主函数
func main() {
	config := parseFlags()

	if config.ShowVersion {
		fmt.Printf("docker-pull version %s\n", version)
		return
	}

	if config.Image == "" {
		fmt.Println("错误: 必须指定镜像名称")
		flag.Usage()
		os.Exit(1)
	}

	// 解析镜像名称
	registry, repository, tag := parseImageName(config.Image, config.Registry)

	// 显示配置信息
	fmt.Printf("开始拉取镜像: %s:%s\n", repository, tag)
	fmt.Printf("默认仓库: %s\n", registry)
	if len(config.Mirrors) > 0 {
		fmt.Printf("配置的镜像加速器: %s\n", strings.Join(config.Mirrors, ", "))
	}

	// 创建HTTP客户端
	client := createHTTPClient(config.Insecure)

	// 获取认证信息
	auth := getAuthToken(client, registry, repository, config.Username, config.Password)

	// 获取镜像清单
	manifest, err := getManifest(client, registry, repository, tag, auth, config.Arch, config.Mirrors)
	if err != nil {
		fmt.Printf("获取镜像清单失败: %v\n", err)
		os.Exit(1)
	}

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "docker-pull-*")
	if err != nil {
		fmt.Printf("创建临时目录失败: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	// 下载镜像层
	layers, err := downloadLayers(client, registry, repository, manifest, auth, tempDir, config.Mirrors)
	if err != nil {
		fmt.Printf("下载镜像层失败: %v\n", err)
		os.Exit(1)
	}

	// 生成输出文件名
	outputFile := config.Output
	if outputFile == "" {
		outputFile = fmt.Sprintf("%s-%s-%s.tar", strings.ReplaceAll(repository, "/", "_"), tag, config.Arch)
	}

	// 创建tar文件
	err = createTarFile(outputFile, manifest, layers, repository, tag)
	if err != nil {
		fmt.Printf("创建tar文件失败: %v\n", err)
		return
	}

	fmt.Printf("镜像已成功保存到: %s\n", outputFile)
}

// 解析命令行参数
func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.Image, "i", "", "Docker镜像名称 (格式: [registry/]repository[:tag])")
	flag.StringVar(&config.Output, "o", "", "输出文件路径 (默认: repository-tag.tar)")
	flag.StringVar(&config.Registry, "r", "registry-1.docker.io", "Docker Registry地址")
	flag.StringVar(&config.Username, "u", "", "Registry用户名")
	flag.StringVar(&config.Password, "p", "", "Registry密码")
	flag.StringVar(&config.Arch, "a", "amd64", "镜像架构 (例如: amd64, arm64)")
	flag.StringVar(&config.CacheDir, "cache-dir", "", "层缓存目录 (默认: ~/.docker-pull/cache)")
	flag.BoolVar(&config.Insecure, "k", false, "允许不安全的HTTPS连接")
	flag.BoolVar(&config.ShowVersion, "version", false, "显示版本信息")

	// 添加镜像加速器支持
	var mirrors string
	flag.StringVar(&mirrors, "m", "docker.gh-proxy.com,docker.1ms.run,docker.xjyi.me", "镜像加速器地址列表，多个地址用逗号分隔")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: docker-pull [选项]\n\n选项:\n")
		fmt.Fprintf(os.Stderr, "  -i, --image string\t\tDocker镜像名称 (格式: [registry/]repository[:tag])\n")
		fmt.Fprintf(os.Stderr, "  -o, --output string\t\t输出文件路径 (默认: repository-tag.tar)\n")
		fmt.Fprintf(os.Stderr, "  -r, --registry string\t\tDocker Registry地址 (默认: registry-1.docker.io)\n")
		fmt.Fprintf(os.Stderr, "  -u, --username string\t\tRegistry用户名\n")
		fmt.Fprintf(os.Stderr, "  -p, --password string\t\tRegistry密码\n")
		fmt.Fprintf(os.Stderr, "  -a, --arch string\t\t镜像架构 (例如: amd64, arm64) (默认: amd64)\n")
		fmt.Fprintf(os.Stderr, "      --cache-dir string\t\t层缓存目录 (默认: ~/.docker-pull/cache)\n")
		fmt.Fprintf(os.Stderr, "  -k, --insecure\t\t允许不安全的HTTPS连接\n")
		fmt.Fprintf(os.Stderr, "  -m, --mirrors string\t\t镜像加速器地址列表，多个地址用逗号分隔\n")
		fmt.Fprintf(os.Stderr, "      --version\t\t\t显示版本信息\n")
	}

	flag.Parse()

	// 处理镜像加速器配置
	if mirrors != "" {
		config.Mirrors = strings.Split(mirrors, ",")
		// 去除空白字符
		for i := range config.Mirrors {
			config.Mirrors[i] = strings.TrimSpace(config.Mirrors[i])
		}
	}

	// 检查环境变量中的镜像加速器配置
	if envMirrors := os.Getenv("DOCKER_PULL_MIRRORS"); envMirrors != "" && len(config.Mirrors) == 0 {
		config.Mirrors = strings.Split(envMirrors, ",")
		for i := range config.Mirrors {
			config.Mirrors[i] = strings.TrimSpace(config.Mirrors[i])
		}
	}

	return config
}

// 解析镜像名称
func parseImageName(imageName, defaultRegistry string) (registry, repository, tag string) {
	// 默认标签为latest
	tag = "latest"

	// 检查是否包含标签
	parts := strings.Split(imageName, ":")
	if len(parts) > 1 {
		// 检查是否包含端口号
		if len(strings.Split(parts[1], "/")) > 1 {
			// 包含端口号，将其作为registry的一部分
			imageArr := parts[:len(parts)-1]
			imageName = strings.Join(imageArr, ":")
			tag = parts[len(parts)-1]
		} else {
			imageName = parts[0]
			tag = parts[1]
		}
	}
	fmt.Println(imageName)
	fmt.Println(tag)
	// 检查是否包含registry
	parts = strings.Split(imageName, "/")
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		// 包含域名或端口号，认为是registry
		registry = parts[0]
		repository = strings.Join(parts[1:], "/")
	} else {
		// 使用默认registry
		registry = defaultRegistry
		repository = imageName

		// 仅当使用Docker Hub且镜像名不包含斜杠时，添加library前缀
		if !strings.Contains(repository, "/") && registry == "registry-1.docker.io" {
			repository = "library/" + repository
		}
	}

	return
}

// 创建HTTP客户端
func createHTTPClient(insecure bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		DisableCompression: false,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}
}

// 获取认证令牌
func getAuthToken(client *http.Client, registry, repository, username, password string) string {
	// 如果提供了用户名和密码，先尝试Basic认证
	if username != "" && password != "" {
		auth := fmt.Sprintf("%s:%s", username, password)
		return "Basic " + base64Encode(auth)
	}

	// 尝试获取token认证
	authURL := fmt.Sprintf("https://%s/v2/", registry)
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// 检查是否需要token认证
	if resp.StatusCode == http.StatusUnauthorized {
		authHeader := resp.Header.Get("Www-Authenticate")
		if strings.HasPrefix(authHeader, "Bearer ") {
			// 解析认证信息
			params := make(map[string]string)
			parts := strings.Split(authHeader[7:], ",")
			for _, part := range parts {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) == 2 {
					params[kv[0]] = strings.Trim(kv[1], "\"")
				}
			}

			// 构建token请求URL
			tokenURL := fmt.Sprintf("%s?service=%s&scope=repository:%s:pull",
				params["realm"],
				params["service"],
				repository)

			// 请求token
			tokenReq, err := http.NewRequest("GET", tokenURL, nil)
			if err != nil {
				return ""
			}

			tokenResp, err := client.Do(tokenReq)
			if err != nil {
				return ""
			}
			defer tokenResp.Body.Close()

			if tokenResp.StatusCode == http.StatusOK {
				var result struct {
					Token string `json:"token"`
				}
				if err := json.NewDecoder(tokenResp.Body).Decode(&result); err == nil {
					return "Bearer " + result.Token
				}
			}
		}
	}

	return ""
}

// Base64编码
func base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// tryRegistries 尝试对多个镜像仓库执行操作，直到成功或全部失败
func tryRegistries(config Config, repository string, operation func(registry string) (interface{}, error)) (interface{}, error) {
	var lastErr error
	registries := []string{}

	// 首先尝试镜像加速器
	if len(config.Mirrors) > 0 {
		registries = append(registries, config.Mirrors...)
	}

	// 最后尝试原始仓库
	registries = append(registries, config.Registry)

	for _, registry := range registries {
		result, err := operation(registry)
		if err == nil {
			// 判断是否使用了加速器
			isMirror := false
			for _, mirror := range config.Mirrors {
				if mirror == registry {
					isMirror = true
					fmt.Printf("成功使用镜像加速器: %s\n", registry)
					break
				}
			}
			if !isMirror {
				fmt.Printf("成功使用原始仓库: %s\n", registry)
			}
			return result, nil
		}
		lastErr = &RegistryError{
			Registry: registry,
			Op:       "registry operation",
			Err:      err,
		}
		fmt.Printf("警告: 从 %s 拉取失败: %v，尝试下一个地址\n", registry, err)
	}

	return nil, fmt.Errorf("所有镜像仓库都失败: %v", lastErr)
}

// getManifest 获取镜像清单
func getManifest(client *http.Client, registry, repository, tag, auth string, arch string, mirrors []string) (map[string]interface{}, error) {
	operation := func(registry string) (interface{}, error) {
		url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, tag)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		// 添加认证头
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}

		// 支持多种manifest格式
		req.Header.Set("Accept", strings.Join([]string{
			"application/vnd.docker.distribution.manifest.v2+json",
			"application/vnd.docker.distribution.manifest.v1+json",
			"application/vnd.docker.distribution.manifest.list.v2+json",
			"application/vnd.oci.image.manifest.v1+json",
			"application/vnd.oci.image.index.v1+json",
		}, ","))

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("获取清单失败，状态码: %d", resp.StatusCode)
		}

		var manifest map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
			return nil, err
		}

		// 处理manifest列表
		if mediaType, ok := manifest["mediaType"].(string); ok {
			if strings.Contains(mediaType, "manifest.list") || strings.Contains(mediaType, "index.v1") {
				// 从manifest列表中选择合适的manifest
				manifests, ok := manifest["manifests"].([]interface{})
				if !ok {
					return nil, fmt.Errorf("无效的manifest列表格式")
				}

				// 查找指定架构的manifest
				for _, m := range manifests {
					if mf, ok := m.(map[string]interface{}); ok {
						platform, ok := mf["platform"].(map[string]interface{})
						if !ok {
							continue
						}

						// 使用传入的arch参数
						if platform["architecture"] == arch && platform["os"] == "linux" {
							// 获取具体的manifest
							digest := mf["digest"].(string)
							return getManifest(client, registry, repository, digest, auth, arch, mirrors)
						}
					}
				}
				return nil, fmt.Errorf("未找到架构为 %s 的manifest", arch)
			}
		}

		return manifest, nil
	}

	// 创建包含镜像加速器配置的 Config
	config := Config{
		Registry: registry,
		Mirrors:  []string{}, // 默认不使用加速器
	}

	// 定义需要使用加速器的仓库列表
	ignoreRegistry := []string{"registry-1.docker.io", "docker.io", "ghcr.io", "k8s.gcr.io", "registry.k8s.io", "quay.io", "mcr.microsoft.com", "docker.elastic.co", "nvcr.io", "gcr.io"}

	// 检查是否需要使用加速器
	if slices.Contains(ignoreRegistry, registry) {
		config.Mirrors = mirrors
	}

	result, err := tryRegistries(config, repository, operation)
	if err != nil {
		return nil, err
	}

	return result.(map[string]interface{}), nil
}

// 下载镜像层
func downloadLayers(client *http.Client, registry, repository string, manifest map[string]interface{}, auth, tempDir string, mirrors []string) ([]string, error) {
	var layers []interface{}

	// 获取缓存目录
	config := Config{} // 使用默认配置
	cacheDir, err := getCacheDir(config)
	if err != nil {
		fmt.Printf("警告: 无法获取缓存目录: %v，将不使用缓存\n", err)
		cacheDir = ""
	}

	// 检查manifest版本并获取层信息
	if schemaVersion, ok := manifest["schemaVersion"].(float64); ok {
		if schemaVersion == 1 {
			// Schema 1格式
			if fsLayers, ok := manifest["fsLayers"].([]interface{}); ok {
				layers = make([]interface{}, len(fsLayers))
				for i, layer := range fsLayers {
					if blobSum, ok := layer.(map[string]interface{})["blobSum"].(string); ok {
						layers[i] = map[string]interface{}{"digest": blobSum}
					}
				}
			}
		} else {
			// Schema 2格式
			if l, ok := manifest["layers"].([]interface{}); ok {
				layers = l
			}
		}
	}

	if layers == nil {
		return nil, fmt.Errorf("无效的manifest格式或未找到层信息")
	}

	layerFiles := make([]string, 0, len(layers))

	fmt.Printf("开始下载 %d 个镜像层...\n", len(layers))

	for i, layer := range layers {
		layerInfo, ok := layer.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("无效的层信息格式")
		}

		digest, ok := layerInfo["digest"].(string)
		if !ok {
			return nil, fmt.Errorf("无效的层摘要")
		}

		// 检查缓存
		if cacheDir != "" {
			if cachedFile, exists := checkLayerCache(cacheDir, digest); exists {
				fmt.Printf("层 %d/%d: %s 从缓存中获取\n", i+1, len(layers), digest)
				layerFiles = append(layerFiles, cachedFile)
				continue
			}
		}

		fmt.Printf("下载层 %d/%d: %s\n", i+1, len(layers), digest)

		// 下载层
		layerFile, err := downloadLayer(client, registry, repository, digest, auth, tempDir, cacheDir, mirrors)
		if err != nil {
			return nil, err
		}

		layerFiles = append(layerFiles, layerFile)
	}

	return layerFiles, nil
}

// downloadLayer 下载单个镜像层
func downloadLayer(client *http.Client, registry, repository, digest, auth, tempDir, cacheDir string, mirrors []string) (string, error) {
	operation := func(registry string) (interface{}, error) {
		url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, digest)

		// 如果提供了缓存目录，首先检查缓存
		if cacheDir != "" {
			if cachedFile, exists := checkLayerCache(cacheDir, digest); exists {
				// 将缓存文件复制到临时目录
				tempFile := filepath.Join(tempDir, strings.Replace(digest, ":", "_", 1))
				if err := copyFile(cachedFile, tempFile); err != nil {
					fmt.Printf("警告: 无法从缓存复制文件: %v，将重新下载\n", err)
				} else {
					return tempFile, nil
				}
			}
		}

		layerFile := filepath.Join(tempDir, strings.Replace(digest, ":", "_", 1))
		tempFile := layerFile + ".downloading"

		// 尝试加载之前的下载状态
		state, err := loadDownloadState(tempDir, digest)
		if err != nil {
			return "", fmt.Errorf("加载下载状态失败: %v", err)
		}

		var startOffset int64
		var partialHash = sha256.New()

		// 检查是否存在未完成的下载
		if state != nil && verifyPartialDownload(tempFile, state) {
			startOffset = state.Downloaded
			fmt.Printf("发现未完成的下载，从 %.2f MB 处继续\n", float64(startOffset)/(1024*1024))
		} else {
			startOffset = 0
		}

		// 创建请求
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", err
		}

		// 添加认证头
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}

		// 如果有起始偏移，添加Range头
		if startOffset > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", startOffset))
		}

		// 发送请求
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		// 检查响应状态
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			return "", fmt.Errorf("下载层失败，状态码: %d", resp.StatusCode)
		}

		// 获取文件总大小
		var totalSize int64
		if resp.StatusCode == http.StatusPartialContent {
			totalSize = resp.ContentLength + startOffset
		} else {
			totalSize = resp.ContentLength
		}

		// 创建或打开文件
		file, err := func() (*os.File, error) {
			if startOffset > 0 {
				return os.OpenFile(tempFile, os.O_APPEND|os.O_WRONLY, 0644)
			}
			return os.Create(tempFile)
		}()
		if err != nil {
			return "", err
		}

		// 创建进度跟踪变量
		downloaded := startOffset
		startTime := time.Now()
		lastUpdateTime := startTime
		lastDownloaded := downloaded
		var currentHash string

		// 创建缓冲读取器
		buf := make([]byte, 32*1024) // 32KB 缓冲区

		// 使用匿名函数确保资源正确释放
		err = func() error {
			defer file.Close()

			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					// 写入文件
					if _, err := file.Write(buf[:n]); err != nil {
						return err
					}

					// 更新哈希
					partialHash.Write(buf[:n])
					downloaded += int64(n)

					// 每100ms更新一次进度显示
					now := time.Now()
					if now.Sub(lastUpdateTime) >= 100*time.Millisecond {
						// 计算下载速度
						elapsed := now.Sub(lastUpdateTime).Seconds()
						speed := float64(downloaded-lastDownloaded) / elapsed

						// 计算剩余时间
						var remainingTime time.Duration
						if speed > 0 {
							remaining := float64(totalSize-downloaded) / speed
							remainingTime = time.Duration(remaining * float64(time.Second))
						}

						// 显示进度
						progress := float64(downloaded) / float64(totalSize) * 100
						fmt.Printf("\r下载进度: %.1f%% | %.2f MB/%.2f MB | %.2f MB/s | 剩余时间: %v",
							progress,
							float64(downloaded)/(1024*1024),
							float64(totalSize)/(1024*1024),
							speed/(1024*1024),
							remainingTime.Round(time.Second))

						// 更新下载状态
						currentHash = fmt.Sprintf("%x", partialHash.Sum(nil))
						state = &DownloadState{
							LayerDigest:  digest,
							Downloaded:   downloaded,
							TotalSize:    totalSize,
							LastModified: now,
							PartialHash:  currentHash,
						}
						if err := saveDownloadState(*state, tempDir); err != nil {
							fmt.Printf("\n警告: 保存下载状态失败: %v\n", err)
						}

						lastUpdateTime = now
						lastDownloaded = downloaded
					}
				}

				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
			}

			// 确保所有数据都写入磁盘
			return file.Sync()
		}()

		if err != nil {
			return "", err
		}

		// 完成下载，清除进度显示并换行
		fmt.Println()

		// 重命名临时文件
		if err := os.Rename(tempFile, layerFile); err != nil {
			// 如果重命名失败，尝试复制
			if err := copyFile(tempFile, layerFile); err != nil {
				return "", fmt.Errorf("移动文件失败: %v", err)
			}
			os.Remove(tempFile)
		}

		// 如果提供了缓存目录，将文件复制到缓存
		if cacheDir != "" {
			cacheFile := filepath.Join(cacheDir, strings.Replace(digest, ":", "_", 1))
			if err := copyFile(layerFile, cacheFile); err != nil {
				fmt.Printf("警告: 无法将文件复制到缓存: %v\n", err)
			}
		}

		// 清理状态文件
		stateFile := getStateFilePath(tempDir, digest)
		os.Remove(stateFile)

		return layerFile, nil
	}

	// 创建包含镜像加速器配置的 Config
	config := Config{
		Registry: registry,
		Mirrors:  []string{}, // 默认不使用加速器
	}
	// ignoreRegistry := []string{"ghcr.io", "k8s.gcr.io", "registry.k8s.io", "quay.io", "mcr.microsoft.com", "docker.elastic.co", "nvcr.io", "gcr.io"}

	// 只有当使用 Docker Hub 时才使用加速器
	if registry == "registry-1.docker.io" {
		config.Mirrors = mirrors
	}

	result, err := tryRegistries(config, repository, operation)
	if err != nil {
		return "", err
	}

	return result.(string), nil
}

// 创建tar文件
func createTarFile(outputPath string, manifest map[string]interface{}, layerFiles []string, repository, tag string) error {
	// 创建临时目录用于存储压缩后的层文件
	tempDir, err := os.MkdirTemp("", "docker-layers-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建输出文件
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outputFile.Close()

	// 创建tar写入器
	tw := tar.NewWriter(outputFile)
	defer tw.Close()

	// 处理每个层文件
	layerIDs := make([]string, len(layerFiles))
	diffIDs := make([]string, len(layerFiles))
	for i, layerFile := range layerFiles {
		// 生成层ID
		layerID := fmt.Sprintf("layer_%x", sha256.Sum256([]byte(fmt.Sprintf("%s_%d", layerFile, i))))[:32]
		layerIDs[i] = layerID

		// 检查源文件是否存在且有效
		if _, err := os.Stat(layerFile); err != nil {
			return fmt.Errorf("层文件无效: %v", err)
		}

		// 添加层文件
		layerTarPath := filepath.Join(layerID, "layer.tar")
		if err := addFileToTar(tw, layerFile, layerTarPath); err != nil {
			return fmt.Errorf("添加层文件失败: %v", err)
		}

		// 计算diffID
		diffID, err := calculateDiffID(layerFile)
		if err != nil {
			return fmt.Errorf("计算diffID失败: %v", err)
		}
		diffIDs[i] = diffID

		// 添加VERSION文件
		if err := addVersionFile(tw, layerID); err != nil {
			return fmt.Errorf("添加VERSION文件失败: %v", err)
		}

		// 添加json文件
		if err := addLayerJSON(tw, layerID); err != nil {
			return fmt.Errorf("添加json文件失败: %v", err)
		}
	}

	// 获取镜像配置
	config, err := getImageConfig(manifest)
	if err != nil {
		return fmt.Errorf("获取镜像配置失败: %v", err)
	}

	// 添加rootfs信息
	config["rootfs"] = map[string]interface{}{
		"type":     "layers",
		"diff_ids": diffIDs,
	}

	// 生成镜像ID
	imageID := generateImageID(config)

	// 添加镜像配置文件
	if err := addImageConfig(tw, imageID, config, layerIDs); err != nil {
		return fmt.Errorf("添加镜像配置失败: %v", err)
	}

	// 添加manifest.json
	if err := addManifestJSON(tw, repository, tag, imageID, layerIDs); err != nil {
		return fmt.Errorf("添加manifest.json失败: %v", err)
	}

	// 添加repositories文件
	if err := addRepositoriesJSON(tw, repository, tag, imageID); err != nil {
		return fmt.Errorf("添加repositories文件失败: %v", err)
	}

	// 确保所有数据都写入
	if err := tw.Close(); err != nil {
		return fmt.Errorf("关闭tar文件失败: %v", err)
	}

	return nil
}

// 获取镜像配置
func getImageConfig(manifest map[string]interface{}) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"architecture": "amd64",
		"os":           "linux",
		"config":       manifest["config"],
		"created":      time.Now().UTC().Format(time.RFC3339Nano),
		"history":      []interface{}{},
	}
	return config, nil
}

// 生成镜像ID
func generateImageID(config map[string]interface{}) string {
	content, err := json.Marshal(config)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(content)
	return fmt.Sprintf("%x", hash)
}

// 添加文件到tar
func addFileToTar(tw *tar.Writer, filePath, tarPath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %v", err)
	}

	// 统一使用 / 作为路径分隔符
	tarPath = filepath.ToSlash(tarPath)

	// 确保路径不以 / 开头
	tarPath = strings.TrimPrefix(tarPath, "/")

	header := &tar.Header{
		Name:     tarPath,
		Size:     info.Size(),
		Mode:     0644,
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
		Uid:      0,
		Gid:      0,
		Uname:    "root",
		Gname:    "root",
		Format:   tar.FormatGNU, // 使用GNU格式
	}

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("写入tar头部失败: %v", err)
	}

	// 使用缓冲读取
	buf := make([]byte, 1024*1024) // 1MB buffer
	written := int64(0)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			nw, err := tw.Write(buf[:n])
			if err != nil {
				return fmt.Errorf("写入tar内容失败: %v", err)
			}
			if nw != n {
				return fmt.Errorf("写入不完整: 期望 %d 字节, 实际写入 %d 字节", n, nw)
			}
			written += int64(nw)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %v", err)
		}
	}

	// 验证写入的大小
	if written != info.Size() {
		return fmt.Errorf("文件大小不匹配: 期望 %d 字节, 实际写入 %d 字节", info.Size(), written)
	}

	return nil
}

// 添加层版本文件
func addVersionFile(tw *tar.Writer, layerID string) error {
	content := []byte("1.0")
	header := &tar.Header{
		Name: layerID + "/VERSION",
		Size: int64(len(content)),
		Mode: 0644,
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err := tw.Write(content)
	return err
}

// 添加层json文件
func addLayerJSON(tw *tar.Writer, layerID string) error {
	content := []byte(`{
		"id": "` + layerID + `",
		"parent": "",
		"created": "1970-01-01T00:00:00Z",
		"container_config": {
			"Hostname": "",
			"Domainname": "",
			"User": "",
			"AttachStdin": false,
			"AttachStdout": false,
			"AttachStderr": false,
			"Tty": false,
			"OpenStdin": false,
			"StdinOnce": false,
			"Env": null,
			"Cmd": null,
			"Image": "",
			"Volumes": null,
			"WorkingDir": "",
			"Entrypoint": null,
			"OnBuild": null,
			"Labels": null
		},
		"os": "linux"
	}`)

	header := &tar.Header{
		Name: layerID + "/json",
		Size: int64(len(content)),
		Mode: 0644,
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err := tw.Write(content)
	return err
}

// 添加manifest.json文件
func addManifestJSON(tw *tar.Writer, repository, tag, imageID string, layerIDs []string) error {
	layers := make([]string, len(layerIDs))
	for i, id := range layerIDs {
		layers[i] = id + "/layer.tar"
	}

	manifest := []map[string]interface{}{
		{
			"Config":   imageID + ".json",
			"RepoTags": []string{repository + ":" + tag},
			"Layers":   layers,
		},
	}

	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name: "manifest.json",
		Size: int64(len(content)),
		Mode: 0644,
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = tw.Write(content)
	return err
}

// 添加repositories文件
func addRepositoriesJSON(tw *tar.Writer, repository, tag, imageID string) error {
	repositories := map[string]map[string]string{
		repository: {
			tag: imageID,
		},
	}

	content, err := json.MarshalIndent(repositories, "", "  ")
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name: "repositories",
		Size: int64(len(content)),
		Mode: 0644,
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = tw.Write(content)
	return err
}

// 添加镜像配置文件
func addImageConfig(tw *tar.Writer, imageID string, config map[string]interface{}, layerIDs []string) error {
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name: imageID + ".json",
		Size: int64(len(content)),
		Mode: 0644,
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = tw.Write(content)
	return err
}

// 获取下载状态文件路径
func getStateFilePath(tempDir, digest string) string {
	return filepath.Join(tempDir, strings.Replace(digest, ":", "_", 1)+".state")
}

// 保存下载状态
func saveDownloadState(state DownloadState, tempDir string) error {
	stateFile := getStateFilePath(tempDir, state.LayerDigest)
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile, data, 0644)
}

// 读取下载状态
func loadDownloadState(tempDir, digest string) (*DownloadState, error) {
	stateFile := getStateFilePath(tempDir, digest)
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var state DownloadState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// 验证部分下载的文件
func verifyPartialDownload(filePath string, state *DownloadState) bool {
	if state == nil {
		return false
	}

	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	hash := sha256.New()
	n, err := io.Copy(hash, file)
	if err != nil || n != state.Downloaded {
		return false
	}

	return fmt.Sprintf("%x", hash.Sum(nil)) == state.PartialHash
}

// 获取缓存目录
func getCacheDir(config Config) (string, error) {
	if config.CacheDir != "" {
		return config.CacheDir, nil
	}

	// 默认缓存目录
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(homeDir, ".docker-pull", "cache")

	// 创建缓存目录（如果不存在）
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", err
	}

	return cacheDir, nil
}

// 检查缓存中是否存在层文件
func checkLayerCache(cacheDir, digest string) (string, bool) {
	cachedFile := filepath.Join(cacheDir, strings.Replace(digest, ":", "_", 1))
	if _, err := os.Stat(cachedFile); err == nil {
		return cachedFile, true
	}
	return cachedFile, false
}

// 复制文件
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	// 确保写入磁盘
	err = destFile.Sync()
	if err != nil {
		return err
	}

	// 复制文件权限
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, sourceInfo.Mode())
}

// 将层文件移动到缓存
func moveToCache(tempFile, cacheFile string) error {
	// 确保缓存目录存在
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0755); err != nil {
		return err
	}

	// 如果目标文件已存在，先删除
	if _, err := os.Stat(cacheFile); err == nil {
		if err := os.Remove(cacheFile); err != nil {
			return err
		}
	}

	// 先复制文件
	if err := copyFile(tempFile, cacheFile); err != nil {
		return err
	}

	// 复制成功后删除源文件
	return os.Remove(tempFile)
}

// 压缩文件并计算 diff ID
func compressFileAndCalculateDiffID(srcPath, dstPath string) (string, error) {
	// 打开源文件
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("打开源文件失败: %v", err)
	}
	defer srcFile.Close()

	// 检查文件大小
	info, err := srcFile.Stat()
	if err != nil {
		return "", fmt.Errorf("获取文件信息失败: %v", err)
	}
	if info.Size() == 0 {
		return "", fmt.Errorf("源文件大小为0")
	}

	// 创建目标文件
	dstFile, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("创建目标文件失败: %v", err)
	}
	defer dstFile.Close()

	// 创建 gzip writer
	gw := gzip.NewWriter(dstFile)
	defer gw.Close()

	// 设置 gzip 头部信息
	gw.Header = gzip.Header{
		Name:    filepath.Base(srcPath),
		ModTime: time.Now(),
		OS:      255, // 255 表示未知操作系统
	}

	// 创建一个 tee reader 来同时计算 hash
	hash := sha256.New()
	teeReader := io.TeeReader(srcFile, hash)

	// 使用缓冲写入
	buf := make([]byte, 1024*1024) // 1MB buffer
	for {
		n, err := teeReader.Read(buf)
		if n > 0 {
			if _, err := gw.Write(buf[:n]); err != nil {
				return "", fmt.Errorf("写入压缩数据失败: %v", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("读取源文件失败: %v", err)
		}
	}

	// 确保所有数据都写入
	if err := gw.Close(); err != nil {
		return "", fmt.Errorf("关闭gzip writer失败: %v", err)
	}
	if err := dstFile.Sync(); err != nil {
		return "", fmt.Errorf("同步文件到磁盘失败: %v", err)
	}

	// 验证生成的文件
	if fi, err := dstFile.Stat(); err != nil || fi.Size() == 0 {
		return "", fmt.Errorf("生成的压缩文件无效")
	}

	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

// 计算解压缩后内容的哈希值
func calculateUncompressedHash(gzipFile string) (string, error) {
	file, err := os.Open(gzipFile)
	if err != nil {
		return "", fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	// 创建gzip reader
	gr, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("创建gzip reader失败: %v", err)
	}
	defer gr.Close()

	// 计算解压缩后内容的哈希值
	hash := sha256.New()
	buf := make([]byte, 1024*1024) // 1MB buffer
	for {
		n, err := gr.Read(buf)
		if n > 0 {
			if _, err := hash.Write(buf[:n]); err != nil {
				return "", fmt.Errorf("计算哈希失败: %v", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("读取解压缩数据失败: %v", err)
		}
	}

	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

// 计算文件的 diff ID
func calculateDiffID(filePath string) (string, error) {
	// 检查文件是否为gzip格式
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	// 读取前几个字节来检查gzip魔数
	header := make([]byte, 2)
	if _, err := file.Read(header); err != nil {
		return "", fmt.Errorf("读取文件头失败: %v", err)
	}

	// 如果是gzip文件（魔数为1f 8b）
	if header[0] == 0x1f && header[1] == 0x8b {
		return calculateUncompressedHash(filePath)
	}

	// 如果不是gzip文件，计算原始内容的哈希值
	if _, err := file.Seek(0, 0); err != nil {
		return "", fmt.Errorf("重置文件指针失败: %v", err)
	}

	hash := sha256.New()
	buf := make([]byte, 1024*1024) // 1MB buffer
	for {
		n, err := file.Read(buf)
		if n > 0 {
			if _, err := hash.Write(buf[:n]); err != nil {
				return "", fmt.Errorf("计算哈希失败: %v", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("读取文件失败: %v", err)
		}
	}

	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}
