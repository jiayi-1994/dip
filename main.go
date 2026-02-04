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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 版本信息
const version = "0.2.0"

// 默认配置常量
const (
	defaultRegistry     = "registry-1.docker.io"
	defaultArch         = "amd64"
	defaultTimeout      = 5 * time.Minute
	defaultRetryCount   = 3
	defaultRetryDelay   = 2 * time.Second
	defaultConcurrency  = 3
	defaultMirrors      = "docker.gh-proxy.com,docker.1ms.run,docker.xjyi.me"
)

// Config 配置选项
type Config struct {
	Image       string
	Output      string
	Registry    string
	Username    string
	Password    string
	Insecure    bool
	ShowVersion bool
	Arch        string
	CacheDir    string
	Mirrors     []string
	Concurrency int
	RetryCount  int
	Timeout     time.Duration
}

// RegistryError 表示镜像仓库操作错误
type RegistryError struct {
	Registry string
	Op       string
	Err      error
}

func (e *RegistryError) Error() string {
	return fmt.Sprintf("仓库 %s: %s 操作失败: %v", e.Registry, e.Op, e.Err)
}

// DownloadState 保存下载状态
type DownloadState struct {
	LayerDigest  string    `json:"layer_digest"`
	Downloaded   int64     `json:"downloaded"`
	TotalSize    int64     `json:"total_size"`
	LastModified time.Time `json:"last_modified"`
	PartialHash  string    `json:"partial_hash"`
}

// LayerDownloadResult 层下载结果
type LayerDownloadResult struct {
	Index    int
	FilePath string
	Digest   string
	Error    error
}

// ProgressTracker 进度追踪器
type ProgressTracker struct {
	totalLayers     int
	completedLayers int32
	totalBytes      int64
	downloadedBytes int64
	mu              sync.Mutex
	startTime       time.Time
}

func NewProgressTracker(totalLayers int) *ProgressTracker {
	return &ProgressTracker{
		totalLayers: totalLayers,
		startTime:   time.Now(),
	}
}

func (p *ProgressTracker) AddTotalBytes(bytes int64) {
	atomic.AddInt64(&p.totalBytes, bytes)
}

func (p *ProgressTracker) AddDownloadedBytes(bytes int64) {
	atomic.AddInt64(&p.downloadedBytes, bytes)
}

func (p *ProgressTracker) CompleteLayer() {
	atomic.AddInt32(&p.completedLayers, 1)
}

func (p *ProgressTracker) GetProgress() (completed int, total int, downloadedMB, totalMB, speedMBps float64) {
	completed = int(atomic.LoadInt32(&p.completedLayers))
	total = p.totalLayers
	downloaded := atomic.LoadInt64(&p.downloadedBytes)
	totalB := atomic.LoadInt64(&p.totalBytes)
	downloadedMB = float64(downloaded) / (1024 * 1024)
	totalMB = float64(totalB) / (1024 * 1024)
	elapsed := time.Since(p.startTime).Seconds()
	if elapsed > 0 {
		speedMBps = downloadedMB / elapsed
	}
	return
}

// 主函数
func main() {
	config := parseFlags()

	if config.ShowVersion {
		fmt.Printf("dip (docker image pull) 版本 %s\n", version)
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
	fmt.Println("========================================")
	fmt.Printf("镜像: %s:%s\n", repository, tag)
	fmt.Printf("架构: %s\n", config.Arch)
	fmt.Printf("仓库: %s\n", registry)
	fmt.Printf("并发数: %d\n", config.Concurrency)
	fmt.Printf("重试次数: %d\n", config.RetryCount)
	if len(config.Mirrors) > 0 {
		fmt.Printf("镜像加速器: %s\n", strings.Join(config.Mirrors, ", "))
	}
	fmt.Println("========================================")

	// 创建HTTP客户端
	client := createHTTPClient(config)

	// 获取认证信息
	auth := getAuthToken(client, registry, repository, config.Username, config.Password)

	// 获取镜像清单
	fmt.Println("正在获取镜像清单...")
	manifest, err := getManifestWithRetry(client, registry, repository, tag, auth, config)
	if err != nil {
		fmt.Printf("错误: 获取镜像清单失败: %v\n", err)
		os.Exit(1)
	}

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "docker-pull-*")
	if err != nil {
		fmt.Printf("错误: 创建临时目录失败: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	// 下载镜像层（支持并发）
	layers, err := downloadLayersConcurrent(client, registry, repository, manifest, auth, tempDir, config)
	if err != nil {
		fmt.Printf("错误: 下载镜像层失败: %v\n", err)
		os.Exit(1)
	}

	// 生成输出文件名
	outputFile := config.Output
	if outputFile == "" {
		outputFile = fmt.Sprintf("%s-%s-%s.tar", strings.ReplaceAll(repository, "/", "_"), tag, config.Arch)
	}

	// 创建tar文件
	fmt.Println("正在创建镜像文件...")
	err = createTarFile(outputFile, manifest, layers, repository, tag, config.Arch)
	if err != nil {
		fmt.Printf("错误: 创建tar文件失败: %v\n", err)
		os.Exit(1)
	}

	// 验证生成的文件
	if fileInfo, err := os.Stat(outputFile); err == nil {
		fmt.Println("========================================")
		fmt.Printf("✓ 镜像已成功保存到: %s\n", outputFile)
		fmt.Printf("✓ 文件大小: %.2f MB\n", float64(fileInfo.Size())/(1024*1024))
		fmt.Println("========================================")
	}
}

// 解析命令行参数
func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.Image, "i", "", "Docker镜像名称 (格式: [registry/]repository[:tag])")
	flag.StringVar(&config.Output, "o", "", "输出文件路径 (默认: repository-tag-arch.tar)")
	flag.StringVar(&config.Registry, "r", defaultRegistry, "Docker Registry地址")
	flag.StringVar(&config.Username, "u", "", "Registry用户名")
	flag.StringVar(&config.Password, "p", "", "Registry密码")
	flag.StringVar(&config.Arch, "a", defaultArch, "镜像架构 (例如: amd64, arm64)")
	flag.StringVar(&config.CacheDir, "cache-dir", "", "层缓存目录 (默认: ~/.docker-pull/cache)")
	flag.BoolVar(&config.Insecure, "k", false, "允许不安全的HTTPS连接")
	flag.BoolVar(&config.ShowVersion, "version", false, "显示版本信息")
	flag.IntVar(&config.Concurrency, "c", defaultConcurrency, "并发下载数")
	flag.IntVar(&config.RetryCount, "retry", defaultRetryCount, "下载失败重试次数")

	var mirrors string
	var timeout int
	flag.StringVar(&mirrors, "m", defaultMirrors, "镜像加速器地址列表，多个地址用逗号分隔")
	flag.IntVar(&timeout, "timeout", int(defaultTimeout.Seconds()), "下载超时时间（秒）")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "dip - Docker镜像拉取工具 v%s\n\n", version)
		fmt.Fprintf(os.Stderr, "用法: dip [选项]\n\n")
		fmt.Fprintf(os.Stderr, "选项:\n")
		fmt.Fprintf(os.Stderr, "  -i string     Docker镜像名称 (格式: [registry/]repository[:tag])\n")
		fmt.Fprintf(os.Stderr, "  -o string     输出文件路径 (默认: repository-tag-arch.tar)\n")
		fmt.Fprintf(os.Stderr, "  -r string     Docker Registry地址 (默认: %s)\n", defaultRegistry)
		fmt.Fprintf(os.Stderr, "  -u string     Registry用户名\n")
		fmt.Fprintf(os.Stderr, "  -p string     Registry密码\n")
		fmt.Fprintf(os.Stderr, "  -a string     镜像架构 (默认: %s)\n", defaultArch)
		fmt.Fprintf(os.Stderr, "  -c int        并发下载数 (默认: %d)\n", defaultConcurrency)
		fmt.Fprintf(os.Stderr, "  -m string     镜像加速器地址列表，逗号分隔\n")
		fmt.Fprintf(os.Stderr, "  -k            允许不安全的HTTPS连接\n")
		fmt.Fprintf(os.Stderr, "  --retry int   下载失败重试次数 (默认: %d)\n", defaultRetryCount)
		fmt.Fprintf(os.Stderr, "  --timeout int 下载超时时间/秒 (默认: %d)\n", int(defaultTimeout.Seconds()))
		fmt.Fprintf(os.Stderr, "  --cache-dir   层缓存目录\n")
		fmt.Fprintf(os.Stderr, "  --version     显示版本信息\n")
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  dip -i nginx:latest\n")
		fmt.Fprintf(os.Stderr, "  dip -i nginx:latest -a arm64\n")
		fmt.Fprintf(os.Stderr, "  dip -i nginx:latest -o nginx.tar -c 5\n")
	}

	flag.Parse()

	config.Timeout = time.Duration(timeout) * time.Second

	// 处理镜像加速器配置
	if mirrors != "" {
		config.Mirrors = strings.Split(mirrors, ",")
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

	// 验证并发数
	if config.Concurrency < 1 {
		config.Concurrency = 1
	} else if config.Concurrency > 10 {
		config.Concurrency = 10
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
func createHTTPClient(config Config) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Insecure,
		},
		DisableCompression:    false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   config.Timeout,
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

// tryRegistries 尝试从多个仓库获取数据
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
			isMirror := contains(config.Mirrors, registry)
			if isMirror {
				fmt.Printf("✓ 使用镜像加速器: %s\n", registry)
			} else {
				fmt.Printf("✓ 使用原始仓库: %s\n", registry)
			}
			return result, nil
		}
		lastErr = &RegistryError{
			Registry: registry,
			Op:       "获取数据",
			Err:      err,
		}
		fmt.Printf("⚠ 从 %s 获取失败: %v\n", registry, err)
	}

	return nil, fmt.Errorf("所有镜像仓库都失败: %v", lastErr)
}

// withRetry 执行带重试的操作
func withRetry(retryCount int, delay time.Duration, operation func() error) error {
	var lastErr error
	for i := 0; i <= retryCount; i++ {
		if i > 0 {
			fmt.Printf("  重试 %d/%d...\n", i, retryCount)
			time.Sleep(delay)
		}
		lastErr = operation()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

// getManifestWithRetry 获取镜像清单（带重试）
func getManifestWithRetry(client *http.Client, registry, repository, tag, auth string, config Config) (map[string]interface{}, error) {
	var manifest map[string]interface{}
	var err error

	retryErr := withRetry(config.RetryCount, defaultRetryDelay, func() error {
		manifest, err = getManifest(client, registry, repository, tag, auth, config.Arch, config.Mirrors)
		return err
	})

	if retryErr != nil {
		return nil, retryErr
	}
	return manifest, nil
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
	if contains(ignoreRegistry, registry) {
		config.Mirrors = mirrors
	}

	result, err := tryRegistries(config, repository, operation)
	if err != nil {
		return nil, err
	}

	return result.(map[string]interface{}), nil
}

func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

// extractLayersFromManifest 从manifest中提取层信息
func extractLayersFromManifest(manifest map[string]interface{}) ([]map[string]interface{}, error) {
	var rawLayers []interface{}

	if schemaVersion, ok := manifest["schemaVersion"].(float64); ok {
		if schemaVersion == 1 {
			if fsLayers, ok := manifest["fsLayers"].([]interface{}); ok {
				rawLayers = make([]interface{}, len(fsLayers))
				for i, layer := range fsLayers {
					if blobSum, ok := layer.(map[string]interface{})["blobSum"].(string); ok {
						rawLayers[i] = map[string]interface{}{"digest": blobSum}
					}
				}
			}
		} else {
			if l, ok := manifest["layers"].([]interface{}); ok {
				rawLayers = l
			}
		}
	}

	if rawLayers == nil {
		return nil, fmt.Errorf("无效的manifest格式或未找到层信息")
	}

	layers := make([]map[string]interface{}, 0, len(rawLayers))
	for _, layer := range rawLayers {
		if layerInfo, ok := layer.(map[string]interface{}); ok {
			layers = append(layers, layerInfo)
		}
	}

	return layers, nil
}

// downloadLayersConcurrent 并发下载镜像层
func downloadLayersConcurrent(client *http.Client, registry, repository string, manifest map[string]interface{}, auth, tempDir string, config Config) ([]string, error) {
	layers, err := extractLayersFromManifest(manifest)
	if err != nil {
		return nil, err
	}

	cacheDir, err := getCacheDir(config)
	if err != nil {
		fmt.Printf("⚠ 无法获取缓存目录: %v，将不使用缓存\n", err)
		cacheDir = ""
	}

	totalLayers := len(layers)
	fmt.Printf("发现 %d 个镜像层，使用 %d 个并发下载\n", totalLayers, config.Concurrency)

	// 创建结果通道和信号量
	results := make(chan LayerDownloadResult, totalLayers)
	semaphore := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	// 进度追踪器
	tracker := NewProgressTracker(totalLayers)

	// 启动进度显示协程
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				completed, total, downloadedMB, totalMB, speed := tracker.GetProgress()
				if totalMB > 0 {
					fmt.Printf("\r进度: [%d/%d层] %.1f MB / %.1f MB (%.2f MB/s)   ",
						completed, total, downloadedMB, totalMB, speed)
				}
			case <-done:
				return
			}
		}
	}()

	// 并发下载
	for i, layer := range layers {
		digest, ok := layer["digest"].(string)
		if !ok {
			close(done)
			return nil, fmt.Errorf("层 %d: 无效的摘要格式", i+1)
		}

		// 获取层大小用于进度显示
		if size, ok := layer["size"].(float64); ok {
			tracker.AddTotalBytes(int64(size))
		}

		wg.Add(1)
		go func(index int, layerDigest string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var filePath string
			var downloadErr error

			// 检查缓存
			if cacheDir != "" {
				if cachedFile, exists := checkLayerCache(cacheDir, layerDigest); exists {
					fmt.Printf("\n✓ 层 %d/%d: 从缓存获取\n", index+1, totalLayers)
					tracker.CompleteLayer()
					results <- LayerDownloadResult{
						Index:    index,
						FilePath: cachedFile,
						Digest:   layerDigest,
					}
					return
				}
			}

			// 带重试的下载
			downloadErr = withRetry(config.RetryCount, defaultRetryDelay, func() error {
				var err error
				filePath, err = downloadLayerWithProgress(client, registry, repository, layerDigest, auth, tempDir, cacheDir, config.Mirrors, tracker)
				return err
			})

			tracker.CompleteLayer()

			if downloadErr != nil {
				results <- LayerDownloadResult{
					Index:  index,
					Error:  downloadErr,
					Digest: layerDigest,
				}
				return
			}

			// 验证下载的层
			if err := verifyLayerDigest(filePath, layerDigest); err != nil {
				results <- LayerDownloadResult{
					Index:  index,
					Error:  fmt.Errorf("层验证失败: %v", err),
					Digest: layerDigest,
				}
				return
			}

			results <- LayerDownloadResult{
				Index:    index,
				FilePath: filePath,
				Digest:   layerDigest,
			}
		}(i, digest)
	}

	// 等待所有下载完成
	go func() {
		wg.Wait()
		close(results)
		close(done)
	}()

	// 收集结果
	layerResults := make([]LayerDownloadResult, totalLayers)
	for result := range results {
		if result.Error != nil {
			return nil, fmt.Errorf("层 %d 下载失败: %v", result.Index+1, result.Error)
		}
		layerResults[result.Index] = result
	}

	// 按顺序整理文件路径
	layerFiles := make([]string, totalLayers)
	for _, result := range layerResults {
		layerFiles[result.Index] = result.FilePath
	}

	fmt.Printf("\n✓ 所有 %d 个层下载完成\n", totalLayers)
	return layerFiles, nil
}

// verifyLayerDigest 验证层文件的摘要
func verifyLayerDigest(filePath, expectedDigest string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("计算哈希失败: %v", err)
	}

	actualDigest := fmt.Sprintf("sha256:%x", hash.Sum(nil))
	if actualDigest != expectedDigest {
		return fmt.Errorf("摘要不匹配: 期望 %s, 实际 %s", expectedDigest, actualDigest)
	}

	return nil
}

// downloadLayerWithProgress 下载单个层（带进度追踪）
func downloadLayerWithProgress(client *http.Client, registry, repository, digest, auth, tempDir, cacheDir string, mirrors []string, tracker *ProgressTracker) (string, error) {
	operation := func(reg string) (interface{}, error) {
		url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", reg, repository, digest)

		layerFile := filepath.Join(tempDir, strings.Replace(digest, ":", "_", 1))
		tempFile := layerFile + ".downloading"

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", err
		}

		if auth != "" {
			req.Header.Set("Authorization", auth)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			return "", fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
		}

		file, err := os.Create(tempFile)
		if err != nil {
			return "", err
		}

		buf := make([]byte, 64*1024)
		err = func() error {
			defer file.Close()
			for {
				n, readErr := resp.Body.Read(buf)
				if n > 0 {
					if _, writeErr := file.Write(buf[:n]); writeErr != nil {
						return writeErr
					}
					tracker.AddDownloadedBytes(int64(n))
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					return readErr
				}
			}
			return file.Sync()
		}()

		if err != nil {
			os.Remove(tempFile)
			return "", err
		}

		if err := os.Rename(tempFile, layerFile); err != nil {
			if copyErr := copyFile(tempFile, layerFile); copyErr != nil {
				return "", fmt.Errorf("移动文件失败: %v", copyErr)
			}
			os.Remove(tempFile)
		}

		// 缓存文件
		if cacheDir != "" {
			cacheFile := filepath.Join(cacheDir, strings.Replace(digest, ":", "_", 1))
			if err := copyFile(layerFile, cacheFile); err != nil {
				// 缓存失败不影响主流程
			}
		}

		return layerFile, nil
	}

	cfg := Config{
		Registry: registry,
		Mirrors:  []string{},
	}

	if registry == defaultRegistry {
		cfg.Mirrors = mirrors
	}

	result, err := tryRegistries(cfg, repository, operation)
	if err != nil {
		return "", err
	}

	return result.(string), nil
}

// 创建tar文件
func createTarFile(outputPath string, manifest map[string]interface{}, layerFiles []string, repository, tag, arch string) error {
	tempDir, err := os.MkdirTemp("", "docker-layers-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outputFile.Close()

	tw := tar.NewWriter(outputFile)
	defer tw.Close()

	layerIDs := make([]string, len(layerFiles))
	diffIDs := make([]string, len(layerFiles))

	for i, layerFile := range layerFiles {
		layerID := fmt.Sprintf("layer_%x", sha256.Sum256([]byte(fmt.Sprintf("%s_%d", layerFile, i))))[:32]
		layerIDs[i] = layerID

		if _, err := os.Stat(layerFile); err != nil {
			return fmt.Errorf("层文件无效: %v", err)
		}

		layerTarPath := filepath.Join(layerID, "layer.tar")
		if err := addFileToTar(tw, layerFile, layerTarPath); err != nil {
			return fmt.Errorf("添加层文件失败: %v", err)
		}

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
	config, err := getImageConfig(manifest, arch)
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
func getImageConfig(manifest map[string]interface{}, arch string) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"architecture": arch,
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
