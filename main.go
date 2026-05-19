package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
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
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const version = "0.3.0"

const (
	defaultRegistry    = "registry-1.docker.io"
	defaultArch        = "amd64"
	defaultTimeout     = 5 * time.Minute
	defaultRetryCount  = 3
	defaultRetryDelay  = 2 * time.Second
	defaultConcurrency = 3
	defaultMirrors     = "docker.gh-proxy.com,docker.1ms.run,docker.xjyi.me"
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

// DownloadedLayer 下载后的层文件 + 摘要
type DownloadedLayer struct {
	FilePath string
	Digest   string
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

// stdoutMu serializes concurrent stdout writes from ticker + workers.
var stdoutMu sync.Mutex

func safePrintf(format string, a ...any) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	fmt.Printf(format, a...)
}

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	registry, repository, tag := parseImageName(config.Image, config.Registry)

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

	client := createHTTPClient(config)

	auth := getAuthToken(ctx, client, registry, repository, config.Username, config.Password)

	fmt.Println("正在获取镜像清单...")
	manifest, err := getManifestWithRetry(ctx, client, registry, repository, tag, auth, config)
	if err != nil {
		fmt.Printf("错误: 获取镜像清单失败: %v\n", err)
		os.Exit(1)
	}

	tempDir, err := os.MkdirTemp("", "docker-pull-*")
	if err != nil {
		fmt.Printf("错误: 创建临时目录失败: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	var imageConfig map[string]any
	if configInfo, ok := manifest["config"].(map[string]any); ok {
		if configDigest, ok := configInfo["digest"].(string); ok {
			fmt.Println("正在获取镜像配置...")
			imageConfig, err = getImageConfigBlob(ctx, client, registry, repository, configDigest, auth, config.Mirrors)
			if err != nil {
				fmt.Printf("警告: 获取镜像配置失败: %v，将使用默认配置\n", err)
			}
		}
	}

	layers, err := downloadLayersConcurrent(ctx, client, registry, repository, manifest, auth, tempDir, config)
	if err != nil {
		fmt.Printf("错误: 下载镜像层失败: %v\n", err)
		os.Exit(1)
	}

	outputFile := config.Output
	if outputFile == "" {
		outputFile = fmt.Sprintf("%s-%s-%s.tar", strings.ReplaceAll(repository, "/", "_"), tag, config.Arch)
	}

	fmt.Println("正在创建镜像文件...")
	err = createTarFile(outputFile, layers, repository, tag, config.Arch, imageConfig)
	if err != nil {
		fmt.Printf("错误: 创建tar文件失败: %v\n", err)
		os.Exit(1)
	}

	if fileInfo, err := os.Stat(outputFile); err == nil {
		fmt.Println("========================================")
		fmt.Printf("✓ 镜像已成功保存到: %s\n", outputFile)
		fmt.Printf("✓ 文件大小: %.2f MB\n", float64(fileInfo.Size())/(1024*1024))
		fmt.Println("========================================")
	}
}

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

	if mirrors != "" {
		config.Mirrors = strings.Split(mirrors, ",")
		for i := range config.Mirrors {
			config.Mirrors[i] = strings.TrimSpace(config.Mirrors[i])
		}
	}

	if envMirrors := os.Getenv("DOCKER_PULL_MIRRORS"); envMirrors != "" && len(config.Mirrors) == 0 {
		config.Mirrors = strings.Split(envMirrors, ",")
		for i := range config.Mirrors {
			config.Mirrors[i] = strings.TrimSpace(config.Mirrors[i])
		}
	}

	if config.Concurrency < 1 {
		config.Concurrency = 1
	} else if config.Concurrency > 10 {
		config.Concurrency = 10
	}

	return config
}

func parseImageName(imageName, defaultRegistry string) (registry, repository, tag string) {
	tag = "latest"

	parts := strings.Split(imageName, ":")
	if len(parts) > 1 {
		if len(strings.Split(parts[1], "/")) > 1 {
			imageArr := parts[:len(parts)-1]
			imageName = strings.Join(imageArr, ":")
			tag = parts[len(parts)-1]
		} else {
			imageName = parts[0]
			tag = parts[1]
		}
	}

	parts = strings.Split(imageName, "/")
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		registry = parts[0]
		repository = strings.Join(parts[1:], "/")
	} else {
		registry = defaultRegistry
		repository = imageName
		if !strings.Contains(repository, "/") && registry == "registry-1.docker.io" {
			repository = "library/" + repository
		}
	}

	return
}

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

func getAuthToken(ctx context.Context, client *http.Client, registry, repository, username, password string) string {
	if username != "" && password != "" {
		auth := fmt.Sprintf("%s:%s", username, password)
		return "Basic " + base64Encode(auth)
	}

	authURL := fmt.Sprintf("https://%s/v2/", registry)
	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		authHeader := resp.Header.Get("Www-Authenticate")
		if strings.HasPrefix(authHeader, "Bearer ") {
			params := make(map[string]string)
			parts := strings.Split(authHeader[7:], ",")
			for _, part := range parts {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) == 2 {
					params[kv[0]] = strings.Trim(kv[1], "\"")
				}
			}

			tokenURL := fmt.Sprintf("%s?service=%s&scope=repository:%s:pull",
				params["realm"],
				params["service"],
				repository)

			tokenReq, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
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

func base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func tryRegistries(config Config, operation func(registry string) (any, error)) (any, error) {
	var lastErr error
	registries := []string{}

	if len(config.Mirrors) > 0 {
		registries = append(registries, config.Mirrors...)
	}
	registries = append(registries, config.Registry)

	for _, registry := range registries {
		result, err := operation(registry)
		if err == nil {
			isMirror := contains(config.Mirrors, registry)
			if isMirror {
				safePrintf("✓ 使用镜像加速器: %s\n", registry)
			} else {
				safePrintf("✓ 使用原始仓库: %s\n", registry)
			}
			return result, nil
		}
		lastErr = &RegistryError{
			Registry: registry,
			Op:       "获取数据",
			Err:      err,
		}
		safePrintf("⚠ 从 %s 获取失败: %v\n", registry, err)
	}

	return nil, fmt.Errorf("所有镜像仓库都失败: %v", lastErr)
}

func withRetry(ctx context.Context, retryCount int, delay time.Duration, operation func() error) error {
	var lastErr error
	for i := 0; i <= retryCount; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			safePrintf("  重试 %d/%d...\n", i, retryCount)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		lastErr = operation()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func getManifestWithRetry(ctx context.Context, client *http.Client, registry, repository, tag, auth string, config Config) (map[string]any, error) {
	var manifest map[string]any
	var err error

	retryErr := withRetry(ctx, config.RetryCount, defaultRetryDelay, func() error {
		manifest, err = getManifest(ctx, client, registry, repository, tag, auth, config.Arch, config.Mirrors)
		return err
	})

	if retryErr != nil {
		return nil, retryErr
	}
	return manifest, nil
}

func getManifest(ctx context.Context, client *http.Client, registry, repository, tag, auth string, arch string, mirrors []string) (map[string]any, error) {
	operation := func(registry string) (any, error) {
		url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, tag)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}

		if auth != "" {
			req.Header.Set("Authorization", auth)
		}

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

		var manifest map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
			return nil, err
		}

		if mediaType, ok := manifest["mediaType"].(string); ok {
			if strings.Contains(mediaType, "manifest.list") || strings.Contains(mediaType, "index.v1") {
				manifests, ok := manifest["manifests"].([]any)
				if !ok {
					return nil, fmt.Errorf("无效的manifest列表格式")
				}

				for _, m := range manifests {
					if mf, ok := m.(map[string]any); ok {
						platform, ok := mf["platform"].(map[string]any)
						if !ok {
							continue
						}

						if platform["architecture"] == arch && platform["os"] == "linux" {
							digest := mf["digest"].(string)
							return getManifest(ctx, client, registry, repository, digest, auth, arch, mirrors)
						}
					}
				}
				return nil, fmt.Errorf("未找到架构为 %s 的manifest", arch)
			}
		}

		return manifest, nil
	}

	config := Config{
		Registry: registry,
		Mirrors:  []string{},
	}

	ignoreRegistry := []string{"registry-1.docker.io", "docker.io", "ghcr.io", "k8s.gcr.io", "registry.k8s.io", "quay.io", "mcr.microsoft.com", "docker.elastic.co", "nvcr.io", "gcr.io"}

	if contains(ignoreRegistry, registry) {
		config.Mirrors = mirrors
	}

	result, err := tryRegistries(config, operation)
	if err != nil {
		return nil, err
	}

	return result.(map[string]any), nil
}

func contains(slice []string, str string) bool {
	return slices.Contains(slice, str)
}

func getImageConfigBlob(ctx context.Context, client *http.Client, registry, repository, configDigest, auth string, mirrors []string) (map[string]any, error) {
	operation := func(reg string) (any, error) {
		url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", reg, repository, configDigest)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}

		if auth != "" {
			req.Header.Set("Authorization", auth)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("获取配置失败，状态码: %d", resp.StatusCode)
		}

		var config map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
			return nil, err
		}

		return config, nil
	}

	cfg := Config{
		Registry: registry,
		Mirrors:  []string{},
	}

	if registry == defaultRegistry {
		cfg.Mirrors = mirrors
	}

	result, err := tryRegistries(cfg, operation)
	if err != nil {
		return nil, err
	}

	return result.(map[string]any), nil
}

func extractLayersFromManifest(manifest map[string]any) ([]map[string]any, error) {
	var rawLayers []any

	if schemaVersion, ok := manifest["schemaVersion"].(float64); ok {
		if schemaVersion == 1 {
			if fsLayers, ok := manifest["fsLayers"].([]any); ok {
				rawLayers = make([]any, len(fsLayers))
				for i, layer := range fsLayers {
					if blobSum, ok := layer.(map[string]any)["blobSum"].(string); ok {
						rawLayers[i] = map[string]any{"digest": blobSum}
					}
				}
			}
		} else {
			if l, ok := manifest["layers"].([]any); ok {
				rawLayers = l
			}
		}
	}

	if rawLayers == nil {
		return nil, fmt.Errorf("无效的manifest格式或未找到层信息")
	}

	layers := make([]map[string]any, 0, len(rawLayers))
	for _, layer := range rawLayers {
		if layerInfo, ok := layer.(map[string]any); ok {
			layers = append(layers, layerInfo)
		}
	}

	return layers, nil
}

type uniqueLayer struct {
	primaryIdx int
	digest     string
	size       int64
}

func downloadLayersConcurrent(ctx context.Context, client *http.Client, registry, repository string, manifest map[string]any, auth, tempDir string, config Config) ([]DownloadedLayer, error) {
	layers, err := extractLayersFromManifest(manifest)
	if err != nil {
		return nil, err
	}

	cacheDir, err := getCacheDir(config)
	if err != nil {
		safePrintf("⚠ 无法获取缓存目录: %v，将不使用缓存\n", err)
		cacheDir = ""
	}

	totalLayers := len(layers)

	digestToPrimary := make(map[string]int)
	aliases := make(map[int]int)
	digests := make([]string, totalLayers)
	uniques := []uniqueLayer{}
	for i, layer := range layers {
		digest, ok := layer["digest"].(string)
		if !ok {
			return nil, fmt.Errorf("层 %d: 无效的摘要格式", i+1)
		}
		digests[i] = digest
		if primary, exists := digestToPrimary[digest]; exists {
			aliases[i] = primary
			continue
		}
		digestToPrimary[digest] = i
		var size int64
		if s, ok := layer["size"].(float64); ok {
			size = int64(s)
		}
		uniques = append(uniques, uniqueLayer{primaryIdx: i, digest: digest, size: size})
	}

	if len(uniques) == len(layers) {
		safePrintf("发现 %d 个镜像层，使用 %d 个并发下载\n", totalLayers, config.Concurrency)
	} else {
		safePrintf("发现 %d 个镜像层 (%d 唯一)，使用 %d 个并发下载\n", totalLayers, len(uniques), config.Concurrency)
	}

	tracker := NewProgressTracker(len(uniques))
	for _, u := range uniques {
		tracker.AddTotalBytes(u.size)
	}

	dlCtx, dlCancel := context.WithCancel(ctx)
	defer dlCancel()

	results := make(chan LayerDownloadResult, len(uniques))
	semaphore := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	done := make(chan struct{})
	var doneOnce sync.Once
	closeDone := func() { doneOnce.Do(func() { close(done) }) }

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				completed, total, downloadedMB, totalMB, speed := tracker.GetProgress()
				if totalMB > 0 {
					safePrintf("\r进度: [%d/%d层] %.1f MB / %.1f MB (%.2f MB/s)   ",
						completed, total, downloadedMB, totalMB, speed)
				}
			case <-done:
				return
			}
		}
	}()

	spawnAborted := false
SpawnLoop:
	for _, u := range uniques {
		select {
		case semaphore <- struct{}{}:
		case <-dlCtx.Done():
			spawnAborted = true
			break SpawnLoop
		}

		wg.Add(1)
		go func(layer uniqueLayer) {
			defer wg.Done()
			defer func() { <-semaphore }()

			if err := dlCtx.Err(); err != nil {
				results <- LayerDownloadResult{Index: layer.primaryIdx, Digest: layer.digest, Error: err}
				return
			}

			if cacheDir != "" {
				if cachedFile, exists := checkLayerCache(cacheDir, layer.digest); exists {
					safePrintf("\n✓ 层 %d/%d: 从缓存获取\n", layer.primaryIdx+1, totalLayers)
					tracker.CompleteLayer()
					results <- LayerDownloadResult{Index: layer.primaryIdx, FilePath: cachedFile, Digest: layer.digest}
					return
				}
			}

			var filePath string
			downloadErr := withRetry(dlCtx, config.RetryCount, defaultRetryDelay, func() error {
				var e error
				filePath, e = downloadLayerWithProgress(dlCtx, client, registry, repository, layer.digest, auth, tempDir, cacheDir, config.Mirrors, tracker)
				return e
			})

			tracker.CompleteLayer()

			if downloadErr != nil {
				results <- LayerDownloadResult{Index: layer.primaryIdx, Digest: layer.digest, Error: downloadErr}
				return
			}

			if err := verifyLayerDigest(filePath, layer.digest); err != nil {
				results <- LayerDownloadResult{Index: layer.primaryIdx, Digest: layer.digest, Error: fmt.Errorf("层验证失败: %v", err)}
				return
			}

			results <- LayerDownloadResult{Index: layer.primaryIdx, FilePath: filePath, Digest: layer.digest}
		}(u)
	}

	go func() {
		wg.Wait()
		close(results)
		closeDone()
	}()

	primaryFiles := make(map[int]string)
	var firstErr error
	for result := range results {
		if result.Error != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("层 %d 下载失败: %v", result.Index+1, result.Error)
				dlCancel()
			}
			continue
		}
		primaryFiles[result.Index] = result.FilePath
	}

	closeDone()

	if firstErr != nil {
		return nil, firstErr
	}
	if spawnAborted {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("下载提前终止")
	}

	out := make([]DownloadedLayer, totalLayers)
	for i := range layers {
		primary := i
		if p, ok := aliases[i]; ok {
			primary = p
		}
		fp, ok := primaryFiles[primary]
		if !ok {
			return nil, fmt.Errorf("层 %d 缺失下载结果", i+1)
		}
		out[i] = DownloadedLayer{FilePath: fp, Digest: digests[i]}
	}

	safePrintf("\n✓ 所有 %d 个层下载完成\n", totalLayers)
	return out, nil
}

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

func downloadLayerWithProgress(ctx context.Context, client *http.Client, registry, repository, digest, auth, tempDir, cacheDir string, mirrors []string, tracker *ProgressTracker) (string, error) {
	operation := func(reg string) (any, error) {
		url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", reg, repository, digest)

		layerFile := filepath.Join(tempDir, strings.Replace(digest, ":", "_", 1))
		tempFile := layerFile + ".downloading"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
				if err := ctx.Err(); err != nil {
					return err
				}
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

		if cacheDir != "" {
			cacheFile := filepath.Join(cacheDir, strings.Replace(digest, ":", "_", 1))
			if err := copyFile(layerFile, cacheFile); err != nil {
				safePrintf("\n⚠ 写入缓存失败 %s: %v\n", cacheFile, err)
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

	result, err := tryRegistries(cfg, operation)
	if err != nil {
		return "", err
	}

	return result.(string), nil
}

func createTarFile(outputPath string, layers []DownloadedLayer, repository, tag, arch string, imageConfig map[string]any) error {
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

	layerIDs := make([]string, len(layers))
	diffIDs := make([]string, len(layers))

	for i, l := range layers {
		layerID := layerIDFor(l.Digest, i)
		layerIDs[i] = layerID

		if _, err := os.Stat(l.FilePath); err != nil {
			return fmt.Errorf("层文件无效: %v", err)
		}

		layerTarPath := filepath.Join(layerID, "layer.tar")
		if err := addFileToTar(tw, l.FilePath, layerTarPath); err != nil {
			return fmt.Errorf("添加层文件失败: %v", err)
		}

		diffID, err := calculateDiffID(l.FilePath)
		if err != nil {
			return fmt.Errorf("计算diffID失败: %v", err)
		}
		diffIDs[i] = diffID

		if err := addVersionFile(tw, layerID); err != nil {
			return fmt.Errorf("添加VERSION文件失败: %v", err)
		}

		if err := addLayerJSON(tw, layerID); err != nil {
			return fmt.Errorf("添加json文件失败: %v", err)
		}
	}

	var config map[string]any
	if imageConfig != nil {
		config = imageConfig
	} else {
		config = map[string]any{
			"architecture": arch,
			"os":           "linux",
			"config":       map[string]any{},
			"created":      time.Now().UTC().Format(time.RFC3339Nano),
			"history":      []any{},
		}
	}

	config["rootfs"] = map[string]any{
		"type":     "layers",
		"diff_ids": diffIDs,
	}

	imageID := generateImageID(config)

	if err := addImageConfig(tw, imageID, config); err != nil {
		return fmt.Errorf("添加镜像配置失败: %v", err)
	}

	if err := addManifestJSON(tw, repository, tag, imageID, layerIDs); err != nil {
		return fmt.Errorf("添加manifest.json失败: %v", err)
	}

	if err := addRepositoriesJSON(tw, repository, tag, imageID); err != nil {
		return fmt.Errorf("添加repositories文件失败: %v", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("关闭tar文件失败: %v", err)
	}

	return nil
}

// layerIDFor returns deterministic 64-hex layer directory ID derived from digest+index.
// Index suffix keeps IDs unique when the same digest appears twice in a manifest.
func layerIDFor(digest string, index int) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s_%d", digest, index))
	return fmt.Sprintf("%x", h)
}

func generateImageID(config map[string]any) string {
	content, err := json.Marshal(config)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(content)
	return fmt.Sprintf("%x", hash)
}

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

	tarPath = filepath.ToSlash(tarPath)
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
		Format:   tar.FormatGNU,
	}

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("写入tar头部失败: %v", err)
	}

	buf := make([]byte, 1024*1024)
	written := int64(0)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			nw, werr := tw.Write(buf[:n])
			if werr != nil {
				return fmt.Errorf("写入tar内容失败: %v", werr)
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

	if written != info.Size() {
		return fmt.Errorf("文件大小不匹配: 期望 %d 字节, 实际写入 %d 字节", info.Size(), written)
	}

	return nil
}

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

func addManifestJSON(tw *tar.Writer, repository, tag, imageID string, layerIDs []string) error {
	layers := make([]string, len(layerIDs))
	for i, id := range layerIDs {
		layers[i] = id + "/layer.tar"
	}

	manifest := []map[string]any{
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

func addImageConfig(tw *tar.Writer, imageID string, config map[string]any) error {
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

func getCacheDir(config Config) (string, error) {
	if config.CacheDir != "" {
		return config.CacheDir, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(homeDir, ".docker-pull", "cache")

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", err
	}

	return cacheDir, nil
}

func checkLayerCache(cacheDir, digest string) (string, bool) {
	cachedFile := filepath.Join(cacheDir, strings.Replace(digest, ":", "_", 1))
	if _, err := os.Stat(cachedFile); err == nil {
		return cachedFile, true
	}
	return cachedFile, false
}

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

	err = destFile.Sync()
	if err != nil {
		return err
	}

	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, sourceInfo.Mode())
}

func calculateUncompressedHash(gzipFile string) (string, error) {
	file, err := os.Open(gzipFile)
	if err != nil {
		return "", fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("创建gzip reader失败: %v", err)
	}
	defer gr.Close()

	hash := sha256.New()
	buf := make([]byte, 1024*1024)
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

func calculateDiffID(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	header := make([]byte, 2)
	if _, err := file.Read(header); err != nil {
		return "", fmt.Errorf("读取文件头失败: %v", err)
	}

	if header[0] == 0x1f && header[1] == 0x8b {
		return calculateUncompressedHash(filePath)
	}

	if _, err := file.Seek(0, 0); err != nil {
		return "", fmt.Errorf("重置文件指针失败: %v", err)
	}

	hash := sha256.New()
	buf := make([]byte, 1024*1024)
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
