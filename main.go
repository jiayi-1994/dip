package main

import (
	"archive/tar"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

	fmt.Printf("开始拉取镜像: %s:%s 从 %s\n", repository, tag, registry)

	// 创建HTTP客户端
	client := createHTTPClient(config.Insecure)

	// 获取认证信息
	auth := getAuthToken(client, registry, repository, config.Username, config.Password)

	// 获取镜像清单
	manifest, err := getManifest(client, registry, repository, tag, auth, config.Arch)
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
	layers, err := downloadLayers(client, registry, repository, manifest, auth, tempDir)
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
	err = createTarFile(outputFile, layers, manifest, repository, tag)
	if err != nil {
		fmt.Printf("创建tar文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("镜像已成功保存到: %s\n", outputFile)
}

// 解析命令行参数
func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.Image, "image", "", "Docker镜像名称 (格式: [registry/]repository[:tag])")
	flag.StringVar(&config.Output, "output", "", "输出文件路径 (默认: repository-tag.tar)")
	flag.StringVar(&config.Registry, "registry", "registry-1.docker.io", "Docker Registry地址")
	flag.StringVar(&config.Username, "username", "", "Registry用户名")
	flag.StringVar(&config.Password, "password", "", "Registry密码")
	flag.StringVar(&config.Arch, "arch", "amd64", "镜像架构 (例如: amd64, arm64)")
	flag.BoolVar(&config.Insecure, "insecure", false, "允许不安全的HTTPS连接")
	flag.BoolVar(&config.ShowVersion, "version", false, "显示版本信息")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: docker-pull [选项]\n\n选项:\n")
		flag.PrintDefaults()
	}

	flag.Parse()
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

// 获取镜像清单
func getManifest(client *http.Client, registry, repository, tag, auth string, arch string) (map[string]interface{}, error) {
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
						return getManifest(client, registry, repository, digest, auth, arch)
					}
				}
			}
			return nil, fmt.Errorf("未找到架构为 %s 的manifest", arch)
		}
	}

	return manifest, nil
}

// 下载镜像层
func downloadLayers(client *http.Client, registry, repository string, manifest map[string]interface{}, auth, tempDir string) ([]string, error) {
	var layers []interface{}

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

		fmt.Printf("下载层 %d/%d: %s\n", i+1, len(layers), digest)

		// 下载层
		layerFile, err := downloadLayer(client, registry, repository, digest, auth, tempDir)
		if err != nil {
			return nil, err
		}

		layerFiles = append(layerFiles, layerFile)
	}

	return layerFiles, nil
}

// 下载单个镜像层
func downloadLayer(client *http.Client, registry, repository, digest, auth, tempDir string) (string, error) {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, digest)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// 添加认证头
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载层失败，状态码: %d", resp.StatusCode)
	}

	// 获取文件大小
	totalSize := resp.ContentLength

	// 创建临时文件
	layerFile := filepath.Join(tempDir, strings.Replace(digest, ":", "_", 1))
	file, err := os.Create(layerFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 创建进度条读取器
	downloaded := int64(0)
	startTime := time.Now()
	lastUpdateTime := startTime
	lastDownloaded := int64(0)

	reader := io.TeeReader(resp.Body, file)
	buf := make([]byte, 32*1024) // 32KB 缓冲区

	for {
		n, err := reader.Read(buf)
		if n > 0 {
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

				lastUpdateTime = now
				lastDownloaded = downloaded
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	// 完成下载，清除进度显示并换行
	fmt.Println()

	return layerFile, nil
}

// 创建tar文件
func createTarFile(outputFile string, layers []string, manifest map[string]interface{}, repository, tag string) error {
	fmt.Printf("创建tar文件: %s\n", outputFile)

	// 创建输出文件
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// 创建tar写入器
	tw := tar.NewWriter(file)
	defer tw.Close()

	// 获取配置信息
	config, err := getImageConfig(manifest)
	if err != nil {
		return fmt.Errorf("获取镜像配置失败: %v", err)
	}

	// 生成镜像ID
	imageID := generateImageID(config)

	// 添加层文件到tar
	layerIDs := make([]string, 0, len(layers))
	for _, layerFile := range layers {
		layerID := filepath.Base(layerFile)
		layerIDs = append(layerIDs, layerID)

		// 添加层文件到tar
		if err := addFileToTar(tw, layerFile, layerID+"/layer.tar"); err != nil {
			return fmt.Errorf("添加层文件失败: %v", err)
		}

		// 添加层版本文件
		if err := addVersionFile(tw, layerID); err != nil {
			return fmt.Errorf("添加层版本文件失败: %v", err)
		}

		// 添加层json文件
		if err := addLayerJSON(tw, layerID); err != nil {
			return fmt.Errorf("添加层JSON文件失败: %v", err)
		}
	}

	// 添加manifest.json文件
	if err := addManifestJSON(tw, repository, tag, imageID, layerIDs); err != nil {
		return fmt.Errorf("添加manifest.json文件失败: %v", err)
	}

	// 添加repositories文件
	if err := addRepositoriesJSON(tw, repository, tag, imageID); err != nil {
		return fmt.Errorf("添加repositories文件失败: %v", err)
	}

	// 添加镜像配置文件
	if err := addImageConfig(tw, imageID, config, layerIDs); err != nil {
		return fmt.Errorf("添加镜像配置文件失败: %v", err)
	}

	return nil
}

// 获取镜像配置
func getImageConfig(manifest map[string]interface{}) (map[string]interface{}, error) {
	// 简化实现，实际项目中需要从manifest中提取config
	config := make(map[string]interface{})
	config["architecture"] = "amd64"
	config["os"] = "linux"
	config["config"] = map[string]interface{}{
		"Hostname":     "",
		"Domainname":   "",
		"User":         "",
		"ExposedPorts": map[string]interface{}{},
		"Env":          []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		"Cmd":          []string{"/bin/sh"},
		"WorkingDir":   "/",
	}
	return config, nil
}

// 生成镜像ID
func generateImageID(config map[string]interface{}) string {
	// 简化实现，实际项目中应该计算配置的SHA256
	return "sha256:" + base64Encode(fmt.Sprintf("%v", config))[:12]
}

// 添加文件到tar
func addFileToTar(tw *tar.Writer, filePath, tarPath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    tarPath,
		Size:    info.Size(),
		Mode:    int64(info.Mode()),
		ModTime: info.ModTime(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = io.Copy(tw, file)
	return err
}

// 添加版本文件
func addVersionFile(tw *tar.Writer, layerID string) error {
	content := []byte("1.0")
	header := &tar.Header{
		Name:    layerID + "/VERSION",
		Size:    int64(len(content)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err := tw.Write(content)
	return err
}

// 添加层JSON文件
func addLayerJSON(tw *tar.Writer, layerID string) error {
	layerJSON := map[string]interface{}{
		"id":      layerID,
		"created": time.Now().Format(time.RFC3339),
		"container_config": map[string]interface{}{
			"Hostname":   "",
			"Domainname": "",
			"User":       "",
			"Cmd":        []string{"/bin/sh"},
		},
	}

	content, err := json.Marshal(layerJSON)
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    layerID + "/json",
		Size:    int64(len(content)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = tw.Write(content)
	return err
}

// 添加manifest.json文件
func addManifestJSON(tw *tar.Writer, repository, tag, imageID string, layerIDs []string) error {
	// 构建层路径
	layerPaths := make([]string, 0, len(layerIDs))
	for _, layerID := range layerIDs {
		layerPaths = append(layerPaths, layerID+"/layer.tar")
	}

	// 构建manifest
	manifest := []map[string]interface{}{
		{
			"Config":   imageID + ".json",
			"RepoTags": []string{repository + ":" + tag},
			"Layers":   layerPaths,
		},
	}

	content, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    "manifest.json",
		Size:    int64(len(content)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = tw.Write(content)
	return err
}

// 添加repositories文件
func addRepositoriesJSON(tw *tar.Writer, repository, tag, imageID string) error {
	// 构建repositories
	repos := map[string]interface{}{
		repository: map[string]string{
			tag: imageID,
		},
	}

	content, err := json.Marshal(repos)
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    "repositories",
		Size:    int64(len(content)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = tw.Write(content)
	return err
}

// 添加镜像配置文件
func addImageConfig(tw *tar.Writer, imageID string, config map[string]interface{}, layerIDs []string) error {
	// 添加层历史
	config["history"] = make([]map[string]interface{}, len(layerIDs))
	// 将 history 转换为正确的类型并更新
	history := make([]map[string]interface{}, len(layerIDs))
	for i := range layerIDs {
		history[i] = map[string]interface{}{
			"created":    time.Now().Format(time.RFC3339),
			"created_by": "/bin/sh",
		}
	}
	config["history"] = history

	// 添加rootfs信息
	config["rootfs"] = map[string]interface{}{
		"type":     "layers",
		"diff_ids": layerIDs,
	}

	content, err := json.Marshal(config)
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    imageID + ".json",
		Size:    int64(len(content)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = tw.Write(content)
	return err
}
