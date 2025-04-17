package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// 启动Web服务器的主函数
func main() {
	// 创建静态文件目录
	os.MkdirAll("./static", 0755)

	// 创建HTML模板
	createHTMLTemplates()

	// 处理静态文件
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// 处理首页
	http.HandleFunc("/", handleIndex)

	// 处理API请求
	http.HandleFunc("/api/pull", handlePull)

	// 启动服务器
	fmt.Println("Web服务器已启动，访问 http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

// 创建HTML模板
func createHTMLTemplates() {
	// 创建index.html
	indexHTML := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Docker镜像拉取工具</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <h1>Docker镜像拉取工具</h1>
        <div class="form-container">
            <div class="form-group">
                <label for="image">Docker镜像名称:</label>
                <input type="text" id="image" placeholder="例如: nginx:latest">
            </div>
            <div class="form-group">
                <label for="output">输出文件名:</label>
                <input type="text" id="output" placeholder="例如: nginx.tar">
            </div>
            <div class="form-group">
                <label for="registry">Registry地址:</label>
                <input type="text" id="registry" value="registry-1.docker.io">
            </div>
            <div class="form-group">
                <label for="arch">架构:</label>
                <select id="arch">
                    <option value="amd64">amd64</option>
                    <option value="arm64">arm64</option>
                    <option value="arm">arm</option>
                    <option value="386">386</option>
                </select>
            </div>
            <div class="form-group">
                <label for="mirrors">镜像加速器:</label>
                <input type="text" id="mirrors" value="docker.gh-proxy.com,docker.1ms.run,docker.xjyi.me">
            </div>
            <div class="form-group checkbox">
                <input type="checkbox" id="insecure">
                <label for="insecure">允许不安全的HTTPS连接</label>
            </div>
            <div class="form-actions">
                <button id="pull-btn" onclick="pullImage()">拉取镜像</button>
            </div>
        </div>
        <div class="result-container" id="result-container" style="display: none;">
            <h2>拉取结果</h2>
            <pre id="result-output"></pre>
        </div>
    </div>
    <script src="/static/script.js"></script>
</body>
</html>`

	os.WriteFile("./static/index.html", []byte(indexHTML), 0644)

	// 创建CSS文件
	css := `body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f8f9fa;
    margin: 0;
    padding: 0;
}

.container {
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
}

h1 {
    text-align: center;
    color: #2c3e50;
    margin-bottom: 30px;
}

.form-container {
    background-color: white;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    margin-bottom: 20px;
}

.form-group {
    margin-bottom: 15px;
}

label {
    display: block;
    margin-bottom: 5px;
    font-weight: 600;
}

input[type="text"], select {
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
}

.checkbox {
    display: flex;
    align-items: center;
}

.checkbox input {
    margin-right: 10px;
}

.checkbox label {
    margin-bottom: 0;
}

.form-actions {
    text-align: center;
    margin-top: 20px;
}

button {
    background-color: #3498db;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
    transition: background-color 0.3s;
}

button:hover {
    background-color: #2980b9;
}

.result-container {
    background-color: white;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

pre {
    background-color: #f5f5f5;
    padding: 15px;
    border-radius: 4px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
}`

	os.WriteFile("./static/style.css", []byte(css), 0644)

	// 创建JavaScript文件
	js := `function pullImage() {
    const image = document.getElementById('image').value;
    if (!image) {
        alert('请输入Docker镜像名称');
        return;
    }

    const output = document.getElementById('output').value;
    const registry = document.getElementById('registry').value;
    const arch = document.getElementById('arch').value;
    const mirrors = document.getElementById('mirrors').value;
    const insecure = document.getElementById('insecure').checked;

    const pullBtn = document.getElementById('pull-btn');
    const resultContainer = document.getElementById('result-container');
    const resultOutput = document.getElementById('result-output');

    pullBtn.disabled = true;
    pullBtn.textContent = '拉取中...';
    resultContainer.style.display = 'block';
    resultOutput.textContent = '正在拉取镜像，请稍候...';

    // 构建请求参数
    const params = {
        image: image,
        output: output,
        registry: registry,
        arch: arch,
        mirrors: mirrors,
        insecure: insecure
    };

    // 发送API请求
    fetch('/api/pull', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(params)
    })
    .then(response => response.json())
    .then(data => {
        resultOutput.textContent = data.message;
        pullBtn.disabled = false;
        pullBtn.textContent = '拉取镜像';
    })
    .catch(error => {
        resultOutput.textContent = '错误: ' + error.message;
        pullBtn.disabled = false;
        pullBtn.textContent = '拉取镜像';
    });
}`

	os.WriteFile("./static/script.js", []byte(js), 0644)
}

// 处理首页请求
func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/index.html")
}

// 处理拉取请求
func handlePull(w http.ResponseWriter, r *http.Request) {
	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	// 解析请求
	var params struct {
		Image    string `json:"image"`
		Output   string `json:"output"`
		Registry string `json:"registry"`
		Arch     string `json:"arch"`
		Mirrors  string `json:"mirrors"`
		Insecure bool   `json:"insecure"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"message": "请求解析失败: " + err.Error()})
		return
	}

	// 构建响应消息
	message := fmt.Sprintf("开始拉取镜像: %s\n", params.Image)
	if params.Registry != "" {
		message += fmt.Sprintf("默认仓库: %s\n", params.Registry)
	}
	if params.Mirrors != "" {
		message += fmt.Sprintf("配置的镜像加速器: %s\n", params.Mirrors)
	}

	// 生成输出文件名
	outputFile := params.Output
	if outputFile == "" {
		outputFile = fmt.Sprintf("%s-%s.tar", strings.ReplaceAll(params.Image, "/", "_"), params.Arch)
	}

	// 返回响应
	message += fmt.Sprintf("\n镜像拉取请求已提交，输出文件将保存为: %s\n", outputFile)
	message += "\n注意: 在Web界面中，镜像拉取功能仅作为演示，实际拉取过程需要在命令行中执行。\n"
	message += "请使用以下命令在命令行中拉取镜像:\n\n"

	// 构建命令行示例
	cmd := fmt.Sprintf("go run main.go -i %s", params.Image)
	if params.Output != "" {
		cmd += fmt.Sprintf(" -o %s", params.Output)
	}
	if params.Registry != "registry-1.docker.io" {
		cmd += fmt.Sprintf(" -r %s", params.Registry)
	}
	if params.Arch != "amd64" {
		cmd += fmt.Sprintf(" -a %s", params.Arch)
	}
	if params.Mirrors != "" {
		cmd += fmt.Sprintf(" -m %s", params.Mirrors)
	}
	if params.Insecure {
		cmd += " -k"
	}

	message += cmd

	json.NewEncoder(w).Encode(map[string]string{"message": message})
}
