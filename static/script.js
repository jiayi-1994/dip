function pullImage() {
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
}