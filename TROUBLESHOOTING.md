# MinerU插件DNS解析问题解决方案

## 问题描述
当使用MinerU插件处理文件时，可能会遇到以下错误：
```
requests.exceptions.ConnectionError: HTTPConnectionPool(host='api', port=5001): Max retries exceeded with url: /files/upload/for-plugin...
```

这个错误表明Dify环境的文件上传服务无法解析主机名 `api`。

## 根本原因
该问题通常发生在以下场景：
1. Dify环境未正确配置 `FILES_URL` 环境变量
2. 在非Docker Compose环境中使用了 `api:5001` 作为文件服务地址
3. 网络配置导致无法解析 `api` 主机名

## 解决方案

### 方案1：配置Dify环境变量（推荐）

1. **找到Dify部署目录**：
   ```bash
   # 如果您使用Docker Compose部署
   cd /path/to/dify/docker
   ```

2. **编辑 `.env` 文件**：
   ```bash
   # 对于Docker Compose部署
   echo "FILES_URL=http://api:5001" >> .env
   
   # 对于其他部署方式（使用实际IP地址）
   echo "FILES_URL=http://YOUR_DIFY_HOST_IP:5001" >> .env
   ```

3. **重启Dify服务**：
   ```bash
   docker-compose down
   docker-compose up -d
   ```

### 方案2：使用IP地址替代主机名

如果您知道Dify服务的实际IP地址，可以直接使用IP地址：

```bash
# 示例：假设Dify运行在192.168.1.100
echo "FILES_URL=http://192.168.1.100:5001" >> .env
```

### 方案3：修改hosts文件（临时方案）

在Linux/macOS上：
```bash
# 编辑 /etc/hosts 文件
sudo echo "127.0.0.1 api" >> /etc/hosts
```

在Windows上：
编辑 `C:\Windows\System32\drivers\etc\hosts` 文件，添加：
```
127.0.0.1 api
```

## 验证配置

1. **检查端口是否开放**：
   ```bash
   netstat -tuln | grep 5001
   ```

2. **测试连接**：
   ```bash
   curl http://localhost:5001/health
   ```

3. **在Dify中重新配置插件**：
   - 进入Dify管理界面
   - 找到MinerU插件配置
   - 更新Base URL为正确的地址

## 注意事项

- 如果使用IP地址，确保IP地址不会频繁变化
- 在Docker环境中，确保端口5001已正确映射
- 如果使用反向代理，确保代理配置正确

## 联系支持

如果以上方案仍无法解决问题，请提供：
1. Dify的部署方式（Docker Compose/原生部署/其他）
2. 当前的网络环境
3. 完整的错误日志
