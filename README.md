# 常见网络攻击的检测与防御系统

本项目是《信息安全科技创新》课程的教学型安全实验项目，目标是围绕一个简单 Web 应用场景，完成常见网络攻击行为的检测、分析、关联、展示与基础响应联动。当前实现以日志驱动的 IDS 为主，同时包含一个面向 Linux 内核模块的 IPS/防御联动接口层，便于课程展示从“检测”到“响应”的完整流程。

## 项目定位

- 能清楚展示常见网络攻击的行为特征。
- 能通过结构化日志进行规则检测、误用检测/特征库匹配和基础异常检测。
- 能输出可解释的告警结果、风险等级、置信度、基线统计和攻击链事件。
- 能根据高风险告警和攻击链事件生成限流、封禁、账户锁定等响应建议，并为 IPS 式主动响应提供接口和架构基础。

## 当前已实现功能

### 1. 日志导入与解析

系统支持加载内置扩展示例日志，或上传 CSV 日志文件进行分析。CSV 解析流程保留基础字段，同时支持课程演示所需的扩展字段。

基础字段：

- `timestamp`
- `source_ip`
- `target_ip`
- `port`
- `path`
- `status_code`
- `username`
- `login_success`

可选扩展字段：

- `method`
- `protocol`
- `host`
- `user_agent`
- `bytes_sent`
- `duration_ms`
- `tls_fingerprint`

对应代码见 [src/parser/log_parser.py](./src/parser/log_parser.py) 和 [src/app.py](./src/app.py)。

### 2. IDS 检测能力与特征库

当前后端已经实现一组教学演示型检测规则、误用检测特征库和异常检测模块，用于识别常见攻击或异常访问行为，包括：

- 端口扫描
- 暴力登录
- 可疑路径访问
- 异常状态码集中出现
- 异常访问频率
- SQL 注入尝试
- XSS 尝试
- 目录遍历与敏感文件访问
- WebShell / 恶意命令访问
- 疑似控制信道
- 外部来源访问内网
- TLS 指纹异常
- 疑似密码喷洒
- 疑似横向移动
- 大流量或长会话异常

规则检测入口在 [src/detector/rules.py](./src/detector/rules.py)，特征库检测入口在 [src/detector/signatures.py](./src/detector/signatures.py)，异常检测入口在 [src/detector/anomaly.py](./src/detector/anomaly.py)。内置特征库位于 [data/signatures.json](./data/signatures.json)，示例测试覆盖见 [tests/test_detection.py](./tests/test_detection.py) 和 [tests/test_signatures.py](./tests/test_signatures.py)。

### 3. 风险评分、基线与攻击链关联

系统会根据检测结果为告警计算分数，并划分为 `低危`、`中危`、`高危` 三类风险等级。分析结果还会返回批内基线统计，例如每个来源 IP 的访问量、多端口访问情况、登录失败次数，以及扩展字段覆盖情况。

攻击链关联模块会按来源 IP 汇总扫描、初始访问、凭据攻击、横向移动、执行或控制等阶段。当同一来源触发两个及以上阶段时，系统会生成 `incidents` 事件，并输出对应的 `recommendations` 响应建议。

风险评分相关实现位于 [src/scoring/risk.py](./src/scoring/risk.py)，攻击链关联实现位于 [src/detector/correlation.py](./src/detector/correlation.py)，统一结果模型位于 [src/detector/models.py](./src/detector/models.py)。

### 4. Web 界面与分析接口

项目提供 Flask Web 服务，支持页面访问和 JSON API 调用。当前后端已提供：

- `GET /api/sample`：分析内置示例日志
- `POST /api/analyze`：上传 CSV 日志并分析
- `GET /api/analyze/lab-live`：读取靶场实时访问日志并分析
- `GET /api/alerts`：按条件筛选告警
- `GET /api/alerts/export`：按当前筛选条件导出告警 CSV
- `POST /api/alerts/clear`：清空当前告警和靶场访问日志
- `GET /api/alerts/stats`：获取统计信息
- `GET /api/alerts/recent`：获取最近告警
- `POST /api/alerts/analyze`：对单条告警生成 AI/规则化分析说明
- `POST /api/alerts/defend`：根据告警生成并尝试下发防御规则
- `POST /api/alerts/chain`：对告警集合生成攻击链推演文本
- `GET /api/dashboard`：聚合 IDS 与防御模块状态

`GET /api/sample` 和 `POST /api/analyze` 会返回统一分析结果，主要字段包括：

```json
{
  "events": 0,
  "alerts": [],
  "incidents": [],
  "summary": {
    "by_level": {},
    "by_type": {},
    "by_category": {},
    "top_sources": [],
    "top_targets": [],
    "timeline": []
  },
  "baseline": {
    "request_rate_per_ip": [],
    "unique_ports_per_ip": [],
    "login_failures_per_ip": [],
    "data_coverage": {}
  },
  "metadata": {},
  "source": "",
  "recommendations": []
}
```

主应用入口见 [run.py](./run.py) 和 [src/app.py](./src/app.py)。

### 5. IPS / 防御扩展接口

仓库中已经包含一个防御接口层 [src/defense.py](./src/defense.py)，并在后端暴露了规则管理、状态查询和统计接口，例如：

- `GET /api/defense/status`
- `POST /api/defense/enable`
- `GET /api/defense/rules`
- `POST /api/defense/rules`
- `PUT /api/defense/rules/<id>`
- `DELETE /api/defense/rules/<id>`
- `GET /api/defense/stats`
- `POST /api/defense/stats/record`
- `POST /api/defense/stats/clear`
- `GET /api/defense/default-policy`
- `PUT /api/defense/default-policy`

这部分当前主要用于教学型联动演示。在非 Linux 环境或没有对应内核设备时，会回退到模拟状态。模拟模式只维护内存中的规则、状态和统计数字，用于页面展示和答辩演示，不会真正修改系统防火墙规则，也不应理解为完整可部署的生产级防火墙系统。

### 6. AI 分析辅助模块

项目包含 [src/llm.py](./src/llm.py) 作为告警解释和防御建议的 AI 辅助层。该模块默认连接本地 Ollama 服务，也支持通过配置切换到 OpenAI 兼容接口。当前后端提供：

- `GET /api/llm/status`：检查 AI 分析服务是否可用
- `GET /api/llm/config`：读取当前 AI 配置，返回结果会隐藏 API Key
- `PUT /api/llm/config`：更新 provider、接口地址、模型名等配置
- `POST /api/llm/test`：测试指定配置或当前配置是否可连接
- `GET /api/llm/models`：获取当前 provider 下可用模型列表

当模型服务未启用、未安装 HTTP 依赖或接口不可达时，系统会自动使用内置规则化文本生成告警解释、防御建议和攻击链分析，保证课程演示流程不会因为模型不可用而中断。AI 输出仅作为辅助说明，最终判断仍以检测规则、特征匹配、异常检测结果和人工复核为准。

## 项目结构

```text
network intrusion detection system/
├── README.md
├── requirements.txt
├── pytest.ini
├── run.py
├── data/
│   ├── sample_logs.csv
│   ├── sample_logs_extended.csv
│   ├── signatures.json
│   └── llm_config.json          # AI 分析模块配置文件
├── kernel_module/              # Linux 内核防御模块相关内容
├── frontend/                   # Vue 前端工程与构建产物
├── 交大学生成绩管理系统_vuln_lab/ # 课程演示靶场与访问日志来源
├── src/
│   ├── app.py                  # Flask 应用与 API
│   ├── defense.py              # 防御接口封装
│   ├── llm.py                  # AI 告警分析与防御建议辅助模块
│   ├── detector/
│   │   ├── anomaly.py          # 异常检测与基线统计
│   │   ├── correlation.py      # 攻击链关联与响应建议
│   │   ├── models.py           # 告警、事件和分析结果模型
│   │   ├── rules.py            # IDS 规则检测
│   │   └── signatures.py       # 误用检测/特征库匹配
│   ├── parser/
│   │   └── log_parser.py       # CSV 日志解析
│   ├── scoring/
│   │   └── risk.py             # 风险评分
│   ├── static/                 # 传统模板前端资源
│   ├── templates/              # Flask 模板
│   └── utils/
│       └── serialization.py    # 序列化工具
└── tests/
    ├── conftest.py
    ├── test_detection.py
    └── test_signatures.py
```

## 运行环境

### 软件要求

- Python 3.10 及以上
- Node.js 18 及以上
- 现代浏览器（Chrome / Edge）

Python 依赖见 [requirements.txt](./requirements.txt)，前端依赖见 [frontend/package.json](./frontend/package.json)。

### 硬件与系统建议

- Windows 10/11 或 Linux
- 至少 8 GB 内存
- 现代浏览器（Chrome / Edge）

说明：

- 纯 IDS 日志分析部分可以在 Windows 或 Linux 上运行。
- `src/defense.py` 对应的防御联动更偏向 Linux 环境；在其他环境下默认以模拟状态返回。

## 快速开始

先进入项目根目录：

```bash
cd "C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system"
```

安装后端依赖：

```bash
python -m pip install -r requirements.txt
```

安装前端依赖：

```bash
cd frontend
npm install
cd ..
```

### 方式一：开发模式运行

先启动后端服务：

```bash
python run.py
```

后端默认监听：

```text
http://127.0.0.1:5000
```

再打开另一个终端启动前端开发服务：

```bash
cd "C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/frontend"
npm run dev
```

浏览器访问前端开发服务输出的本地地址，通常是：

```text
http://localhost:5173
```

### 方式二：构建后由 Flask 统一访问

如果只想启动一个服务，可以先构建前端：

```bash
cd frontend
npm run build
cd ..
```

然后启动后端：

```bash
python run.py
```

浏览器访问：

```text
http://127.0.0.1:5000
```

此时 Flask 会优先使用 `frontend/dist` 中的构建产物，并继续提供所有 `/api/...` 接口。

### 基本使用流程

启动系统后，可以在页面中加载内置示例数据，或上传符合格式的 CSV 日志文件进行分析。分析结果会展示 IDS 告警、风险等级、攻击链事件、基线统计和响应建议。

在 Windows 或未加载 Linux 内核模块的环境下，防御模块会自动进入模拟模式。此时防御规则的新增、修改、删除和状态展示仍可用于课程演示，但不会真正修改系统防火墙规则。

### 靶场联动运行

如果需要演示真实网站访问日志联动，另开一个终端启动靶场：

```bash
cd "C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/交大学生成绩管理系统_vuln_lab"
python app.py
```

靶场默认访问地址：

```text
http://127.0.0.1:8001
```

靶场运行后会把访问记录写入 `交大学生成绩管理系统_vuln_lab/data/access_log.csv`。回到 IDS 页面后，使用“分析靶场实时日志”即可读取这份日志并生成告警。前端与后端建立 WebSocket 连接后，后端还会启动后台监听任务，按文件变化增量读取新增访问记录，并把新的分析结果推送到监控页面。靶场的演示账号和脚本命令见 [交大学生成绩管理系统_vuln_lab/README.md](./交大学生成绩管理系统_vuln_lab/README.md)。

## 测试

运行后端自动化测试：

```bash
python -m pytest
```

运行靶场子项目测试：

```bash
PYTHONPATH="C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/交大学生成绩管理系统_vuln_lab;C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system" python -m pytest "C:/Users/tmp/Desktop/信安科技创新/network intrusion detection system/交大学生成绩管理系统_vuln_lab/tests"
```

检查前端是否可以正常构建：

```bash
cd frontend
npm run build
cd ..
```

当前测试重点覆盖：

- 示例日志是否能触发预期告警类型
- 告警是否具备有效风险等级与分数
- 非法时间戳和非法端口是否会被接口拒绝
- 扩展示例是否返回 `baseline`、`incidents`、`recommendations` 和新 `summary` 结构
- 旧格式 CSV 上传是否仍可兼容
- 可选扩展字段是否能被正确解析
- SQL 注入、XSS、目录遍历、恶意命令和疑似控制信道等特征库规则是否命中

## CSV 输入格式

最小可用字段格式如下，旧格式 CSV 仍可上传分析：

```text
timestamp,source_ip,target_ip,port,path,status_code,username,login_success
2026-07-08T10:00:00,192.168.1.20,10.0.0.5,80,/index,200,,
```

其中：

- `timestamp` 使用 ISO 风格时间字符串
- `port` 和 `status_code` 需要能转换为数字
- `login_success` 用于描述登录是否成功

扩展字段格式如下，适合展示异常检测、TLS 指纹模拟和基线覆盖情况：

```text
timestamp,source_ip,target_ip,port,path,status_code,username,login_success,method,protocol,host,user_agent,bytes_sent,duration_ms,tls_fingerprint
2026-07-08T10:04:00,198.51.100.88,10.0.0.42,443,"/search?q=1%20union%20select%20username,password%20from%20users",500,,,GET,tcp,app.lab,sqlmap-demo,5400,420,ja3-browser
```

其中：

- `method`、`protocol`、`host`、`user_agent` 用于描述请求方法、协议、主机名和客户端特征。
- `bytes_sent` 和 `duration_ms` 用于检测大流量或长会话异常，留空时不会影响基础分析。
- `tls_fingerprint` 用于模拟 TLS 指纹异常检测，留空时不会影响基础分析。

## 当前仓库状态说明

当前仓库已经具备一个可以运行的课程演示版本，重点完成了：

- Flask 后端接口
- CSV 日志解析
- 基础 IDS 检测规则
- 误用检测特征库
- 异常检测与基线统计
- 攻击链关联事件
- 风险评分
- 响应建议输出
- 页面展示与统计接口
- 防御模块 API 壳层
- pytest 自动化测试

同时，项目还保留了继续增强实时数据采集、响应联动展示和前端可视化细节的空间。

## 小组分工

- **成员 1（组长）：总体设计、攻击样例统筹模拟与系统集成**。负责需求分析、总体架构、模块接口定义、进度协调，统筹 SQL 注入、XSS、暴力登录、敏感路径探测等攻击样例构造与检测验证方案，并负责最后的系统整合与报告汇总。
- **成员 2：模拟网站与业务功能**。负责登录页面、普通页面、搜索接口、受限资源页面等业务功能实现，并保证网站能够产生访问日志和认证日志。
- **成员 3：日志解析与数据预处理**。负责 CSV 日志格式设计、字段提取、数据清洗、标准化处理和结构化事件输出。
- **成员 4：攻击检测、风险评分与防御响应分析**。负责误用检测规则、异常检测逻辑、风险评分、攻击链关联分析，以及高风险事件对应的限流、封禁、账户锁定等主动响应策略设计，是 IDS/IPS 核心分析与响应模块的主要负责人。
- **成员 5：前端展示、结果整理与答辩材料制作**。负责可视化界面、告警结果展示、实验截图、结果整理，以及演示脚本和答辩材料制作。

## 安全与用途声明

本项目仅用于课程学习、教学演示和防御性安全研究。仓库中的检测规则、样例数据和防御接口用于帮助理解常见网络攻击检测与响应机制，不用于未授权攻击、渗透破坏或其他违规用途。
