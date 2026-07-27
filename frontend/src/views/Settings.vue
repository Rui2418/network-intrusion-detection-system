<template>
  <div class="settings">
    <div class="section">
      <h3>IDS 检测器阈值</h3>
      <div class="grid-3">
        <div class="t-item" v-for="t in thresholds" :key="t.name">
          <label>{{ t.label }} <small>({{ t.window }}s)</small></label>
          <input type="number" v-model.number="t.value" min="1" />
        </div>
      </div>
      <p class="hint">阈值和窗口时间当前在服务器端配置（src/detector/rules.py），此处仅参考展示。</p>
    </div>

    <div class="section">
      <h3>IPS 网络接口</h3>
      <div class="row">
        <select v-model="selectedIface">
          <option value="">自动选择</option>
          <option v-for="iface in interfaces" :key="iface" :value="iface">{{ iface }}</option>
        </select>
        <button @click="refreshIfaces">刷新</button>
      </div>
      <p class="hint">IPS 内核模块监听所有接口上的 POST_ROUTING 流量。</p>
    </div>

    <div class="section">
      <h3>Zeek 数据采集 (实时抓包)</h3>
      <div class="zeek-status">
        <div class="zeek-info">
          <div class="zeek-row">
            <span class="zeek-label">Zeek 状态:</span>
            <span :class="'zeek-badge ' + (zeekInfo.installed ? 'ok' : 'na')">
              {{ zeekInfo.installed ? '已安装' : '未安装' }}
            </span>
            <span v-if="zeekInfo.version" class="zeek-version">{{ zeekInfo.version }}</span>
          </div>
          <div class="zeek-row">
            <span class="zeek-label">抓包状态:</span>
            <span :class="'zeek-badge ' + (zeekInfo.running ? 'ok' : 'na')">
              {{ zeekInfo.running ? '运行中' : '已停止' }}
            </span>
            <span v-if="zeekInfo.running" class="zeek-iface">接口: {{ zeekInfo.interface }}</span>
          </div>
          <div class="zeek-row">
            <span class="zeek-label">Zeek 路径:</span>
            <span class="zeek-path">{{ zeekInfo.zeek_path || '未找到' }}</span>
          </div>
          <div class="zeek-row">
            <span class="zeek-label">日志目录:</span>
            <span class="zeek-path">{{ zeekInfo.log_dir || '未设置' }}</span>
          </div>
        </div>
        <div class="zeek-actions">
          <div class="zeek-iface-select" v-if="!zeekInfo.running">
            <label>监听的网络接口:</label>
            <div class="iface-row">
              <select v-model="selectedCaptureIface">
                <option value="">自动选择</option>
                <option v-for="iface in collectorIfaces" :key="iface" :value="iface">{{ iface }}</option>
              </select>
              <button class="btn-refresh" @click="refreshCollectorIfaces">刷新</button>
            </div>
          </div>
          <div class="zeek-btn-row">
            <button class="btn-start"
              @click="startZeekCapture"
              :disabled="zeekInfo.running || zeekBusy">
              {{ zeekBusy ? '启动中...' : '启动抓包' }}
            </button>
            <button class="btn-stop"
              @click="stopZeekCapture"
              :disabled="!zeekInfo.running || zeekBusy">
              {{ zeekBusy ? '停止中...' : '停止抓包' }}
            </button>
            <button class="btn-analyze"
              @click="analyzeZeekLogs"
              :disabled="zeekBusy">
              分析 Zeek 日志
            </button>
            <button class="btn-refresh" @click="fetchZeekStatus">刷新状态</button>
          </div>
          <div class="zeek-result" v-if="zeekMsg">
            <span :class="zeekMsgOk ? 'ok' : 'fail'">{{ zeekMsg }}</span>
          </div>
        </div>
      </div>
      <p class="hint">
        Zeek 是一个开源网络流量分析框架。启动后会自动抓取指定接口的流量并生成结构化日志，
        本系统将实时解析并分析。Windows 用户请在 WSL/Linux 虚拟机中运行 Zeek。
        <a href="https://zeek.org" target="_blank">安装指南</a>
      </p>
    </div>

    <div class="section">
      <h3>AI 智能分析配置</h3>
      <div class="ai-form">
        <div class="form-row">
          <div class="fg">
            <label>提供商</label>
            <select v-model="llmConfig.provider">
              <option value="ollama">Ollama (本地)</option>
              <option value="openai">OpenAI 兼容</option>
            </select>
          </div>
          <div class="fg flex-2">
            <label>API 地址</label>
            <input v-model="llmConfig.api_url" placeholder="http://localhost:11434" />
          </div>
        </div>
        <div class="form-row">
          <div class="fg flex-2">
            <label>API Key <small>(OpenAI 必填，Ollama 留空)</small></label>
            <div class="key-row">
              <input :type="showKey ? 'text' : 'password'" v-model="llmConfig.api_key" placeholder="sk-xxxxx" />
              <button class="btn-eye" @click="showKey = !showKey">{{ showKey ? '👁' : '👁‍🗨' }}</button>
            </div>
          </div>
          <div class="fg">
            <label>模型名称</label>
            <div class="model-row">
              <select v-if="availableModels.length > 0" v-model="llmConfig.model" class="model-select">
                <option v-for="m in availableModels" :key="m" :value="m">{{ m }}</option>
              </select>
              <input v-model="llmConfig.model" :placeholder="llmConfig.provider==='ollama'?'qwen2.5:3b':'gpt-4o-mini'" />
            </div>
            <small v-if="availableModels.length > 0" class="model-hint">可用模型: {{ availableModels.join(', ') }}</small>
          </div>
        </div>
        <div class="ai-actions">
          <button class="btn-test" @click="testLLM" :disabled="testing">
            {{ testing ? '测试中...' : '测试连接' }}
          </button>
          <span class="test-result" :class="{ ok: testOk, fail: !testOk && testDone }">
            {{ testMsg }}
          </span>
          <button class="btn-save" @click="saveLLM" :disabled="saving">
            {{ saving ? '保存中...' : '保存配置' }}
          </button>
        </div>
        <p class="hint">支持 Ollama 本地部署以及任何 OpenAI 兼容 API（如学校提供的 ChatGPT 代理地址）。API Key 仅保存在本地服务器上。</p>
      </div>
    </div>

    <div class="section">
      <h3>系统信息</h3>
      <div class="grid-2">
        <div class="info"><label>后端框架</label><span>Flask 3.0</span></div>
        <div class="info"><label>前端框架</label><span>Vue 3 + ECharts 5</span></div>
        <div class="info"><label>IDS 检测引擎</label><span>规则匹配 + 滑动窗口</span></div>
        <div class="info"><label>IPS 防御引擎</label><span>Linux Netfilter 内核模块</span></div>
        <div class="info"><label>检测规则</label><span>端口扫描 / 暴力登录 / 高频 / 可疑路径 / 状态码</span></div>
        <div class="info"><label>防御规则</label><span>IP / 端口 / 协议 / 动作</span></div>
        <div class="info"><label>数据格式</label><span>CSV (检测) + 字符设备ioctl (防御)</span></div>
        <div class="info"><label>运行环境</label><span>Linux (完整) / Windows (检测)</span></div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  name: 'SettingsPage',
  data() {
    return {
      interfaces: [],
      selectedIface: '',
      thresholds: [
        { name: 'port_scan', label: '端口扫描', value: 5, window: 60 },
        { name: 'brute_force', label: '暴力登录', value: 5, window: 120 },
        { name: 'high_freq', label: '高频访问', value: 20, window: 60 },
        { name: 'abnormal_status', label: '异常状态码', value: 8, window: '-' },
      ],
      llmConfig: { provider: 'ollama', api_url: 'http://localhost:11434', api_key: '', model: 'qwen2.5:3b' },
      showKey: false, testing: false, saving: false,
      testOk: false, testDone: false, testMsg: '',
      availableModels: [],
      zeekInfo: { installed: false, zeek_path: '', version: '', log_dir: '', running: false, interface: '' },
      collectorIfaces: [],
      selectedCaptureIface: '',
      zeekBusy: false,
      zeekMsg: '',
      zeekMsgOk: false,
    }
  },
  methods: {
    async refreshIfaces() {
      try {
        const { data } = await axios.get('/api/interfaces')
        this.interfaces = data.data || []
      } catch (e) {}
    },
    async fetchLLMConfig() {
      try {
        const { data } = await axios.get('/api/llm/config')
        if (data.code === 0) this.llmConfig = { ...this.llmConfig, ...data.data }
      } catch (e) {}
    },
    async testLLM() {
      this.testing = true; this.testDone = false; this.testMsg = ''
      try {
        const [testResp, modelsResp] = await Promise.all([
          axios.post('/api/llm/test', {
            provider: this.llmConfig.provider,
            api_url: this.llmConfig.api_url,
            api_key: this.llmConfig.api_key,
            model: this.llmConfig.model,
          }),
          axios.get('/api/llm/models'),
        ])
        const r = testResp.data.data
        this.testOk = r.ok
        this.testDone = true
        this.availableModels = modelsResp.data.data || r.available_models || []
        if (r.ok) {
          this.testMsg = `连接成功: ${r.provider} / ${r.model}${r.hint ? ' (' + r.hint + ')' : ''}`
        } else {
          this.testMsg = `连接失败: ${r.error}`
        }
      } catch (e) {
        this.testOk = false; this.testDone = true; this.testMsg = '请求失败'
      }
      this.testing = false
    },
    async saveLLM() {
      this.saving = true
      try {
        await axios.put('/api/llm/config', {
          provider: this.llmConfig.provider,
          api_url: this.llmConfig.api_url,
          api_key: this.llmConfig.api_key,
          model: this.llmConfig.model,
        })
        alert('AI 配置已保存')
      } catch (e) {
        alert('保存失败')
      }
      this.saving = false
    },
  },
    async fetchZeekStatus() {
      try {
        const { data } = await axios.get('/api/collector/status')
        if (data.code === 0) this.zeekInfo = data.data
      } catch (e) {}
    },
    async refreshCollectorIfaces() {
      try {
        const { data } = await axios.get('/api/collector/interfaces')
        if (data.code === 0) {
          this.collectorIfaces = data.data.interfaces || []
          if (data.data.current_interface) this.selectedCaptureIface = data.data.current_interface
        }
      } catch (e) {}
    },
    async startZeekCapture() {
      this.zeekBusy = true; this.zeekMsg = ''
      try {
        const { data } = await axios.post('/api/collector/start', { interface: this.selectedCaptureIface })
        this.zeekMsgOk = data.code === 0
        this.zeekMsg = data.data.message || (data.code === 0 ? '启动成功' : '启动失败')
        if (data.code === 0) await this.fetchZeekStatus()
      } catch (e) {
        this.zeekMsgOk = false; this.zeekMsg = '请求失败'
      }
      this.zeekBusy = false
    },
    async stopZeekCapture() {
      this.zeekBusy = true; this.zeekMsg = ''
      try {
        const { data } = await axios.post('/api/collector/stop')
        this.zeekMsgOk = data.code === 0
        this.zeekMsg = data.data.message || (data.code === 0 ? '已停止' : '停止失败')
        if (data.code === 0) await this.fetchZeekStatus()
      } catch (e) {
        this.zeekMsgOk = false; this.zeekMsg = '请求失败'
      }
      this.zeekBusy = false
    },
    async analyzeZeekLogs() {
      this.zeekBusy = true; this.zeekMsg = ''
      try {
        const { data } = await axios.post('/api/collector/analyze')
        this.zeekMsgOk = data.code === 0
        if (data.code === 0) {
          const parsed = data.data.events_parsed || 0
          this.zeekMsg = `分析完成: 解析 ${parsed} 个事件，生成了 ${data.data.analysis.alerts.length} 条告警`
        } else {
          this.zeekMsg = data.message || '分析失败'
        }
      } catch (e) {
        this.zeekMsgOk = false; this.zeekMsg = '未找到 Zeek 日志'
      }
      this.zeekBusy = false
    },
  },
  mounted() { this.refreshIfaces(); this.fetchLLMConfig(); this.fetchZeekStatus() },
}
</script>

<style scoped>
.settings { display: flex; flex-direction: column; gap: 18px; max-width: 800px; }
.section {
  background: #fff; border-radius: 8px; padding: 18px; border: 1px solid #e8ecf1;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.section h3 { font-size: 15px; color: #37474f; margin-bottom: 12px; padding-left: 8px; border-left: 3px solid #4fc3f7; }
.grid-3 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.t-item {
  padding: 10px; background: #f8fafc; border: 1px solid #e8ecf1; border-radius: 6px;
}
.t-item label { font-size: 12px; color: #546e7a; display: block; margin-bottom: 4px; }
.t-item label small { color: #90a4ae; font-weight: normal; }
.t-item input { width: 100%; padding: 5px 8px; border: 1px solid #d5dce6; border-radius: 4px; font-size: 13px; }
.hint { font-size: 11px; color: #90a4ae; margin-top: 10px; }
.row { display: flex; gap: 8px; align-items: center; }
.row select { padding: 6px 12px; border: 1px solid #d5dce6; border-radius: 4px; font-size: 13px; }
.row button { padding: 6px 14px; background: #1e88e5; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.info { display: flex; justify-content: space-between; padding: 8px 12px; background: #f8fafc; border-radius: 4px; }
.info label { font-size: 12px; color: #78909c; }
.info span { font-size: 12px; color: #37474f; font-weight: 600; }
.ai-form { display: flex; flex-direction: column; gap: 12px; }
.form-row { display: flex; gap: 12px; }
.form-row .fg { display: flex; flex-direction: column; gap: 3px; }
.form-row .fg.flex-2 { flex: 2; }
.form-row .fg.flex-2 { flex: 2; }
.fg label { font-size: 11px; color: #78909c; }
.fg label small { color: #90a4ae; font-weight: normal; }
.fg input, .fg select {
  padding: 6px 10px; border: 1px solid #d5dce6; border-radius: 4px;
  font-size: 13px; background: #fff; color: #37474f;
}
.key-row { display: flex; gap: 4px; }
.key-row input { flex: 1; }
.btn-eye { padding: 6px 10px; border: 1px solid #d5dce6; border-radius: 4px; background: #fff; cursor: pointer; font-size: 14px; }
.model-row { display: flex; gap: 6px; }
.model-row select { width: 100%; padding: 6px 10px; border: 1px solid #d5dce6; border-radius: 4px; font-size: 13px; background: #fff; }
.model-row input { flex: 1; }
.model-hint { display: block; margin-top: 4px; color: #1565c0; font-size: 11px; }
.ai-actions { display: flex; align-items: center; gap: 12px; }
.btn-test, .btn-save {
  padding: 7px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; color: #fff;
}
.btn-test { background: #7c4dff; }
.btn-save { background: #1e88e5; }
.btn-test:disabled, .btn-save:disabled { opacity: 0.5; cursor: default; }
.test-result { font-size: 12px; }
.test-result.ok { color: #2e7d32; font-weight: 600; }
.test-result.fail { color: #d32f2f; }

/* Zeek 采集器样式 */
.zeek-status { display: flex; flex-direction: column; gap: 12px; }
.zeek-info { display: flex; flex-direction: column; gap: 6px; background: #f8fafc; padding: 12px; border-radius: 6px; }
.zeek-row { display: flex; align-items: center; gap: 8px; font-size: 13px; }
.zeek-label { color: #78909c; min-width: 80px; }
.zeek-badge { padding: 2px 10px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.zeek-badge.ok { background: #e8f5e9; color: #2e7d32; }
.zeek-badge.na { background: #fbe9e7; color: #c62828; }
.zeek-version { color: #546e7a; font-size: 11px; }
.zeek-iface { color: #1565c0; font-size: 12px; }
.zeek-path { color: #546e7a; font-family: monospace; font-size: 12px; }
.zeek-actions { display: flex; flex-direction: column; gap: 10px; }
.zeek-iface-select { display: flex; flex-direction: column; gap: 4px; }
.zeek-iface-select label { font-size: 11px; color: #78909c; }
.iface-row { display: flex; gap: 6px; }
.iface-row select { padding: 5px 10px; border: 1px solid #d5dce6; border-radius: 4px; font-size: 13px; flex: 1; }
.zeek-btn-row { display: flex; gap: 8px; flex-wrap: wrap; }
.btn-start { padding: 7px 16px; background: #2e7d32; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
.btn-stop { padding: 7px 16px; background: #c62828; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
.btn-analyze { padding: 7px 16px; background: #1565c0; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
.btn-refresh { padding: 7px 16px; background: #546e7a; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
.btn-start:disabled, .btn-stop:disabled, .btn-analyze:disabled, .btn-refresh:disabled { opacity: 0.5; cursor: default; }
.zeek-result { padding: 8px 12px; background: #f8fafc; border-radius: 4px; font-size: 12px; }
.zeek-result .ok { color: #2e7d32; }
.zeek-result .fail { color: #c62828; }
</style>
