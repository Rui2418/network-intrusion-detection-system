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
            <input v-model="llmConfig.model" :placeholder="llmConfig.provider==='ollama'?'qwen2.5:3b':'gpt-4o-mini'" />
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
        const { data } = await axios.post('/api/llm/test', {
          provider: this.llmConfig.provider,
          api_url: this.llmConfig.api_url,
          api_key: this.llmConfig.api_key,
          model: this.llmConfig.model,
        })
        const r = data.data
        this.testOk = r.ok
        this.testDone = true
        this.testMsg = r.ok
          ? `连接成功: ${r.provider} / ${r.model}${r.hint ? ' (' + r.hint + ')' : ''}`
          : `连接失败: ${r.error}`
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
  mounted() { this.refreshIfaces(); this.fetchLLMConfig() },
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
</style>
