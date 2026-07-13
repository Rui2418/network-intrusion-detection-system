<template>
  <div class="analysis-page">
    <div class="hero">
      <div class="hero-text">
        <p class="eyebrow">Network Attack Detection</p>
        <h1>日志分析</h1>
        <p>导入网络访问日志，检测端口扫描、暴力登录、异常访问频率、可疑路径和异常状态码。</p>
      </div>
      <div class="hero-actions">
        <button class="btn btn-primary" @click="loadSample" :disabled="loading">
          {{ loading ? '分析中...' : '加载示例数据' }}
        </button>
        <label class="btn btn-outline">
          上传 CSV
          <input type="file" accept=".csv" @change="uploadFile" />
        </label>
      </div>
    </div>

    <div class="result-summary" v-if="lastResult">
      <div class="summary-card"><span>日志条目</span><strong>{{ lastResult.events }}</strong></div>
      <div class="summary-card high"><span>高危</span><strong>{{ levelCount('高危') }}</strong></div>
      <div class="summary-card medium"><span>中危</span><strong>{{ levelCount('中危') }}</strong></div>
      <div class="summary-card low"><span>低危</span><strong>{{ levelCount('低危') }}</strong></div>
      <div class="summary-card"><span>告警总数</span><strong>{{ lastResult.alerts?.length || 0 }}</strong></div>
    </div>

    <div class="table-wrap" v-if="lastResult">
      <table>
        <thead>
          <tr>
            <th>类型</th><th>等级</th><th>分数</th><th>来源IP</th><th>目标</th><th>检测依据</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(a, i) in lastResult.alerts" :key="i">
            <td><span class="tag">{{ a.alert_type }}</span></td>
            <td><span class="badge" :class="'badge-' + a.level">{{ a.level }}</span></td>
            <td class="td-score">{{ a.score }}</td>
            <td class="td-mono">{{ a.source_ip }}</td>
            <td class="td-mono">{{ a.target }}</td>
            <td class="td-evidence">{{ a.evidence }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  name: 'AnalysisPage',
  data() { return { lastResult: null, loading: false } },
  methods: {
    levelCount(level) {
      const summary = this.lastResult?.summary || {}
      return summary?.by_level?.[level] ?? summary?.[level] ?? 0
    },
    async loadSample() {
      this.loading = true
      try {
        const { data } = await axios.get('/api/sample')
        this.lastResult = data
      } catch (e) {}
      this.loading = false
    },
    async uploadFile(e) {
      const file = e.target.files[0]
      if (!file) return
      this.loading = true
      const fd = new FormData()
      fd.append('file', file)
      try {
        const { data } = await axios.post('/api/analyze', fd)
        this.lastResult = data
      } catch (e) {}
      this.loading = false
      e.target.value = ''
    },
  },
  mounted() {
    this.loadSample()
  },
}
</script>

<style scoped>
.analysis-page { display: flex; flex-direction: column; gap: 16px; }
.hero {
  display: flex; justify-content: space-between; align-items: flex-end; gap: 20px;
  background: #fff; border-radius: 8px; padding: 24px; border: 1px solid #e8ecf1;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.hero-text { flex: 1; }
.eyebrow { font-size: 12px; color: #1e88e5; font-weight: 700; margin-bottom: 4px; }
h1 { font-size: 24px; color: #263238; margin-bottom: 6px; }
.hero-text p { color: #607d8b; font-size: 14px; }
.hero-actions { display: flex; gap: 10px; }
.btn {
  padding: 9px 18px; border-radius: 6px; font-size: 13px; cursor: pointer; border: none; display: inline-flex; align-items: center;
}
.btn-primary { background: #1e88e5; color: #fff; }
.btn-primary:disabled { opacity: 0.6; cursor: default; }
.btn-outline { border: 1px solid #b0bec5; color: #455a64; background: #fff; cursor: pointer; }
.btn-outline input { display: none; }
.result-summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
.summary-card {
  background: #fff; border-radius: 8px; padding: 14px; text-align: center;
  border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.summary-card span { display: block; font-size: 12px; color: #78909c; margin-bottom: 4px; }
.summary-card strong { font-size: 26px; color: #455a64; }
.summary-card.high strong { color: #d32f2f; }
.summary-card.medium strong { color: #e65100; }
.summary-card.low strong { color: #2e7d32; }
.table-wrap { background: #fff; border-radius: 8px; border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04); overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 11px 14px; text-align: left; border-bottom: 1px solid #edf1f6; }
th { background: #f8fafc; color: #546e7a; font-weight: 600; }
tr:hover td { background: #f8fafc; }
.tag { padding: 2px 10px; border-radius: 4px; font-size: 12px; background: #e3f2fd; color: #1565c0; }
.badge { padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; }
.badge-高危 { background: #f44336; }
.badge-中危 { background: #ff9800; }
.badge-低危 { background: #4caf50; }
.td-score { font-weight: 700; color: #455a64; }
.td-mono { font-family: 'Consolas', monospace; font-size: 12px; color: #37474f; }
.td-evidence { color: #78909c; font-size: 12px; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
