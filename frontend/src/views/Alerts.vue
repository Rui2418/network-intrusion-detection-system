<template>
  <div class="alerts-page">
    <div class="toolbar">
      <h3>告警列表</h3>
      <div class="filters">
        <select v-model="filterType" @change="fetchAlerts">
          <option value="">全部类型</option>
          <option v-for="type in availableTypes" :key="type" :value="type">{{ type }}</option>
        </select>
        <select v-model="filterSev" @change="fetchAlerts">
          <option value="">全部等级</option>
          <option value="高危">高危</option>
          <option value="中危">中危</option>
          <option value="低危">低危</option>
        </select>
        <button class="btn-export" @click="exportCSV">导出 CSV</button>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>类型</th><th>等级</th><th>分数</th><th>来源IP</th><th>目标</th><th>检测依据</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(a, i) in alerts" :key="i" :class="'row-' + a.level">
            <td><span class="tag" :style="{ background: typeColor(a.alert_type)+'20', color: typeColor(a.alert_type) }">{{ a.alert_type }}</span></td>
            <td><span class="badge" :class="'badge-' + a.level">{{ a.level }}</span></td>
            <td class="td-score">{{ a.score }}</td>
            <td class="td-mono">{{ a.source_ip }}</td>
            <td class="td-mono">{{ a.target }}</td>
            <td class="td-evidence">{{ a.evidence }}</td>
            <td class="td-actions">
              <button class="btn-ai" @click="analyzeAlert(a, i)" :disabled="analyzing === i">
                {{ analyzing === i ? '分析中...' : 'AI 分析' }}
              </button>
              <button class="btn-block" @click="defendAlert(a, i)" :disabled="blocking === i" v-if="a.level === '高危' || a.level === '中危'">
                {{ blocking === i ? '下发中...' : '一键阻断' }}
              </button>
            </td>
          </tr>
          <tr v-if="alerts.length===0"><td colspan="7" class="empty">请先加载日志数据</td></tr>
        </tbody>
      </table>
    </div>
    <div class="footer">共 {{ total }} 条告警</div>

    <div class="modal-overlay" v-if="showModal" @click.self="showModal = false">
      <div class="modal">
        <div class="modal-header">
          <h3>AI 智能分析</h3>
          <span class="modal-badge" :class="'badge-' + analyzeTarget?.level">{{ analyzeTarget?.level }}</span>
        </div>
        <div class="modal-body">
          <div v-if="analyzing !== null" class="loading-ai">AI 正在分析告警，请稍候...</div>
          <div v-else class="ai-result">{{ aiResult }}</div>
        </div>
        <div class="modal-footer">
          <button class="btn-cancel" @click="showModal = false">关闭</button>
          <button class="btn-block" @click="defendFromModal" :disabled="blocking !== null" v-if="analyzeTarget">
            {{ blocking !== null ? '下发中...' : '一键阻断此攻击源' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

const TYPE_COLORS = {
  '端口扫描': '#ff9800', '暴力登录': '#f44336', '异常访问频率': '#e91e63',
  '可疑路径访问': '#9c27b0', '异常状态码': '#2196f3',
}

export default {
  name: 'AlertsPage',
  data() { return { alerts: [], total: 0, filterType: '', filterSev: '', availableTypes: [] } },
  methods: {
    typeColor(t) { return TYPE_COLORS[t] || '#607d8b' },
    async fetchAlerts() {
      const p = {}
      if (this.filterType) p.type = this.filterType
      if (this.filterSev) p.severity = this.filterSev
      try {
        const { data } = await axios.get('/api/alerts', { params: p })
        this.alerts = data.items
        this.total = data.total
        this.availableTypes = Array.from(new Set((data.items || []).map(item => item.alert_type).filter(Boolean)))
      } catch (e) {}
    },
    async analyzeAlert(alert, idx) {
      this.analyzing = idx
      this.analyzeTarget = alert
      this.aiResult = ''
      this.showModal = true
      try {
        const { data } = await axios.post('/api/alerts/analyze', { alert })
        this.aiResult = data.data?.analysis || '分析失败'
      } catch (e) {
        this.aiResult = 'AI 分析请求失败，请检查后端是否运行。'
      }
      this.analyzing = null
    },
    async defendAlert(alert, idx) {
      this.blocking = idx
      try {
        const { data } = await axios.post('/api/alerts/defend', { alert })
        const ok = data.data?.rule_created
        alert._blocked = ok ? '规则已下发' : '下发失败'
        alert._blockedOk = ok
        alert._blockMsg = data.data?.reason || ''
      } catch (e) {
        alert._blocked = '请求失败'
        alert._blockedOk = false
      }
      this.blocking = null
    },
    async defendFromModal() {
      if (!this.analyzeTarget) return
      this.blocking = -1
      try {
        const { data } = await axios.post('/api/alerts/defend', { alert: this.analyzeTarget })
        const ok = data.data?.rule_created
        alert(ok ? 'IPS 防御规则已创建，已下发至内核模块' : '规则生成成功但下发失败（可能内核模块未加载）')
      } catch (e) {
        alert('防御请求失败')
      }
      this.blocking = null
      this.showModal = false
    },
    exportCSV() {
      window.open('/api/alerts/export', '_blank')
    },
  },
  mounted() { this.fetchAlerts() },
}
</script>

<style scoped>
.alerts-page { display: flex; flex-direction: column; gap: 14px; }
.toolbar { display: flex; justify-content: space-between; align-items: center; }
.toolbar h3 { font-size: 17px; color: #37474f; }
.filters { display: flex; gap: 8px; align-items: center; }
.filters select {
  padding: 6px 12px; border: 1px solid #d5dce6; border-radius: 6px;
  background: #fff; font-size: 13px; color: #455a64;
}
.btn-export { padding: 6px 14px; background: #2e7d32; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; }
.table-wrap { overflow-x: auto; background: #fff; border-radius: 8px; border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #edf1f6; }
th { background: #f8fafc; color: #546e7a; font-weight: 600; white-space: nowrap; }
tr:hover td { background: #f8fafc; }
.row-高危 { border-left: 4px solid #f44336; }
.row-中危 { border-left: 4px solid #ff9800; }
.row-低危 { border-left: 4px solid #4caf50; }
.tag { padding: 2px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.badge { padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; }
.badge-高危 { background: #f44336; }
.badge-中危 { background: #ff9800; }
.badge-低危 { background: #4caf50; }
.td-score { font-weight: 700; color: #455a64; }
.td-mono { font-family: 'Consolas', monospace; font-size: 12px; color: #37474f; }
.td-evidence { color: #78909c; font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.td-actions { display: flex; gap: 4px; white-space: nowrap; }
.btn-ai, .btn-block {
  padding: 3px 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 11px; white-space: nowrap;
}
.btn-ai { background: #7c4dff; color: #fff; }
.btn-ai:disabled { opacity: 0.5; cursor: default; }
.btn-block { background: #d32f2f; color: #fff; }
.btn-block:disabled { opacity: 0.5; cursor: default; }
.empty { text-align: center; padding: 40px; color: #90a4ae; }
.footer { text-align: center; font-size: 12px; color: #90a4ae; }

.modal-overlay { position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 100; }
.modal { background: #fff; border-radius: 12px; width: 560px; max-width: 90vw; max-height: 80vh; display: flex; flex-direction: column; }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid #edf1f6; }
.modal-header h3 { font-size: 16px; color: #263238; }
.modal-badge { padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; }
.modal-body { padding: 18px 20px; overflow-y: auto; flex: 1; }
.loading-ai { text-align: center; color: #7c4dff; padding: 30px; font-size: 14px; }
.ai-result { white-space: pre-wrap; line-height: 1.8; font-size: 13px; color: #37474f; }
.modal-footer { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 20px; border-top: 1px solid #edf1f6; }
.btn-cancel { padding: 7px 16px; border: 1px solid #b0bec5; border-radius: 6px; background: #fff; color: #607d8b; cursor: pointer; }
</style>
