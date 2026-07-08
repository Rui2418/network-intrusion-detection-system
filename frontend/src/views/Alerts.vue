<template>
  <div class="alerts-page">
    <div class="toolbar">
      <h3>告警列表</h3>
      <div class="filters">
        <select v-model="filterType" @change="fetchAlerts">
          <option value="">全部类型</option>
          <option value="端口扫描">端口扫描</option>
          <option value="暴力登录">暴力登录</option>
          <option value="异常访问频率">异常访问频率</option>
          <option value="可疑路径访问">可疑路径访问</option>
          <option value="异常状态码">异常状态码</option>
        </select>
        <select v-model="filterSev" @change="fetchAlerts">
          <option value="">全部等级</option>
          <option value="高危">高危</option>
          <option value="中危">中危</option>
          <option value="低危">低危</option>
        </select>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>类型</th>
            <th>等级</th>
            <th>分数</th>
            <th>来源IP</th>
            <th>目标</th>
            <th>检测依据</th>
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
          </tr>
          <tr v-if="alerts.length===0"><td colspan="6" class="empty">请先加载日志数据</td></tr>
        </tbody>
      </table>
    </div>
    <div class="footer">共 {{ total }} 条告警</div>
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
  data() { return { alerts: [], total: 0, filterType: '', filterSev: '' } },
  methods: {
    typeColor(t) { return TYPE_COLORS[t] || '#607d8b' },
    async fetchAlerts() {
      const p = {}
      if (this.filterType) p.type = this.filterType
      if (this.filterSev) p.severity = this.filterSev
      try {
        const { data } = await axios.get('/api/alerts', { params: p })
        this.alerts = data.items; this.total = data.total
      } catch (e) {}
    },
  },
  mounted() { this.fetchAlerts() },
}
</script>

<style scoped>
.alerts-page { display: flex; flex-direction: column; gap: 14px; }
.toolbar { display: flex; justify-content: space-between; align-items: center; }
.toolbar h3 { font-size: 17px; color: #37474f; }
.filters { display: flex; gap: 8px; }
.filters select {
  padding: 6px 12px; border: 1px solid #d5dce6; border-radius: 6px;
  background: #fff; font-size: 13px; color: #455a64;
}
.table-wrap { overflow-x: auto; background: #fff; border-radius: 8px; border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #edf1f6; }
th { background: #f8fafc; color: #546e7a; font-weight: 600; }
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
.td-evidence { color: #78909c; font-size: 12px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.empty { text-align: center; padding: 40px; color: #90a4ae; }
.footer { text-align: center; font-size: 12px; color: #90a4ae; }
</style>
