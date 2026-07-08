<template>
  <div class="dash">
    <div class="section-title">&#x1F4CA; IDS 入侵检测概览</div>
    <div class="stat-row">
      <div class="card">
        <div class="card-label">日志总量</div>
        <div class="card-value">{{ ids.events || 0 }}</div>
      </div>
      <div class="card high"><div class="card-label">高危</div><div class="card-value">{{ ids.summary?.高危 || 0 }}</div></div>
      <div class="card medium"><div class="card-label">中危</div><div class="card-value">{{ ids.summary?.中危 || 0 }}</div></div>
      <div class="card low"><div class="card-label">低危</div><div class="card-value">{{ ids.summary?.低危 || 0 }}</div></div>
      <div class="card"><div class="card-label">总告警</div><div class="card-value">{{ ids.total_alerts || 0 }}</div></div>
      <div class="card"><div class="card-label">平均分</div><div class="card-value">{{ ids.avg_score || 0 }}</div></div>
    </div>

    <div class="charts-row">
      <div class="chart-panel"><div class="panel-title">攻击类型分布</div><div ref="pieChart" class="cbox"></div></div>
      <div class="chart-panel"><div class="panel-title">严重程度</div><div ref="sevChart" class="cbox"></div></div>
      <div class="chart-panel"><div class="panel-title">Top 攻击来源</div><div ref="barChart" class="cbox"></div></div>
    </div>

    <hr class="divider" />

    <div class="section-title">&#x1F6E1; IPS 防御策略状态</div>
    <div class="stat-row">
      <div class="card" :class="{ active: ips.status.enabled, stopped: !ips.status.enabled }">
        <div class="card-label">防火墙状态</div>
        <div class="card-value">{{ ips.status.enabled ? '已启用' : '已停止' }}</div>
      </div>
      <div class="card"><div class="card-label">活跃规则</div><div class="card-value">{{ ips.status.rule_count || 0 }}</div></div>
      <div class="card"><div class="card-label">运行时长</div><div class="card-value">{{ fmtTime(ips.status.uptime_seconds || 0) }}</div></div>
      <div class="card drop"><div class="card-label">已拦截包</div><div class="card-value">{{ fmtNum(ips.stats.total_dropped || 0) }}</div></div>
      <div class="card"><div class="card-label">已检查包</div><div class="card-value">{{ fmtNum(ips.stats.total_checked || 0) }}</div></div>
      <div class="card"><div class="card-label">拦截率</div><div class="card-value">{{ ips.stats.drop_rate || 0 }}%</div></div>
    </div>

    <div class="charts-row">
      <div class="chart-panel"><div class="panel-title">协议分布 (ICMP/TCP/UDP)</div><div ref="protoChart" class="cbox-sm"></div></div>
      <div class="chart-panel"><div class="panel-title">{{ ips.availability === 'available' ? '内核模块已连接' : '内核模块未加载 (模拟)' }}</div>
        <div style="padding: 40px; text-align: center; color: #78909c;">
          {{ ips.availability === 'available' ? '✅ Linux IPS 内核模块正常运行中' : '⚠ 未检测到 /dev/firewall 设备，\n防御功能以模拟模式运行' }}
        </div>
      </div>
    </div>

    <div class="refresh-bar">
      <button @click="refreshAll" :disabled="loading">{{ loading ? '刷新中...' : '刷新数据' }}</button>
      <span class="note">仪表盘每 5 秒自动刷新</span>
    </div>
  </div>
</template>

<script>
import * as echarts from 'echarts'
import axios from 'axios'

const TCOLORS = { '端口扫描':'#ff9800','暴力登录':'#f44336','异常访问频率':'#e91e63','可疑路径访问':'#9c27b0','异常状态码':'#2196f3' }
const SCOLORS = { '高危':'#f44336','中危':'#ff9800','低危':'#4caf50' }

export default {
  name: 'Dashboard',
  data() {
    return {
      ids: { events: 0, summary: {}, total_alerts: 0, avg_score: 0, type_counts: {}, severity_counts: {}, top_sources: [] },
      ips: { status: { enabled: false, rule_count: 0, uptime_seconds: 0 }, stats: { total_checked: 0, total_dropped: 0, total_accepted: 0, drop_rate: 0, protocols: {} }, availability: 'checking' },
      loading: false,
    }
  },
  methods: {
    fmtNum(n) { return n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'K' : String(n) },
    fmtTime(s) { s = parseInt(s); const m = Math.floor(s/60); return m > 0 ? `${m}m ${s%60}s` : `${s}s` },
    initCharts() {
      this.pieChart = echarts.init(this.$refs.pieChart)
      this.sevChart = echarts.init(this.$refs.sevChart)
      this.barChart = echarts.init(this.$refs.barChart)
      this.protoChart = echarts.init(this.$refs.protoChart)
    },
    updateCharts() {
      const tc = this.ids.type_counts || {}
      const pd = Object.entries(tc).map(([k,v]) => ({ value: v, name: k, itemStyle: { color: TCOLORS[k] || '#607d8b' } }))
      this.pieChart?.setOption({
        tooltip: { trigger: 'item' },
        series: [{ type: 'pie', radius: ['45%','72%'], center: ['50%','55%'], label: { fontSize: 11 }, data: pd.length ? pd : [{ value: 1, name: '暂无', itemStyle: { color: '#ddd' } }] }],
      })

      const sc = this.ids.severity_counts || {}
      this.sevChart?.setOption({
        tooltip: { trigger: 'item' },
        series: [{ type: 'pie', radius: ['40%','68%'], center: ['50%','55%'], label: { fontSize: 11 }, data: Object.entries(sc).filter(([,v]) => v>0).map(([k,v]) => ({ value: v, name: k, itemStyle: { color: SCOLORS[k] } })) }],
      })

      const ts = this.ids.top_sources || []
      this.barChart?.setOption({
        tooltip: { trigger: 'axis' },
        grid: { top: 10, right: 20, bottom: 20, left: 60 },
        xAxis: { type: 'value' },
        yAxis: { type: 'category', data: ts.map(s=>s.ip).reverse(), inverse: true },
        series: [{ type: 'bar', data: ts.map(s=>s.count).reverse(), barWidth: 14, itemStyle: { color: new echarts.graphic.LinearGradient(0,0,1,0,[{offset:0,color:'#f44336'},{offset:1,color:'#ff7043'}]) } }],
      })

      const proto = this.ips.stats.protocols || {}
      this.protoChart?.setOption({
        tooltip: { trigger: 'item' },
        series: [{ type: 'pie', radius: ['45%','70%'], center: ['50%','55%'], label: { fontSize: 11 }, data: [
          { value: proto.icmp||0, name: 'ICMP', itemStyle: { color: '#ff9800' } },
          { value: proto.tcp||0, name: 'TCP', itemStyle: { color: '#2196f3' } },
          { value: proto.udp||0, name: 'UDP', itemStyle: { color: '#9c27b0' } },
        ] }],
      })
    },
    async refreshAll() {
      this.loading = true
      try {
        const { data } = await axios.get('/api/dashboard')
        this.ids = data.ids || this.ids
        this.ips = data.ips || this.ips
        this.$nextTick(() => this.updateCharts())
      } catch (e) {}
      this.loading = false
    },
  },
  mounted() {
    this.initCharts()
    this.refreshAll()
    this._timer = setInterval(() => this.refreshAll(), 5000)
    window.addEventListener('resize', () => Object.values(this).filter(v => v?.resize).forEach(c => c.resize()))
  },
  beforeUnmount() { clearInterval(this._timer) },
}
</script>

<style scoped>
.dash { display: flex; flex-direction: column; gap: 14px; }
.section-title { font-size: 15px; font-weight: 700; color: #37474f; padding: 6px 0; }
.stat-row { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; }
.card {
  background: #fff; border-radius: 8px; padding: 14px; text-align: center;
  border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.card.active { border-color: #4caf50; }
.card.stopped { border-color: #f44336; }
.card-label { font-size: 11px; color: #78909c; margin-bottom: 4px; }
.card-value { font-size: 24px; font-weight: 700; color: #455a64; }
.card.high .card-value { color: #d32f2f; }
.card.medium .card-value { color: #e65100; }
.card.low .card-value { color: #2e7d32; }
.card.drop .card-value { color: #d32f2f; }
.card.active .card-value { color: #2e7d32; }
.charts-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.chart-panel {
  background: #fff; border-radius: 8px; padding: 14px;
  border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.panel-title { font-size: 12px; color: #546e7a; margin-bottom: 8px; padding-left: 8px; border-left: 3px solid #4fc3f7; }
.cbox { width: 100%; height: 250px; }
.cbox-sm { width: 100%; height: 200px; }
.divider { border: none; border-top: 2px solid #e0e4ea; margin: 4px 0; }
.refresh-bar { display: flex; align-items: center; gap: 12px; }
.refresh-bar button {
  padding: 7px 18px; background: #1e88e5; color: #fff; border: none;
  border-radius: 6px; cursor: pointer; font-size: 13px;
}
.refresh-bar button:disabled { opacity: 0.5; }
.note { font-size: 12px; color: #90a4ae; }
</style>
