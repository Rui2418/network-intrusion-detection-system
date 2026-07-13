<template>
  <div class="monitor">
    <div class="top-bar">
      <div class="live-indicator">
        <span class="pulse" :class="{ active: connected }"></span>
        <span class="live-text">{{ connected ? '实时监控中' : '未连接' }}</span>
      </div>
      <div class="counters">
        <span>告警总数: <strong>{{ alerts.length }}</strong></span>
        <span class="sep">|</span>
        <span>高危: <strong class="c-critical">{{ criticalCount }}</strong></span>
        <span class="sep">|</span>
        <span>中危: <strong class="c-high">{{ highCount }}</strong></span>
      </div>
      <div class="controls">
        <select v-model="filterType">
          <option value="">全部类型</option>
          <option value="端口扫描">端口扫描</option>
          <option value="暴力登录">暴力登录</option>
          <option value="异常访问频率">异常访问频率</option>
          <option value="可疑路径访问">可疑路径访问</option>
          <option value="异常状态码">异常状态码</option>
        </select>
        <button @click="paused = !paused">{{ paused ? '恢复' : '暂停' }}</button>
        <button @click="alerts = []">清空</button>
      </div>
    </div>

    <div class="stream" ref="streamEl">
      <div class="alert-row" v-for="(a, i) in filteredAlerts" :key="i"
        :class="'sev-' + (a.level || '低危')">
        <span class="a-time">{{ a.timestamp || '--' }}</span>
        <span class="a-badge" :class="'badge-' + (a.level || '低危')">{{ a.level || '低危' }}</span>
        <span class="a-type">{{ a.alert_type }}</span>
        <span class="a-src">{{ a.source_ip }}</span>
        <span class="a-arrow">→</span>
        <span class="a-target">{{ a.target }}</span>
        <span class="a-detail">{{ a.evidence || a.score }}</span>
      </div>
      <div v-if="filteredAlerts.length === 0" class="empty-stream">
        <div class="empty-icon">📡</div>
        <p>{{ connected ? '等待告警...' : 'WebSocket 未连接，请加载示例数据或上传 CSV' }}</p>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'
import { io } from 'socket.io-client'

export default {
  name: 'MonitorPage',
  data() {
    return {
      alerts: [],
      connected: false,
      paused: false,
      filterType: '',
      socket: null,
      maxAlerts: 300,
    }
  },
  computed: {
    filteredAlerts() {
      if (!this.filterType) return this.alerts
      return this.alerts.filter(a => a.alert_type === this.filterType)
    },
    criticalCount() { return this.alerts.filter(a => a.level === '高危').length },
    highCount() { return this.alerts.filter(a => a.level === '中危').length },
  },
  methods: {
    fetchAlerts() {
      axios.get('/api/alerts/recent', { params: { count: 200 } }).then(({ data }) => {
        if (data.items) {
          this.alerts = data.items.sort((a, b) => b.score - a.score)
        }
      }).catch(() => {})
    },
  },
  mounted() {
    this.fetchAlerts()

    this.socket = io()
    this.socket.on('connect', () => { this.connected = true })
    this.socket.on('ids_update', () => { this.fetchAlerts() })
    this.socket.on('disconnect', () => { this.connected = false })
  },
  beforeUnmount() {
    if (this.socket) this.socket.disconnect()
  },
}
</script>

<style scoped>
.monitor { display: flex; flex-direction: column; gap: 12px; height: calc(100vh - 100px); }
.top-bar {
  display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
  padding: 10px 16px; background: #fff; border-radius: 8px;
  border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.live-indicator { display: flex; align-items: center; gap: 6px; }
.pulse { width: 9px; height: 9px; border-radius: 50%; background: #90a4ae; }
.pulse.active { background: #4caf50; animation: pulse 1.5s infinite; box-shadow: 0 0 6px #4caf50; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.live-text { font-size: 13px; font-weight: 600; color: #37474f; }
.counters { font-size: 12px; color: #607d8b; flex: 1; }
.counters strong { color: #37474f; }
.c-critical { color: #d32f2f !important; }
.c-high { color: #e65100 !important; }
.sep { color: #cfd8dc; margin: 0 2px; }
.controls { display: flex; gap: 6px; align-items: center; }
.controls select, .controls button {
  padding: 4px 10px; font-size: 12px; border: 1px solid #d5dce6;
  border-radius: 4px; background: #fff; color: #455a64; cursor: pointer;
}
.stream {
  flex: 1; overflow-y: auto; background: #fff; border-radius: 8px;
  border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04); padding: 4px;
}
.alert-row {
  display: flex; align-items: center; gap: 10px; padding: 8px 12px;
  border-bottom: 1px solid #f0f3f7; font-size: 12px;
  border-left: 4px solid transparent; transition: background .2s;
}
.alert-row:hover { background: #f8fafc; }
.sev-高危 { border-left-color: #f44336; background: rgba(244,67,54,0.03); }
.sev-中危 { border-left-color: #ff9800; }
.sev-低危 { border-left-color: #4caf50; }
.a-time { color: #90a4ae; min-width: 80px; font-size: 11px; font-family: monospace; }
.a-badge { padding: 1px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; color: #fff; }
.badge-高危 { background: #f44336; }
.badge-中危 { background: #ff9800; }
.badge-低危 { background: #4caf50; }
.a-type { font-weight: 600; color: #37474f; min-width: 80px; }
.a-src { color: #1565c0; font-family: monospace; }
.a-arrow { color: #b0bec5; }
.a-target { color: #546e7a; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.a-detail { color: #90a4ae; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.empty-stream { text-align: center; padding: 60px; color: #90a4ae; }
.empty-icon { font-size: 36px; margin-bottom: 8px; }
</style>
