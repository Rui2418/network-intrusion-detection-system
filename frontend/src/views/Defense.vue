<template>
  <div class="defense-page">
    <div class="top-bar">
      <div class="status-box">
        <span class="dot" :class="{ on: defStatus.enabled }"></span>
        <strong>防火墙: {{ defStatus.enabled ? '已启用' : '已停止' }}</strong>
        <span class="sub">规则: {{ defStatus.rule_count }} | 策略: {{ defStatus.default_policy || 'accept' }}</span>
      </div>
      <div class="actions">
        <button class="btn" :class="defStatus.enabled ? 'btn-stop' : 'btn-start'" @click="toggleFirewall">
          {{ defStatus.enabled ? '停止防火墙' : '启用防火墙' }}
        </button>
      </div>
    </div>

    <div class="stats-bar">
      <div class="mini-card"><span>已检查包</span><strong>{{ fmt(defStats.total_checked) }}</strong></div>
      <div class="mini-card drop"><span>已拦截</span><strong>{{ fmt(defStats.total_dropped) }}</strong></div>
      <div class="mini-card"><span>已放行</span><strong>{{ fmt(defStats.total_accepted) }}</strong></div>
      <div class="mini-card"><span>拦截率</span><strong>{{ defStats.drop_rate }}%</strong></div>
      <button class="btn-clear" @click="clearStats">清零统计</button>
    </div>

    <div class="toolbar">
      <h3>防火墙规则</h3>
      <button class="btn-add" @click="openAdd">+ 添加规则</button>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>优先级</th><th>协议</th><th>源IP</th><th>目的IP</th>
            <th>源端口</th><th>目的端口</th><th>动作</th><th>命中数</th><th>状态</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rules" :key="r.id">
            <td>{{ r.id }}</td><td>{{ r.priority }}</td>
            <td><span class="tag">{{ r.protocol }}</span></td>
            <td>{{ r.saddr || '*' }}</td><td>{{ r.daddr || '*' }}</td>
            <td>{{ r.sport || '*' }}</td><td>{{ r.dport || '*' }}</td>
            <td><span class="tag" :class="r.action==='drop'?'tag-drop':'tag-accept'">{{ r.action.toUpperCase() }}</span></td>
            <td>{{ r.hit_count || 0 }}</td>
            <td>
              <label class="switch"><input type="checkbox" :checked="r.enabled" @change="toggleRule(r)" /><span class="slider"></span></label>
            </td>
            <td>
              <button class="btn-sm" @click="editRule(r)">编辑</button>
              <button class="btn-sm btn-del" @click="delRule(r.id)">删除</button>
            </td>
          </tr>
          <tr v-if="rules.length===0"><td colspan="11" class="empty">暂无规则，点击"添加规则"创建</td></tr>
        </tbody>
      </table>
    </div>

    <div class="modal-overlay" v-if="showModal" @click.self="closeModal">
      <div class="modal">
        <h3>{{ editing ? '编辑规则' : '添加规则' }}</h3>
        <div class="form-grid">
          <div class="fg"><label>优先级</label><input v-model.number="form.priority" type="number" /></div>
          <div class="fg"><label>协议</label><select v-model="form.protocol"><option value="any">任意</option><option value="icmp">ICMP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></div>
          <div class="fg"><label>源IP</label><input v-model="form.saddr" placeholder="空=任意" /></div>
          <div class="fg"><label>目的IP</label><input v-model="form.daddr" placeholder="空=任意" /></div>
          <div class="fg"><label>源端口</label><input v-model.number="form.sport" type="number" placeholder="0=任意" /></div>
          <div class="fg"><label>目的端口</label><input v-model.number="form.dport" type="number" placeholder="0=任意" /></div>
          <div class="fg"><label>动作</label><select v-model="form.action"><option value="drop">DROP</option><option value="accept">ACCEPT</option></select></div>
          <div class="fg"><label>启用</label><select v-model="form.enabled"><option :value="true">是</option><option :value="false">否</option></select></div>
        </div>
        <div class="modal-btns">
          <button class="btn-cancel" @click="closeModal">取消</button>
          <button class="btn-save" @click="saveRule">{{ editing ? '保存' : '添加' }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  name: 'DefensePage',
  data() {
    return {
      defStatus: { enabled: false, rule_count: 0, default_policy: 'accept' },
      defStats: { total_checked: 0, total_dropped: 0, total_accepted: 0, drop_rate: 0 },
      rules: [],
      showModal: false,
      editing: null,
      form: { priority: 100, protocol: 'any', saddr: '', daddr: '', sport: 0, dport: 0, action: 'drop', enabled: true },
    }
  },
  methods: {
    fmt(n) { return n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'K' : String(n) },
    async fetchStatus() {
      try { const { data } = await axios.get('/api/defense/status'); this.defStatus = data.data || this.defStatus } catch (e) {}
    },
    async fetchStats() {
      try { const { data } = await axios.get('/api/defense/stats'); this.defStats = data.data || this.defStats } catch (e) {}
    },
    async fetchRules() {
      try { const { data } = await axios.get('/api/defense/rules'); this.rules = data.data || [] } catch (e) {}
    },
    async toggleFirewall() {
      await axios.post('/api/defense/enable', { enabled: !this.defStatus.enabled })
      await this.fetchStatus()
    },
    async clearStats() {
      await axios.post('/api/defense/stats/clear')
      await this.fetchStats()
    },
    async toggleRule(r) {
      try {
        await axios.put(`/api/defense/rules/${r.id}`, {
          id: r.id, priority: r.priority, protocol: r.protocol_num || ({any:0,icmp:1,tcp:6,udp:17}[r.protocol]||0),
          saddr: r.saddr, daddr: r.daddr, sport: r.sport||0, dport: r.dport||0,
          action: r.action, enabled: !r.enabled,
        })
        r.enabled = !r.enabled
      } catch (e) {}
    },
    async delRule(id) { if (!confirm('确认删除？')) return; await axios.delete(`/api/defense/rules/${id}`); this.fetchRules() },
    openAdd() {
      this.editing = null; this.form = { priority: 100, protocol: 'any', saddr: '', daddr: '', sport: 0, dport: 0, action: 'drop', enabled: true }; this.showModal = true
    },
    editRule(r) {
      this.editing = r; this.form = { priority: r.priority, protocol: r.protocol, saddr: r.saddr, daddr: r.daddr, sport: r.sport||0, dport: r.dport||0, action: r.action, enabled: r.enabled }; this.showModal = true
    },
    async saveRule() {
      const p = { ...this.form, sport: this.form.sport||0, dport: this.form.dport||0 }
      if (this.editing) await axios.put(`/api/defense/rules/${this.editing.id}`, p)
      else await axios.post('/api/defense/rules', p)
      this.showModal = false; this.fetchRules(); this.fetchStatus()
    },
    closeModal() { this.showModal = false },
  },
  mounted() { this.fetchStatus(); this.fetchStats(); this.fetchRules() },
}
</script>

<style scoped>
.defense-page { display: flex; flex-direction: column; gap: 14px; }
.top-bar { display: flex; justify-content: space-between; align-items: center; background: #fff; border-radius: 8px; padding: 14px 18px; border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
.status-box { display: flex; align-items: center; gap: 10px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: #f44336; }
.dot.on { background: #4caf50; box-shadow: 0 0 6px #4caf50; }
.sub { color: #90a4ae; font-size: 12px; }
.btn { padding: 8px 18px; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; color: #fff; }
.btn-start { background: #4caf50; }
.btn-stop { background: #f44336; }
.stats-bar { display: flex; align-items: center; gap: 12px; }
.mini-card { background: #fff; border-radius: 6px; padding: 10px 16px; text-align: center; border: 1px solid #e8ecf1; }
.mini-card span { display: block; font-size: 11px; color: #78909c; }
.mini-card strong { font-size: 20px; color: #455a64; }
.mini-card.drop strong { color: #d32f2f; }
.btn-clear { padding: 5px 12px; border: 1px solid #d5dce6; border-radius: 4px; background: #fff; color: #607d8b; cursor: pointer; font-size: 12px; }
.toolbar { display: flex; justify-content: space-between; align-items: center; }
.toolbar h3 { font-size: 16px; color: #37474f; }
.btn-add { padding: 7px 18px; background: #1e88e5; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; }
.table-wrap { overflow-x: auto; background: #fff; border-radius: 8px; border: 1px solid #e8ecf1; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { padding: 9px 10px; text-align: center; border-bottom: 1px solid #edf1f6; }
th { background: #f8fafc; color: #546e7a; font-weight: 600; }
tr:hover td { background: #f8fafc; }
.tag { padding: 2px 8px; border-radius: 4px; font-size: 11px; background: #e3f2fd; color: #1565c0; }
.tag-drop { background: #ffebee; color: #c62828; }
.tag-accept { background: #e8f5e9; color: #2e7d32; }
.switch { position: relative; display: inline-block; width: 36px; height: 20px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top:0; left:0; right:0; bottom:0; background: #b0bec5; border-radius: 20px; transition: 0.3s; }
.slider::before { content:''; position: absolute; height: 14px; width: 14px; left: 3px; bottom: 3px; background: #fff; border-radius: 50%; transition: 0.3s; }
input:checked + .slider { background: #4caf50; }
input:checked + .slider::before { transform: translateX(16px); }
.btn-sm { padding: 4px 10px; margin: 0 2px; border: none; border-radius: 4px; cursor: pointer; font-size: 11px; color: #fff; background: #1e88e5; }
.btn-del { background: #e53935; }
.empty { color: #90a4ae; padding: 40px; }
.modal-overlay { position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 100; }
.modal { background: #fff; border-radius: 12px; padding: 24px; width: 460px; max-width: 90vw; }
.modal h3 { margin-bottom: 16px; color: #263238; }
.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.fg { display: flex; flex-direction: column; gap: 3px; }
.fg label { font-size: 11px; color: #78909c; }
.fg input, .fg select { padding: 6px 10px; border: 1px solid #d5dce6; border-radius: 4px; font-size: 13px; }
.modal-btns { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
.btn-cancel { padding: 7px 16px; border: 1px solid #b0bec5; border-radius: 6px; background: #fff; color: #607d8b; cursor: pointer; }
.btn-save { padding: 7px 16px; border: none; border-radius: 6px; background: #1e88e5; color: #fff; cursor: pointer; }
</style>
