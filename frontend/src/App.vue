<template>
  <div class="app">
    <header class="header">
      <div class="brand">
        <span class="icon">&#x1F6E1;</span>
        <span class="title">IDS + IPS 统一安全系统</span>
      </div>
      <nav class="nav">
        <router-link to="/" class="nav-link">仪表盘</router-link>
        <router-link to="/monitor" class="nav-link">实时监控</router-link>
        <router-link to="/detect" class="nav-link">入侵检测</router-link>
        <router-link to="/defense" class="nav-link">防御策略</router-link>
        <router-link to="/alerts" class="nav-link">告警列表</router-link>
        <router-link to="/settings" class="nav-link">设置</router-link>
      </nav>
    </header>
    <main class="main">
      <router-view :key="$route.fullPath" />
    </main>
  </div>
</template>

<script>
export default { name: 'App' }
</script>

<style>
.app { min-height: 100vh; display: flex; flex-direction: column; }
.header {
  display: flex; align-items: center; height: 52px; padding: 0 20px;
  background: #1a2436; color: #e0e0e0; flex-shrink: 0;
  box-shadow: 0 1px 4px rgba(0,0,0,0.1);
}
.brand { display: flex; align-items: center; gap: 8px; margin-right: 28px; }
.icon { font-size: 20px; }
.title { font-size: 15px; font-weight: 700; color: #4fc3f7; letter-spacing: 1px; }
.nav { display: flex; gap: 2px; flex: 1; }
.nav-link {
  padding: 7px 18px; text-decoration: none; color: #78909c;
  border-radius: 6px; font-size: 13px; transition: all 0.2s;
}
.nav-link:hover { color: #b0bec5; background: rgba(255,255,255,0.05); }
.nav-link.router-link-active { color: #4fc3f7; background: rgba(79,195,247,0.1); }
.main { flex: 1; padding: 20px; background: #f0f2f5; }
</style>
