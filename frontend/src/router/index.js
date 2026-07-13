import { createRouter, createWebHistory } from 'vue-router'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'Dashboard', component: () => import('../views/Dashboard.vue') },
    { path: '/monitor', name: 'Monitor', component: () => import('../views/Monitor.vue') },
    { path: '/detect', name: 'Detect', component: () => import('../views/Analysis.vue') },
    { path: '/defense', name: 'Defense', component: () => import('../views/Defense.vue') },
    { path: '/alerts', name: 'Alerts', component: () => import('../views/Alerts.vue') },
    { path: '/settings', name: 'Settings', component: () => import('../views/Settings.vue') },
  ],
})
