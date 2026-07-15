const state = {
  token: localStorage.getItem('grade_token') || '',
  user: null,
  grades: [],
}

const el = (id) => document.getElementById(id)

function authHeaders() {
  return state.token ? { Authorization: `Bearer ${state.token}` } : {}
}

function setMessage(target, text, ok = false) {
  target.textContent = text || ''
  target.classList.toggle('success', Boolean(ok))
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  })
  const data = await response.json().catch(() => ({ code: 1, message: '服务返回异常' }))
  if (!response.ok || data.code !== 0) {
    throw new Error(data.message || '请求失败')
  }
  return data.data
}

function showLogin() {
  el('loginPanel').classList.remove('hidden')
  el('workspace').classList.add('hidden')
  el('logoutBtn').classList.add('hidden')
}

function showWorkspace() {
  el('loginPanel').classList.add('hidden')
  el('workspace').classList.remove('hidden')
  el('logoutBtn').classList.remove('hidden')
}

function renderUser() {
  const user = state.user
  el('currentName').textContent = user ? `${user.name}（${user.role === 'teacher' ? '教师' : '学生'}）` : '-'
  el('currentMeta').textContent = user && user.role === 'student'
    ? `${user.student_id} · ${user.class_name}`
    : '可查看、登记和修改全部学生成绩'
  el('teacherPanel').classList.toggle('hidden', !user || user.role !== 'teacher')
  el('filterBox').classList.toggle('hidden', !user || user.role !== 'teacher')
}

function renderGrades() {
  const body = el('gradesBody')
  body.innerHTML = ''

  if (state.grades.length === 0) {
    const row = document.createElement('tr')
    row.innerHTML = '<td class="empty-row" colspan="5">暂无成绩记录</td>'
    body.appendChild(row)
  } else {
    for (const item of state.grades) {
      const row = document.createElement('tr')
      row.innerHTML = `
        <td>${item.student_id}</td>
        <td>${item.student_name}</td>
        <td>${item.class_name}</td>
        <td>${item.course}</td>
        <td><span class="score-pill">${item.score}</span></td>
      `
      body.appendChild(row)
    }
  }

  el('gradeTotal').textContent = state.grades.length
  const avg = state.grades.length
    ? Math.round((state.grades.reduce((sum, item) => sum + Number(item.score || 0), 0) / state.grades.length) * 10) / 10
    : 0
  el('avgScore').textContent = avg
}

async function loadGrades(studentId = '') {
  const query = studentId ? `?student_id=${encodeURIComponent(studentId)}` : ''
  const data = await requestJson(`/api/grades${query}`, { headers: authHeaders() })
  state.grades = data.items || []
  renderGrades()
}

async function restoreSession() {
  if (!state.token) {
    showLogin()
    return
  }

  try {
    state.user = await requestJson('/api/me', { headers: authHeaders() })
    renderUser()
    showWorkspace()
    await loadGrades()
  } catch (error) {
    localStorage.removeItem('grade_token')
    state.token = ''
    state.user = null
    showLogin()
  }
}

el('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault()
  setMessage(el('loginMessage'), '')
  const payload = {
    username: el('username').value.trim(),
    password: el('password').value,
  }

  try {
    const data = await requestJson('/api/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    state.token = data.token
    state.user = data.user
    localStorage.setItem('grade_token', state.token)
    renderUser()
    showWorkspace()
    await loadGrades()
  } catch (error) {
    setMessage(el('loginMessage'), error.message)
  }
})

el('logoutBtn').addEventListener('click', async () => {
  try {
    await requestJson('/api/logout', {
      method: 'POST',
      headers: authHeaders(),
      body: '{}',
    })
  } finally {
    localStorage.removeItem('grade_token')
    state.token = ''
    state.user = null
    state.grades = []
    showLogin()
  }
})

el('gradeForm').addEventListener('submit', async (event) => {
  event.preventDefault()
  setMessage(el('gradeMessage'), '')
  const payload = {
    student_id: el('studentId').value.trim(),
    course: el('course').value.trim(),
    score: el('score').value,
  }

  try {
    await requestJson('/api/grades', {
      method: 'PUT',
      headers: authHeaders(),
      body: JSON.stringify(payload),
    })
    setMessage(el('gradeMessage'), '保存成功', true)
    el('gradeForm').reset()
    await loadGrades(el('filterStudentId').value.trim())
  } catch (error) {
    setMessage(el('gradeMessage'), error.message)
  }
})

el('filterBtn').addEventListener('click', () => {
  loadGrades(el('filterStudentId').value.trim()).catch((error) => setMessage(el('gradeMessage'), error.message))
})

el('resetFilterBtn').addEventListener('click', () => {
  el('filterStudentId').value = ''
  loadGrades().catch((error) => setMessage(el('gradeMessage'), error.message))
})

restoreSession()
