const sampleBtn = document.querySelector('#sampleBtn');
const fileInput = document.querySelector('#fileInput');
const statusText = document.querySelector('#statusText');
const alertBody = document.querySelector('#alertBody');

sampleBtn.addEventListener('click', async () => {
  statusText.textContent = '正在分析示例数据';
  const response = await fetch('/api/sample');
  renderResult(await response.json());
});

fileInput.addEventListener('change', async () => {
  const file = fileInput.files[0];
  if (!file) return;

  statusText.textContent = '正在分析上传日志';
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch('/api/analyze', {
    method: 'POST',
    body: formData,
  });
  renderResult(await response.json());
});

function renderResult(result) {
  if (result.error) {
    statusText.textContent = result.error;
    return;
  }

  document.querySelector('#eventCount').textContent = result.events;
  document.querySelector('#highCount').textContent = result.summary['高危'] || 0;
  document.querySelector('#mediumCount').textContent = result.summary['中危'] || 0;
  document.querySelector('#lowCount').textContent = result.summary['低危'] || 0;
  statusText.textContent = `发现 ${result.alerts.length} 条告警`;

  if (result.alerts.length === 0) {
    alertBody.innerHTML = '<tr><td colspan="6" class="empty">未发现告警</td></tr>';
    return;
  }

  alertBody.innerHTML = result.alerts.map(alert => `
    <tr>
      <td>${escapeHtml(alert.alert_type)}</td>
      <td>${escapeHtml(alert.source_ip)}</td>
      <td>${escapeHtml(alert.target)}</td>
      <td>${escapeHtml(alert.level)}</td>
      <td>${alert.score}</td>
      <td>${escapeHtml(alert.evidence)}</td>
    </tr>
  `).join('');
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
