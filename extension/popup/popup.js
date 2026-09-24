// Script de control para la ventana emergente de Arca Shield

document.addEventListener('DOMContentLoaded', () => {
  const statusPill = document.getElementById('status-pill');
  const siteDomain = document.getElementById('site-domain');
  const siteProtocol = document.getElementById('site-protocol');
  const threatSection = document.getElementById('threat-section');
  const threatTitle = document.getElementById('threat-title');
  const threatDesc = document.getElementById('threat-desc');
  const safeSection = document.getElementById('safe-section');
  const openVaultBtn = document.getElementById('open-vault-btn');

  openVaultBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:5173' });
  });

  chrome.runtime.sendMessage({ action: 'GET_CURRENT_SECURITY_REPORT' }, (report) => {
    if (!report) {
      siteDomain.textContent = 'Sin pestaña activa';
      statusPill.textContent = 'Inactivo';
      return;
    }

    siteDomain.textContent = report.hostname || 'Página Interna';
    siteProtocol.textContent = report.isSecure ? '🔒 Protocolo HTTPS Cifrado' : '⚠️ Protocolo HTTP Sin Cifrar';

    if (report.riskLevel === 'danger') {
      statusPill.textContent = 'Peligro';
      statusPill.className = 'status-pill status-pill--danger';

      threatSection.classList.remove('hidden');
      safeSection.classList.add('hidden');

      threatTitle.textContent = report.title || 'Alerta de Phishing';
      threatDesc.textContent = report.description || 'Se detectaron indicios de suplantación de identidad.';
    } else if (report.riskLevel === 'warning') {
      statusPill.textContent = 'Inseguro';
      statusPill.className = 'status-pill status-pill--warning';

      threatSection.classList.remove('hidden');
      safeSection.classList.add('hidden');

      threatTitle.textContent = report.title || 'Conexión Insegura';
      threatDesc.textContent = report.description || 'El tráfico viaja en texto plano sin cifrado HTTPS.';
    } else if (report.riskLevel === 'safe') {
      statusPill.textContent = 'Seguro';
      statusPill.className = 'status-pill status-pill--safe';

      threatSection.classList.add('hidden');
      safeSection.classList.remove('hidden');
    } else {
      statusPill.textContent = 'Interno';
      statusPill.className = 'status-pill status-pill--checking';
      threatSection.classList.add('hidden');
      safeSection.classList.add('hidden');
    }
  });
});
