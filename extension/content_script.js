// Arca Shield Content Script: Detección activa en DOM y bloqueo de autocompletado

let isPhishingThreat = false;
let currentThreatData = null;

function blockAutofillAndInputs() {
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const userInputs = document.querySelectorAll('input[type="email"], input[type="text"], input[name*="user"], input[name*="login"]');
  const forms = document.querySelectorAll('form');

  forms.forEach((form) => {
    form.setAttribute('autocomplete', 'off');
  });

  passwordInputs.forEach((input) => {
    input.setAttribute('autocomplete', 'new-password');
    input.setAttribute('data-arca-shield-blocked', 'true');
    input.style.border = '2px solid #ef4444';
    input.title = 'Arca Shield: Autocompletado bloqueado por riesgo de phishing.';

    // Advertencia en tiempo real al hacer foco
    input.addEventListener('focus', () => {
      if (isPhishingThreat) {
        showFloatingBanner(currentThreatData, true);
      }
    });
  });

  userInputs.forEach((input) => {
    input.setAttribute('autocomplete', 'off');
  });
}

function showFloatingBanner(threatData, shake = false) {
  if (document.getElementById('arca-shield-banner')) {
    if (shake) {
      const banner = document.getElementById('arca-shield-banner');
      banner.style.animation = 'none';
      banner.offsetHeight; // trigger reflow
      banner.style.animation = 'arca-shake 0.5s ease';
    }
    return;
  }

  const banner = document.createElement('div');
  banner.id = 'arca-shield-banner';
  banner.innerHTML = `
    <style>
      #arca-shield-banner {
        position: fixed;
        top: 16px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 2147483647;
        background: #0f172a;
        color: #f8fafc;
        border: 2px solid #ef4444;
        border-radius: 12px;
        padding: 14px 20px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8), 0 0 25px rgba(239, 68, 68, 0.4);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        max-width: 680px;
        width: 90%;
        display: flex;
        align-items: flex-start;
        gap: 14px;
        line-height: 1.4;
        animation: arca-slide-down 0.3s ease-out;
      }
      @keyframes arca-slide-down {
        from { transform: translate(-50%, -30px); opacity: 0; }
        to { transform: translate(-50%, 0); opacity: 1; }
      }
      @keyframes arca-shake {
        0%, 100% { transform: translate(-50%, 0); }
        20%, 60% { transform: translate(calc(-50% - 8px), 0); }
        40%, 80% { transform: translate(calc(-50% + 8px), 0); }
      }
      #arca-shield-banner .arca-icon {
        font-size: 26px;
        line-height: 1;
        flex-shrink: 0;
      }
      #arca-shield-banner .arca-content {
        flex: 1;
      }
      #arca-shield-banner .arca-title {
        font-size: 15px;
        font-weight: 700;
        color: #ef4444;
        margin-bottom: 4px;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      #arca-shield-banner .arca-desc {
        font-size: 13px;
        color: #cbd5e1;
        margin-bottom: 10px;
      }
      #arca-shield-banner .arca-blocked-tag {
        display: inline-block;
        background: rgba(239, 68, 68, 0.2);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.4);
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        margin-bottom: 8px;
      }
      #arca-shield-banner .arca-actions {
        display: flex;
        gap: 10px;
        align-items: center;
      }
      #arca-shield-banner .arca-btn-dismiss {
        background: transparent;
        color: #94a3b8;
        border: 1px solid #334155;
        padding: 6px 12px;
        border-radius: 6px;
        font-size: 12px;
        cursor: pointer;
        transition: all 0.2s;
      }
      #arca-shield-banner .arca-btn-dismiss:hover {
        background: #1e293b;
        color: #f8fafc;
      }
      #arca-shield-banner .arca-btn-vault {
        background: #ef4444;
        color: #ffffff;
        border: none;
        padding: 6px 14px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
      }
      #arca-shield-banner .arca-btn-vault:hover {
        background: #dc2626;
      }
    </style>
    <div class="arca-icon">🚨</div>
    <div class="arca-content">
      <div class="arca-title">
        <span>Arca Shield — Alerta de Phishing / Suplantación</span>
      </div>
      <div class="arca-desc">
        ${threatData?.description || 'Este sitio web presenta patrones de suplantación contra servicios legítimos conocidos.'}
      </div>
      <div class="arca-blocked-tag">
        🔒 Autocompletado de contraseñas bloqueado por seguridad
      </div>
      <div class="arca-actions">
        <button class="arca-btn-dismiss" id="arca-close-btn">Entendido (Cerrar aviso)</button>
        <button class="arca-btn-vault" id="arca-vault-btn">Abrir Bóveda Segura</button>
      </div>
    </div>
  `;

  document.body.appendChild(banner);

  document.getElementById('arca-close-btn')?.addEventListener('click', () => {
    banner.remove();
  });

  document.getElementById('arca-vault-btn')?.addEventListener('click', () => {
    window.open('http://localhost:5173', '_blank');
  });
}

// Escuchar alertas provenientes del background service worker
chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'PHISHING_ALERT') {
    isPhishingThreat = true;
    currentThreatData = message.data;
    blockAutofillAndInputs();
    showFloatingBanner(message.data);
  }
});

// Comprobar estado al cargar la página
chrome.runtime.sendMessage({ action: 'GET_CURRENT_SECURITY_REPORT' }, (response) => {
  if (response && response.riskLevel === 'danger') {
    isPhishingThreat = true;
    currentThreatData = response;
    blockAutofillAndInputs();
    showFloatingBanner(response);
  }
});
