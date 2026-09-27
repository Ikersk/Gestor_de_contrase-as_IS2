// Script de control para la ventana emergente de Arca Shield
// Compatible con Modo Claro / Oscuro, sincronización automática con Bóveda local y autocompletado nativo

document.addEventListener('DOMContentLoaded', async () => {
  const statusPill = document.getElementById('status-pill');
  const siteDomain = document.getElementById('site-domain');
  const siteProtocol = document.getElementById('site-protocol');
  const threatSection = document.getElementById('threat-section');
  const threatTitle = document.getElementById('threat-title');
  const threatDesc = document.getElementById('threat-desc');
  const safeSection = document.getElementById('safe-section');
  const openVaultBtn = document.getElementById('open-vault-btn');
  const vaultLockedSection = document.getElementById('vault-locked-section');
  const btnUnlockPopup = document.getElementById('btn-unlock-popup');
  const autofillSection = document.getElementById('autofill-section');
  const autofillList = document.getElementById('autofill-list');
  const vaultBrowseSection = document.getElementById('vault-browse-section');
  const vaultBrowseLabel = document.getElementById('vault-browse-label');
  const popupSearchInput = document.getElementById('popup-search-input');
  const popupVaultList = document.getElementById('popup-vault-list');
  const autofillToast = document.getElementById('autofill-toast');

  let activeTab = null;
  let allVaultItems = [];

  function openVaultTab() {
    chrome.tabs.create({ url: 'http://localhost:5173' });
  }

  openVaultBtn?.addEventListener('click', openVaultTab);
  btnUnlockPopup?.addEventListener('click', openVaultTab);

  // Obtener la pestaña activa
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  activeTab = (tabs && tabs[0]) || (await chrome.tabs.query({ active: true, currentWindow: true }))[0];

  if (!activeTab || !activeTab.url) {
    siteDomain.textContent = 'Sin pestaña activa';
    statusPill.textContent = 'Inactivo';
    return;
  }

  function showSuccessToast(message = 'Campos completados con éxito') {
    autofillToast.textContent = message;
    autofillToast.classList.remove('hidden');
    setTimeout(() => {
      autofillToast.classList.add('hidden');
    }, 2500);
  }

  // Intento de sincronización automática directa si la pestaña de la bóveda local está abierta
  async function tryAutoSyncFromLocalVault() {
    try {
      const localTabs = await chrome.tabs.query({ url: ['*://localhost:5173/*', '*://127.0.0.1:5173/*'] });
      if (!localTabs || localTabs.length === 0) return null;

      for (const tab of localTabs) {
        if (!chrome.scripting) continue;
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            window.postMessage({ type: 'ARCA_REQUEST_SYNC' }, '*');
            return window.__ARCA_VAULT_ITEMS__ || null;
          },
        });
        const items = results?.[0]?.result;
        if (Array.isArray(items) && items.length > 0) {
          await chrome.storage.local.set({ arca_vault_items: items });
          return items;
        }
      }
    } catch (e) {}
    return null;
  }

  async function triggerAutofill(username, password) {
    if (!activeTab || !activeTab.id) return;

    try {
      chrome.tabs.sendMessage(
        activeTab.id,
        {
          action: 'AUTOFILL_CREDENTIALS',
          username,
          password,
        },
        async (res) => {
          if (chrome.runtime.lastError || !res || !res.success) {
            await executeDirectAutofill(activeTab.id, username, password);
          }
          showSuccessToast(`Autocompletado: ${username || 'Cuenta'}`);
        }
      );
    } catch {
      await executeDirectAutofill(activeTab.id, username, password);
      showSuccessToast(`Autocompletado: ${username || 'Cuenta'}`);
    }
  }

  async function executeDirectAutofill(tabId, username, password) {
    if (!chrome.scripting) return;

    // Intentar también inyectar el content script si la pestaña no lo tenía (ej. pestaña abierta antes de recargar la extensión)
    try {
      await chrome.scripting.executeScript({
        target: { tabId, allFrames: true },
        files: ['content_script.js'],
      });
    } catch {}

    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: (user, pass) => {
        function setVal(el, val) {
          if (!el || val === undefined || val === null) return;
          el.focus();

          try {
            el.dispatchEvent(
              new InputEvent('beforeinput', {
                bubbles: true,
                composed: true,
                inputType: 'insertText',
                data: String(val),
              })
            );
          } catch (e) {}

          const proto = Object.getPrototypeOf(el);
          const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
          if (setter) setter.call(el, val);
          else el.value = val;

          el.setAttribute('value', val);
          el.setAttribute('data-initial-value', val);

          el.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
          try {
            el.dispatchEvent(
              new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertText', data: String(val) })
            );
          } catch (e) {}
          el.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
          el.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Unidentified' }));
          el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Unidentified' }));

          const parentContainer = el.closest('.rFrNMe, .Xb9hP, .form-group, .input-wrapper');
          if (parentContainer) {
            parentContainer.classList.add('CDQnT', 'i9xfre');
            parentContainer.classList.remove('u3bW4e');
          }

          setTimeout(() => {
            el.dispatchEvent(new Event('blur', { bubbles: true, composed: true }));
          }, 35);
        }

        function isVis(el) {
          if (!el || el.disabled || el.readOnly || el.type === 'hidden') return false;
          const s = window.getComputedStyle(el);
          if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') return false;
          const r = el.getBoundingClientRect();
          if (r.width < 35 || r.height < 15) return false;
          if (r.bottom <= 0 || r.top >= window.innerHeight || r.right <= 0 || r.left >= window.innerWidth) return false;
          return true;
        }

        const allInputs = Array.from(document.querySelectorAll('input')).filter(isVis);

        function scorePass(input) {
          let score = 0;
          if (input.name === 'Passwd') score += 150;
          if (input.getAttribute('autocomplete') === 'current-password') score += 120;
          if (input.getAttribute('autocomplete') === 'new-password') score += 100;
          if (input.type === 'password') score += 80;
          if (input.name?.toLowerCase().includes('pass')) score += 70;
          if (input.id?.toLowerCase().includes('pass')) score += 60;
          if (input.getAttribute('tabindex') !== '-1') score += 30;
          return score;
        }

        function scoreUser(input) {
          let score = 0;
          if (input.id === 'identifierId') score += 150;
          if (input.name === 'identifier') score += 140;
          if (input.type === 'email') score += 100;
          if (input.getAttribute('autocomplete') === 'username') score += 90;
          if (input.name === 'username' || input.name === 'loginfmt') score += 85;
          if (input.getAttribute('tabindex') !== '-1') score += 20;
          return score;
        }

        const passInputs = allInputs.filter((el) => {
          const type = (el.type || 'text').toLowerCase();
          return type === 'password' || el.name === 'Passwd' || el.name?.toLowerCase().includes('pass') || el.id?.toLowerCase().includes('pass');
        }).sort((a, b) => scorePass(b) - scorePass(a));

        const userInputs = allInputs.filter((el) => !passInputs.includes(el)).sort((a, b) => scoreUser(b) - scoreUser(a));

        const p = passInputs[0] || null;
        const u = userInputs[0] || null;

        if (p && pass) setVal(p, pass);
        if (u && user) setVal(u, user);

        if (u && !p) {
          const next = document.querySelector(
            '#identifierNext button, #identifierNext, button[type="submit"], input[type="submit"], button[jsname="LgbsSe"]'
          );
          if (next) next.focus();
        } else if (p) {
          const submit = document.querySelector(
            '#passwordNext button, #passwordNext, button[type="submit"], input[type="submit"], #kc-login'
          );
          if (submit) submit.focus();
        }
      },
      args: [username, password],
    });
  }

  function renderCards(container, items) {
    if (!items || items.length === 0) {
      container.innerHTML = `<div style="font-size: 11px; color: var(--text-muted); text-align: center; padding: 12px;">No se encontraron cuentas coincidentes.</div>`;
      return;
    }

    container.innerHTML = items
      .map(
        (m, idx) => `
      <div class="cred-card">
        <div class="cred-info">
          <div class="cred-user">${m.username || 'Usuario'}</div>
          <div class="cred-title">${m.title || 'Acceso'}</div>
        </div>
        <button class="btn-card-autofill" data-idx="${idx}" type="button">Autocompletar</button>
      </div>
    `
      )
      .join('');

    container.querySelectorAll('.btn-card-autofill').forEach((btn) => {
      btn.addEventListener('click', () => {
        const idx = Number(btn.dataset.idx);
        const item = items[idx];
        if (item) {
          triggerAutofill(item.username, item.password);
        }
      });
    });
  }

  // 1. Diagnóstico de seguridad
  chrome.runtime.sendMessage({ action: 'GET_CURRENT_SECURITY_REPORT', url: activeTab.url }, async (report) => {
    if (!report) return;

    siteDomain.textContent = report.hostname || 'Página Interna';
    siteProtocol.textContent = report.isSecure ? 'Protocolo HTTPS Cifrado' : 'Protocolo HTTP Sin Cifrar';

    if (report.riskLevel === 'danger') {
      statusPill.textContent = 'Peligro';
      statusPill.className = 'status-pill status-pill--danger';

      threatSection.classList.remove('hidden');
      safeSection.classList.add('hidden');
      vaultLockedSection.classList.add('hidden');
      autofillSection.classList.add('hidden');
      vaultBrowseSection.classList.add('hidden');

      threatTitle.textContent = report.title || 'Alerta de Phishing';
      threatDesc.textContent = report.description || 'Se detectaron indicios de suplantación de identidad.';
      return;
    }

    if (report.riskLevel === 'warning') {
      statusPill.textContent = 'Inseguro';
      statusPill.className = 'status-pill status-pill--warning';

      threatSection.classList.remove('hidden');
      safeSection.classList.add('hidden');
      vaultLockedSection.classList.add('hidden');
      autofillSection.classList.add('hidden');
      vaultBrowseSection.classList.add('hidden');

      threatTitle.textContent = report.title || 'Conexión Insegura';
      threatDesc.textContent = report.description || 'El tráfico viaja en texto plano sin cifrado HTTPS.';
      return;
    }

    statusPill.textContent = 'Seguro';
    statusPill.className = 'status-pill status-pill--safe';
    threatSection.classList.add('hidden');
    safeSection.classList.remove('hidden');

    // 2. Obtener credenciales (con intento de sincronización automática desde la pestaña local)
    let stored = (await chrome.storage.local.get('arca_vault_items'))?.arca_vault_items;
    if (!Array.isArray(stored) || stored.length === 0) {
      stored = await tryAutoSyncFromLocalVault();
    }

    if (!Array.isArray(stored) || stored.length === 0) {
      // Bóveda no sincronizada o bloqueada
      vaultLockedSection.classList.remove('hidden');
      autofillSection.classList.add('hidden');
      vaultBrowseSection.classList.add('hidden');
      return;
    }

    allVaultItems = stored;
    vaultLockedSection.classList.add('hidden');

    // Consultar coincidencias para esta página web
    chrome.runtime.sendMessage({ action: 'GET_MATCHING_CREDENTIALS', url: activeTab.url }, (resp) => {
      const matches = resp?.matches || [];
      if (matches.length > 0) {
        renderCards(autofillList, matches);
        autofillSection.classList.remove('hidden');

        // Además mostrar el buscador con las otras cuentas
        const others = allVaultItems.filter((v) => !matches.some((m) => m.id === v.id));
        if (others.length > 0) {
          vaultBrowseLabel.textContent = 'Otras cuentas en tu Bóveda';
          renderCards(popupVaultList, others);
          vaultBrowseSection.classList.remove('hidden');
        } else {
          vaultBrowseSection.classList.add('hidden');
        }
      } else {
        // No hay coincidencia directa: mostrar todas las cuentas de la bóveda
        autofillSection.classList.add('hidden');
        vaultBrowseLabel.textContent = 'Cuentas en tu Bóveda Arca';
        renderCards(popupVaultList, allVaultItems);
        vaultBrowseSection.classList.remove('hidden');
      }
    });
  });

  // Búsqueda en vivo en la sección de la bóveda
  popupSearchInput?.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    const filtered = allVaultItems.filter((item) => {
      return (
        (item.username && item.username.toLowerCase().includes(q)) ||
        (item.title && item.title.toLowerCase().includes(q))
      );
    });
    renderCards(popupVaultList, filtered);
  });
});
