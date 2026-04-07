/* ── Theme bootstrap (runs before paint) ─────────────────── */
(function initTheme() {
  const KEY = 'sv-theme';
  const saved = localStorage.getItem(KEY);
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = saved || (prefersDark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-bs-theme', theme);
  syncThemeIcons(theme);
})();

function syncThemeIcons(theme) {
  document.querySelectorAll('.theme-icon-dark').forEach(el => el.classList.toggle('d-none', theme === 'dark'));
  document.querySelectorAll('.theme-icon-light').forEach(el => el.classList.toggle('d-none', theme !== 'dark'));
}

document.querySelectorAll('.theme-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const root = document.documentElement;
    const next = root.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-bs-theme', next);
    localStorage.setItem('sv-theme', next);
    syncThemeIcons(next);
  });
});

/* ── Notification toasts (правый нижний угол, контейнер #sv-toast-stack) ── */
function showNotification(message, type = 'info') {
  const container = document.getElementById('sv-toast-stack');
  if (!container) return;

  const el = document.createElement('div');
  el.className = `alert alert-${type} alert-dismissible fade show sv-toast-item shadow border-0`;
  el.setAttribute('role', 'alert');
  el.innerHTML = `
    <span class="me-2">${getIcon(type)}</span>${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Закрыть"></button>
  `;
  container.appendChild(el);

  const ms = type === 'danger' ? 8000 : 4200;
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 200);
  }, ms);
}

function getIcon(type) {
  const icons = { success: '✓', danger: '✕', warning: '⚠', info: 'ℹ' };
  return icons[type] || '';
}

/* ── Password generator ─────────────────────────────────── */
function generatePassword(length = 18) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*';
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr, n => chars[n % chars.length]).join('');
}

function getPasswordInput(btn) {
  const g = btn.closest('.input-group');
  return g ? (g.querySelector('.credential-password-field') || g.querySelector('input[type="password"]')) : null;
}

/* ── Toggle password visibility ─────────────────────────── */
document.querySelectorAll('.toggle-password').forEach(btn => {
  btn.addEventListener('click', function () {
    const input = getPasswordInput(this);
    if (!input) return;
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    const icon = this.querySelector('i');
    if (icon) icon.className = show ? 'bi bi-eye-slash' : 'bi bi-eye';
  });
});

/* ── Generate password ──────────────────────────────────── */
document.querySelectorAll('.btn-generate-pw').forEach(btn => {
  btn.addEventListener('click', function () {
    const input = getPasswordInput(this);
    if (!input) return;
    const pw = generatePassword(20);
    input.value = pw;
    input.type = 'text';
    const toggleIcon = this.closest('.input-group')?.querySelector('.toggle-password i');
    if (toggleIcon) toggleIcon.className = 'bi bi-eye-slash';
    // Brief pulse on the input
    input.style.borderColor = 'var(--accent)';
    setTimeout(() => { input.style.borderColor = ''; }, 800);
  });
});

/* ── Clipboard (HTTP по IP не даёт Async Clipboard API — нужен fallback) ── */
function copyTextToClipboardLegacy(text) {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, text.length);
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch (e) {
    return false;
  }
}

/** true, если текст реально попал в буфер (или API так считает). */
function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text).then(() => true).catch(() =>
      Promise.resolve(copyTextToClipboardLegacy(text))
    );
  }
  return Promise.resolve(copyTextToClipboardLegacy(text));
}

/* ── Copy username ──────────────────────────────────────── */
function copyUsernameAction(credentialId, buttonEl) {
  fetch(`/credentials/${credentialId}/copy-username`, {
    method: 'POST',
    headers: { 'X-Requested-With': 'XMLHttpRequest' }
  })
    .then(r => {
      if (!r.ok) throw new Error('bad status');
      return r.json();
    })
    .then(data => {
      if (!data.username) throw new Error('no field');
      return copyTextToClipboard(data.username);
    })
    .then((ok) => {
      if (ok) {
        flashBtn(buttonEl, 'bi bi-check');
        showNotification('Логин скопирован', 'success');
      } else {
        showNotification(
          'Логин получен с сервера, но в буфер записать не удалось. Откройте сайт по HTTPS или скопируйте вручную из ответа в инструментах разработчика.',
          'warning'
        );
      }
    })
    .catch(() => showNotification('Не удалось скопировать', 'danger'));
}

document.querySelectorAll('.copy-username-btn').forEach(btn => {
  btn.addEventListener('click', function () {
    const id = this.dataset.credentialId;
    if (id) copyUsernameAction(id, this);
  });
});

/* ── Copy password ──────────────────────────────────────── */
function copyPasswordUrl(id) {
  const cfg = document.getElementById('sv-credentials-config');
  if (!cfg?.dataset.copyPasswordBase) return null;
  return cfg.dataset.copyPasswordBase.replace(/\/0\/copy-password(\?.*)?$/, `/${id}/copy-password$1`);
}

document.querySelectorAll('.copy-password').forEach(btn => {
  btn.addEventListener('click', function () {
    const id = this.dataset.credentialId;
    const buttonEl = this;
    if (!id) return;
    const url = copyPasswordUrl(id);
    if (!url) return;
    fetch(url, { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then(r => {
        if (!r.ok) throw new Error('bad status');
        return r.json();
      })
      .then(data => {
        if (!data.password) throw new Error('no field');
        return copyTextToClipboard(data.password).then((ok) => ({ ok }));
      })
      .then(({ ok }) => {
        if (ok) {
          flashBtn(buttonEl, 'bi bi-check');
          showNotification('Пароль скопирован', 'success');
        } else {
          showNotification(
            'Пароль получен с сервера, но в буфер записать не удалось. Откройте сайт по HTTPS или временно откройте запись для ручного копирования.',
            'warning'
          );
        }
      })
      .catch(() => showNotification('Не удалось скопировать пароль', 'danger'));
  });
});

/* ── Button flash helper ────────────────────────────────── */
function flashBtn(btn, successClass) {
  if (!btn) return;
  const icon = btn.querySelector('i');
  if (!icon) return;
  const prev = icon.className;
  icon.className = successClass;
  btn.style.color = 'var(--emerald-400)';
  setTimeout(() => { icon.className = prev; btn.style.color = ''; }, 1600);
}

/* ── Подсказки пользователей при расшаривании (до 10) ─────── */
function svUsersForShareUrl(apiBase, q, credentialId) {
  const url = new URL(apiBase, window.location.origin);
  url.searchParams.set('q', q);
  if (credentialId) url.searchParams.set('credential_id', String(credentialId));
  return url.pathname + url.search;
}

function initSvShareUserPickers() {
  document.querySelectorAll('[data-sv-share-picker]').forEach(container => {
    const apiBase = container.getAttribute('data-sv-api');
    const input = container.querySelector('.sv-share-user-input');
    const list = container.querySelector('[data-sv-share-suggestions]');
    if (!apiBase || !input || !list) return;

    let debounce;
    const hideList = () => {
      list.innerHTML = '';
      list.style.display = 'none';
    };

    const showUsers = (users) => {
      list.innerHTML = '';
      if (!users.length) {
        hideList();
        return;
      }
      users.forEach(u => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'list-group-item list-group-item-action py-2 px-3 small text-start';
        btn.textContent = u.username;
        btn.addEventListener('click', () => {
          input.value = u.username;
          hideList();
        });
        list.appendChild(btn);
      });
      list.style.display = 'block';
    };

    const load = () => {
      const q = input.value.trim();
      const credId =
        input.getAttribute('data-credential-id') ||
        container.getAttribute('data-sv-credential-id') ||
        '';
      fetch(svUsersForShareUrl(apiBase, q, credId), {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
        .then(r => r.json())
        .then(data => showUsers(data.users || []))
        .catch(() => hideList());
    };

    input.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(load, 200);
    });
    input.addEventListener('focus', () => {
      clearTimeout(debounce);
      debounce = setTimeout(load, 100);
    });

    document.addEventListener('click', e => {
      if (!container.contains(e.target)) hideList();
    });
  });
}

function initServerFlashAutoDismiss() {
  const stack = document.getElementById('sv-toast-stack');
  if (!stack) return;
  stack.querySelectorAll('.alert').forEach((el) => {
    const isDanger = el.classList.contains('alert-danger');
    const ms = isDanger ? 9000 : 5200;
    setTimeout(() => {
      el.classList.remove('show');
      setTimeout(() => el.remove(), 200);
    }, ms);
  });
}

/* ── DOM ready ──────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initServerFlashAutoDismiss();
  initSvShareUserPickers();

  // Bootstrap tooltips
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => new bootstrap.Tooltip(el, { trigger: 'hover' }));

  // Close sidebar offcanvas on link click (mobile)
  const sidebar = document.getElementById('appSidebarMenu');
  if (sidebar) {
    sidebar.addEventListener('click', e => {
      const link = e.target.closest('a[href]');
      if (!link) return;
      const href = link.getAttribute('href');
      if (!href || href === '#' || href.startsWith('javascript:')) return;
      if (window.matchMedia('(max-width: 991.98px)').matches) {
        const inst = bootstrap.Offcanvas.getInstance(sidebar);
        if (inst) inst.hide();
      }
    });
  }

  // Mark active sidebar nav links
  const path = window.location.pathname;
  document.querySelectorAll('.app-sidebar-nav .nav-link[href]').forEach(link => {
    if (link.getAttribute('href') === path) link.classList.add('active');
  });
});
