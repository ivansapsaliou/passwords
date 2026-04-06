(function initTheme() {
    const key = 'securevault-theme';
    const root = document.documentElement;
    const saved = localStorage.getItem(key);
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = saved || (prefersDark ? 'dark' : 'light');
    root.setAttribute('data-bs-theme', theme);
    syncThemeIcons(theme);
})();

function syncThemeIcons(theme) {
    document.querySelectorAll('.theme-icon-dark').forEach((el) => {
        el.classList.toggle('d-none', theme === 'dark');
    });
    document.querySelectorAll('.theme-icon-light').forEach((el) => {
        el.classList.toggle('d-none', theme !== 'dark');
    });
}

document.querySelectorAll('.theme-toggle').forEach((btn) => {
    btn.addEventListener('click', () => {
        const root = document.documentElement;
        const next = root.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
        root.setAttribute('data-bs-theme', next);
        localStorage.setItem('securevault-theme', next);
        syncThemeIcons(next);
    });
});

function showNotification(message, type = 'info') {
    const target =
        document.querySelector('.flash-stack') ||
        document.querySelector('.container-fluid');
    if (!target) return;

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show border-0 shadow-sm`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Закрыть"></button>
    `;
    target.insertBefore(alertDiv, target.firstChild);

    setTimeout(() => {
        alertDiv.remove();
    }, 4000);
}

function generatePassword(length = 16) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*';
    let password = '';
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
        password += chars[array[i] % chars.length];
    }
    return password;
}

function inputGroupPasswordInput(btn) {
    const g = btn.closest('.input-group');
    if (!g) return null;
    return g.querySelector('.credential-password-field') || g.querySelector('input[type="password"]');
}

document.querySelectorAll('.toggle-password').forEach((btn) => {
    btn.addEventListener('click', function () {
        const input = inputGroupPasswordInput(this);
        if (!input) return;
        const show = input.getAttribute('type') === 'password';
        input.setAttribute('type', show ? 'text' : 'password');
        const icon = this.querySelector('i');
        if (icon) {
            icon.className = show ? 'bi bi-eye-slash' : 'bi bi-eye';
        }
    });
});

document.querySelectorAll('.btn-generate-pw').forEach((btn) => {
    btn.addEventListener('click', function () {
        const input = inputGroupPasswordInput(this);
        if (!input) return;
        input.value = generatePassword(18);
        input.setAttribute('type', 'text');
        const t = this.closest('.input-group')?.querySelector('.toggle-password i');
        if (t) t.className = 'bi bi-eye-slash';
    });
});

function copyUsernameAction(credentialId, buttonEl) {
    fetch(`/credentials/${credentialId}/copy-username`, {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
    })
        .then((r) => r.json())
        .then((data) => {
            if (data.username) {
                navigator.clipboard.writeText(data.username);
                if (buttonEl) {
                    const icon = buttonEl.querySelector('i');
                    const prev = icon ? icon.className : '';
                    if (icon) icon.className = 'bi bi-check';
                    setTimeout(() => {
                        if (icon) icon.className = prev;
                    }, 1600);
                }
                showNotification('Логин скопирован', 'success');
            }
        })
        .catch(() => showNotification('Не удалось скопировать', 'danger'));
}

document.querySelectorAll('.copy-username-btn').forEach((btn) => {
    btn.addEventListener('click', function () {
        const id = this.dataset.credentialId;
        if (id) copyUsernameAction(id, this);
    });
});

function copyPasswordApiUrl(credentialId) {
    const cfg = document.getElementById('sv-credentials-config');
    if (!cfg || !cfg.dataset.copyPasswordBase) return null;
    const base = cfg.dataset.copyPasswordBase;
    return base.replace(/\/0\/copy-password(\?.*)?$/, `/${credentialId}/copy-password$1`);
}

document.querySelectorAll('.copy-password').forEach((btn) => {
    btn.addEventListener('click', function () {
        const id = this.dataset.credentialId;
        if (!id) return;
        const url = copyPasswordApiUrl(id);
        if (!url) return;
        fetch(url, {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
        })
            .then((r) => r.json())
            .then((data) => {
                if (data.password) {
                    navigator.clipboard.writeText(data.password);
                    const icon = this.querySelector('i');
                    const prev = icon ? icon.className : '';
                    if (icon) icon.className = 'bi bi-check';
                    setTimeout(() => {
                        if (icon) icon.className = prev;
                    }, 1600);
                    showNotification('Пароль скопирован', 'success');
                }
            })
            .catch(() => showNotification('Не удалось скопировать пароль', 'danger'));
    });
});

document.addEventListener('DOMContentLoaded', function () {
    const tooltipTriggerList = [].slice.call(
        document.querySelectorAll('[data-bs-toggle="tooltip"]')
    );
    tooltipTriggerList.map((el) => new bootstrap.Tooltip(el));

    const sidebar = document.getElementById('appSidebarMenu');
    if (sidebar) {
        sidebar.addEventListener('click', function (e) {
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
});
