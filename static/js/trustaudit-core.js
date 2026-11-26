/* TrustAudit Core Client Utilities: API, Modals, Drawers, Toasts, Command Palette */
(function () {
  function getToken() {
    try { return localStorage.getItem('trustaudit_token') || ''; } catch (e) { return ''; }
  }

  function setToken(tok) {
    try {
      if (tok) localStorage.setItem('trustaudit_token', tok);
      else localStorage.removeItem('trustaudit_token');
    } catch (e) {}
  }

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function toast(msg, kind) {
    let stack = document.getElementById('ta-toast-stack');
    if (!stack) {
      stack = document.createElement('div');
      stack.id = 'ta-toast-stack';
      stack.className = 'toast-stack';
      document.body.appendChild(stack);
    }
    const el = document.createElement('div');
    el.className = 'toast' + (kind === 'err' ? ' err' : '');
    el.textContent = msg;
    stack.appendChild(el);
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 3600);
  }

  async function apiJson(url, opts) {
    const options = Object.assign({}, opts || {});
    const headers = Object.assign({}, options.headers || {});
    const tok = getToken();
    if (tok && !headers.Authorization) headers.Authorization = 'Bearer ' + tok;
    if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    options.headers = headers;
    options.credentials = 'same-origin';
    const res = await fetch(url, options);
    const ct = res.headers.get('content-type') || '';
    const data = ct.indexOf('application/json') !== -1 ? await res.json() : await res.text();
    if (!res.ok) {
      const errMsg = (data && (data.error || data.message)) || ('Request failed (' + res.status + ')');
      if (res.status === 401 && window.location.pathname.indexOf('/app/') === 0) {
        window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
      }
      throw new Error(errMsg);
    }
    return data;
  }

  function openModal(title, htmlContent) {
    let backdrop = document.getElementById('ta-modal-backdrop');
    if (!backdrop) {
      backdrop = document.createElement('div');
      backdrop.id = 'ta-modal-backdrop';
      backdrop.className = 'modal-backdrop';
      backdrop.innerHTML =
        '<div class="modal-box" role="dialog" aria-modal="true">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">' +
        '<h3 id="ta-modal-title" style="margin:0;"></h3>' +
        '<button type="button" class="btn btn-ghost btn-sm" id="ta-modal-close">Close</button>' +
        '</div>' +
        '<div id="ta-modal-body"></div>' +
        '</div>';
      document.body.appendChild(backdrop);
      backdrop.addEventListener('click', function (ev) {
        if (ev.target === backdrop) closeModal();
      });
      document.getElementById('ta-modal-close').addEventListener('click', closeModal);
    }
    document.getElementById('ta-modal-title').textContent = title || '';
    document.getElementById('ta-modal-body').innerHTML = htmlContent || '';
    backdrop.classList.add('open');
  }

  function closeModal() {
    const b = document.getElementById('ta-modal-backdrop');
    if (b) b.classList.remove('open');
  }

  function openDrawer(title, htmlContent) {
    let backdrop = document.getElementById('ta-drawer-backdrop');
    if (!backdrop) {
      backdrop = document.createElement('div');
      backdrop.id = 'ta-drawer-backdrop';
      backdrop.className = 'drawer-backdrop';
      backdrop.innerHTML =
        '<div class="drawer-panel">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border);">' +
        '<h3 id="ta-drawer-title" style="margin:0;"></h3>' +
        '<button type="button" class="btn btn-ghost btn-sm" id="ta-drawer-close">Close</button>' +
        '</div>' +
        '<div id="ta-drawer-body"></div>' +
        '</div>';
      document.body.appendChild(backdrop);
      backdrop.addEventListener('click', function (ev) {
        if (ev.target === backdrop) closeDrawer();
      });
      document.getElementById('ta-drawer-close').addEventListener('click', closeDrawer);
    }
    document.getElementById('ta-drawer-title').textContent = title || '';
    document.getElementById('ta-drawer-body').innerHTML = htmlContent || '';
    backdrop.classList.add('open');
  }

  function closeDrawer() {
    const b = document.getElementById('ta-drawer-backdrop');
    if (b) b.classList.remove('open');
  }

  function initTheme() {
    try {
      const saved = localStorage.getItem('trustaudit_theme') || 'light';
      document.documentElement.setAttribute('data-theme', saved);
    } catch (e) {}
  }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute('data-theme') || 'light';
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('trustaudit_theme', next); } catch (e) {}
  }

  function toggleSidebar() {
    const shell = document.getElementById('ta-app-shell');
    if (!shell) return;
    if (window.innerWidth <= 980) {
      shell.classList.toggle('mobile-sidebar-open');
    } else {
      shell.classList.toggle('sidebar-collapsed');
      try {
        localStorage.setItem('ta_sidebar_collapsed', shell.classList.contains('sidebar-collapsed') ? '1' : '0');
      } catch (e) {}
    }
  }

  function openCommandPalette() {
    const quickLinks = [
      { kind: 'Workspace', title: 'Home Command Centre', subtitle: 'Setup progress and top priority actions', href: '/app/home' },
      { kind: 'Workspace', title: 'Guided Onboarding', subtitle: '6-step assisted setup wizard', href: '/app/onboarding' },
      { kind: 'Workspace', title: 'Discovery Centre', subtitle: 'Website, CSV/XLSX/DOCX/PDF & vendor discovery', href: '/app/discovery' },
      { kind: 'Workspace', title: 'Business Data Inventory', subtitle: 'Manage personal data categories & import CSV/XLSX', href: '/app/data-inventory' },
      { kind: 'Workspace', title: 'Visual Data Map', subtitle: 'Interactive SVG data-flow explorer', href: '/app/data-map' },
      { kind: 'Workspace', title: 'Privacy Assessment', subtitle: '10 understandable privacy topics', href: '/app/assessment' },
      { kind: 'Workspace', title: 'Action Plan', subtitle: 'Kanban, List & Calendar task manager', href: '/app/action-plan' },
      { kind: 'Workspace', title: 'Vendors & Processors', subtitle: 'Track contracts, questionnaires & risks', href: '/app/vendors' },
      { kind: 'Workspace', title: 'Customer Privacy Portal', subtitle: 'Configure branded request intake URL', href: '/app/privacy-portal' },
      { kind: 'Workspace', title: 'AI Privacy Assistant', subtitle: 'Ask grounded DPDP Act & Rules questions', href: '/app/privacy-assistant' },
    ];
    openModal(
      'Quick Search (Cmd/Ctrl + K)',
      '<input id="ta-cmd-input" class="input" placeholder="Search customer data, vendors, tasks, DPDP rules, or pages..." autofocus>' +
      '<div id="ta-cmd-results" style="margin-top:14px;display:flex;flex-direction:column;gap:8px;max-height:360px;overflow-y:auto;"></div>'
    );
    const inp = document.getElementById('ta-cmd-input');
    const out = document.getElementById('ta-cmd-results');
    function renderHits(list) {
      if (!list.length) {
        out.innerHTML = '<div class="ta-muted" style="padding:12px;">No matching workspace records found.</div>';
        return;
      }
      out.innerHTML = list.map(function (item) {
        return '<a href="' + esc(item.href) + '" style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border:1px solid var(--border);border-radius:9px;text-decoration:none;">' +
          '<div><div style="font-weight:700;font-size:13.5px;">' + esc(item.title) + '</div>' +
          '<div class="ta-muted" style="font-size:12px;">' + esc(item.subtitle || '') + '</div></div>' +
          '<span class="badge badge-neutral">' + esc(item.kind || 'Page') + '</span></a>';
      }).join('');
    }
    renderHits(quickLinks);
    inp.addEventListener('input', async function () {
      const q = inp.value.trim();
      if (q.length < 2) { renderHits(quickLinks); return; }
      const filteredNav = quickLinks.filter(function (x) {
        return (x.title + ' ' + x.subtitle).toLowerCase().indexOf(q.toLowerCase()) !== -1;
      });
      try {
        const res = await apiJson('/api/dpdp/search?q=' + encodeURIComponent(q));
        renderHits((res.results || []).concat(filteredNav));
      } catch (e) {
        renderHits(filteredNav);
      }
    });
  }

  async function logout() {
    try { await apiJson('/api/auth/logout', { method: 'POST' }); } catch (e) {}
    setToken('');
    window.location.href = '/login';
  }

  document.addEventListener('keydown', function (ev) {
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      openCommandPalette();
    } else if (ev.key === 'Escape') {
      closeModal();
      closeDrawer();
    }
  });

  document.addEventListener('DOMContentLoaded', function () {
    initTheme();
    const shell = document.getElementById('ta-app-shell');
    try {
      if (shell && localStorage.getItem('ta_sidebar_collapsed') === '1' && window.innerWidth > 980) {
        shell.classList.add('sidebar-collapsed');
      }
    } catch (e) {}
    // Scroll reveal animation
    const els = document.querySelectorAll('.reveal');
    if (els.length && 'IntersectionObserver' in window) {
      const obs = new IntersectionObserver(function (entries) {
        entries.forEach(function (ent) {
          if (ent.isIntersecting) {
            ent.target.classList.add('revealed');
            ent.target.classList.remove('reveal-pending');
            obs.unobserve(ent.target);
          }
        });
      }, { threshold: 0.08 });
      els.forEach(function (el) {
        const r = el.getBoundingClientRect();
        if (r.top > window.innerHeight * 0.95) el.classList.add('reveal-pending');
        obs.observe(el);
      });
    }
  });

  window.TA = {
    getToken: getToken,
    setToken: setToken,
    esc: esc,
    toast: toast,
    apiJson: apiJson,
    openModal: openModal,
    closeModal: closeModal,
    openDrawer: openDrawer,
    closeDrawer: closeDrawer,
    toggleTheme: toggleTheme,
    toggleSidebar: toggleSidebar,
    openCommandPalette: openCommandPalette,
    logout: logout,
  };
})();
