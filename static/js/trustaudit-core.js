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

  const _INFLIGHT_ABORTS = {};

  function debounce(fn, waitMs) {
    let timer = null;
    return function () {
      const ctx = this, args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(ctx, args); }, waitMs || 250);
    };
  }

  function paginate(items, page, perPage) {
    const arr = Array.isArray(items) ? items : [];
    const size = Math.max(1, perPage || 20);
    const totalPages = Math.max(1, Math.ceil(arr.length / size));
    const cur = Math.min(totalPages, Math.max(1, page || 1));
    const start = (cur - 1) * size;
    return { items: arr.slice(start, start + size), page: cur, totalPages: totalPages, total: arr.length };
  }

  function renderRetryBanner(el, msg, retryFn) {
    if (!el) return;
    el.innerHTML =
      '<div style="padding:12px 14px;border-radius:10px;background:rgba(220,38,38,0.08);border:1px solid rgba(220,38,38,0.22);display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">' +
      '<span style="color:#B91C1C;font-size:13.5px;font-weight:600;">' + esc(msg || 'Unable to load section.') + '</span>' +
      '<button type="button" class="btn btn-outline btn-sm" id="ta-retry-banner-btn">Retry</button></div>';
    const b = document.getElementById('ta-retry-banner-btn');
    if (b && typeof retryFn === 'function') b.onclick = retryFn;
  }

  async function apiJson(url, opts) {
    const options = Object.assign({}, opts || {});
    if (options.dedupeKey && typeof AbortController !== 'undefined') {
      if (_INFLIGHT_ABORTS[options.dedupeKey]) {
        try { _INFLIGHT_ABORTS[options.dedupeKey].abort(); } catch (e) {}
      }
      const ctrl = new AbortController();
      _INFLIGHT_ABORTS[options.dedupeKey] = ctrl;
      options.signal = ctrl.signal;
    }
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

  async function loadNotificationBadge() {
    const badge = document.getElementById('ta-notif-badge');
    if (!badge) return;
    try {
      const res = await apiJson('/api/dpdp/notifications', { dedupeKey: 'notif_badge' });
      const n = Number(res.count || 0);
      if (n > 0) { badge.textContent = String(n > 9 ? '9+' : n); badge.style.display = 'inline-flex'; }
      else { badge.style.display = 'none'; }
    } catch (e) {}
  }

  async function openNotifications() {
    openDrawer('Workspace Notifications', '<div class="ta-muted">Checking genuine action alerts...</div>');
    try {
      const res = await apiJson('/api/dpdp/notifications');
      const items = res.notifications || [];
      const body = document.getElementById('ta-drawer-body');
      if (!items.length) {
        body.innerHTML = '<div class="empty-state"><strong>All caught up</strong><p class="ta-muted" style="margin-top:6px;">No overdue tasks, expiring evidence, pending customer requests, or security alerts.</p></div>';
        return;
      }
      body.innerHTML = items.map(function (it) {
        const cls = it.severity === 'HIGH' ? 'badge-amber' : 'badge-neutral';
        return '<a href="' + esc(it.href || '/app/home') + '" style="display:block;padding:12px;border:1px solid var(--border);border-radius:10px;text-decoration:none;margin-bottom:10px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;"><strong>' + esc(it.title) + '</strong><span class="badge ' + cls + '">' + esc(it.severity || 'INFO') + '</span></div>' +
          '<div class="ta-muted" style="font-size:12.5px;margin-top:4px;">' + esc(it.detail || '') + '</div></a>';
      }).join('');
    } catch (e) {
      openDrawer('Workspace Notifications', '<div class="ta-muted">Failed loading notifications: ' + esc(e.message) + '</div>');
    }
  }

  function openContextualHelp() {
    const p = window.location.pathname || '/app/home';
    const guide = {
      '/app/home': ['Home Overview', 'Tracks setup progress (X of 6), top 3 priority tasks, and chronological workspace activity without inflated scores.'],
      '/app/onboarding': ['Guided Onboarding', 'Confirm business details, personal data uses, and systems step by step before creating records.'],
      '/app/discovery': ['Discovery Centre', 'Upload CSV/XLSX/DOCX/PDF files or run a Website Check to extract draft records labeled Needs review until approved.'],
      '/app/data-inventory': ['Data Inventory', 'Track personal data categories, collection sources, lawful bases (Sec 6 consent vs Sec 7), storage, and retention.'],
      '/app/data-map': ['Visual Data Map', 'Visualises confirmed Customer -> Intake -> Storage -> Vendor flows. Unconfirmed drafts stay out until accepted.'],
      '/app/assessment': ['10-Topic Privacy Assessment', 'Covers Sections 3-17, S.O. 5458(E), and Rule 3-16 using 5 honest states from Not assessed to Verified.'],
      '/app/action-plan': ['Action Plan', 'Switch between Kanban, List, and Calendar views to assign owners, due dates, and completion notes.'],
      '/app/vendors': ['Vendors & Processors', 'Record cloud hosts, labs, and SaaS vendors, send Vendor Questionnaires, and track Section 8(2) contracts.'],
      '/app/privacy-portal': ['Customer Privacy Portal', 'Configure your /portal/<slug> page for data principal access, correction, erasure, and grievance requests.'],
      '/app/privacy-profile': ['Privacy Profile', 'Share only approved public details at /p/<slug>; unpublished drafts and vendor secrets never appear.'],
      '/app/settings': ['Settings, 2FA & Sessions', 'Configure TOTP 2FA with offline SVG QR + 8 recovery codes, revoke other sessions, change password, or export audit logs.'],
    };
    const item = guide[p] || ['TrustAudit Workspace Help', 'Use Cmd/Ctrl + K to jump cleanly across inventory, vendors, notices, tasks, evidence, and reports.'];
    openModal('Help: ' + item[0],
      '<p style="font-size:14.5px;line-height:1.6;margin-bottom:14px;">' + esc(item[1]) + '</p>' +
      '<div style="padding:12px;border-radius:10px;background:var(--bg-muted);font-size:13px;margin-bottom:14px;">' +
      '<strong>Statutory Note:</strong> Substantive DPDP duties commence <strong>13 May 2027</strong> (Consent Manager rules 13 Nov 2026; S.O. 5458(E) clarified Sec 9(1) &amp; Sec 10 data audit).' +
      '</div>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
      '<a href="/resources" class="btn btn-outline btn-sm">Open Statutory Library</a>' +
      '<button type="button" class="btn btn-primary btn-sm" onclick="TA.openReportProblemModal()">Report a Problem</button></div>'
    );
  }

  function openReportProblemModal() {
    openModal('Report a Product Problem',
      '<p class="ta-muted" style="margin-bottom:12px;">Describe an issue or unexpected behaviour. TrustAudit logs only your workspace ID, current page path, and description&mdash;zero customer PII or passwords are attached.</p>' +
      '<form onsubmit="TA._submitReportProblem(event)">' +
      '<div class="field"><label for="rp-cat">Issue Area</label><select id="rp-cat" class="input"><option>Page or button issue</option><option>Report or export issue</option><option>Website check issue</option><option>Authentication / 2FA</option><option>Other</option></select></div>' +
      '<div class="field"><label for="rp-desc">What happened?</label><textarea id="rp-desc" class="input" rows="3" required minlength="5" placeholder="Describe steps to reproduce cleanly..."></textarea></div>' +
      '<button type="submit" class="btn btn-primary" style="width:100%;">Submit Issue Report</button></form>' +
      '<div id="rp-out" style="margin-top:10px;font-size:13px;"></div>'
    );
  }

  async function _submitReportProblem(ev) {
    ev.preventDefault();
    const out = document.getElementById('rp-out');
    try {
      const r = await apiJson('/api/support/report-problem', {
        method: 'POST',
        body: JSON.stringify({
          category: document.getElementById('rp-cat').value,
          description: document.getElementById('rp-desc').value.trim(),
          page_route: window.location.pathname,
          browser_info: (navigator.userAgent || '').slice(0, 140),
        }),
      });
      out.innerHTML = '<div style="padding:10px;border-radius:8px;background:var(--emerald-soft);">' + esc(r.message) + '</div>';
    } catch (e) {
      out.innerHTML = '<span style="color:var(--rose);">' + esc(e.message) + '</span>';
    }
  }

  function toggleNavGroup(btn) {
    const grp = btn && btn.closest('.nav-group');
    if (!grp) return;
    grp.classList.toggle('collapsed');
    const key = btn.getAttribute('data-group');
    try {
      if (key) localStorage.setItem('ta_nav_col_' + key, grp.classList.contains('collapsed') ? '1' : '0');
    } catch (e) {}
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
    try {
      document.querySelectorAll('.nav-group-toggle[data-group]').forEach(function (btn) {
        const key = btn.getAttribute('data-group');
        if (localStorage.getItem('ta_nav_col_' + key) === '1' && !btn.closest('.nav-group').querySelector('.nav-item.active')) {
          btn.closest('.nav-group').classList.add('collapsed');
        }
      });
    } catch (e) {}
    if (document.getElementById('ta-notif-badge')) loadNotificationBadge();
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
    debounce: debounce,
    paginate: paginate,
    renderRetryBanner: renderRetryBanner,
    apiJson: apiJson,
    openModal: openModal,
    closeModal: closeModal,
    openDrawer: openDrawer,
    closeDrawer: closeDrawer,
    openNotifications: openNotifications,
    openContextualHelp: openContextualHelp,
    openReportProblemModal: openReportProblemModal,
    _submitReportProblem: _submitReportProblem,
    toggleNavGroup: toggleNavGroup,
    toggleTheme: toggleTheme,
    toggleSidebar: toggleSidebar,
    openCommandPalette: openCommandPalette,
    logout: logout,
  };
})();
