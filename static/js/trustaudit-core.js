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
      { kind: '01. Home', title: 'Home', subtitle: 'Your business setup, next 3 steps & recent activity', href: '/app/home' },
      { kind: 'Setup', title: '5-Step Guided Onboarding', subtitle: 'Answer simple business questions & review suggestions', href: '/app/onboarding' },
      { kind: '02. My Business Data', title: 'Customer Information List', subtitle: 'Review confirmed & suggested customer data items', href: '/app/data-inventory' },
      { kind: '02. My Business Data', title: 'Where My Data Goes', subtitle: 'Interactive visual diagram of customer data flows', href: '/app/data-map' },
      { kind: '02. My Business Data', title: 'Companies I Share Data With', subtitle: 'Track external services & partners receiving data', href: '/app/vendors' },
      { kind: '02. My Business Data', title: 'Website Check', subtitle: 'Check public website notices, forms & trackers', href: '/app/website-check' },
      { kind: '03. My Privacy Tasks', title: 'Privacy Assessment', subtitle: '10 plain-language questions with practical guidance', href: '/app/assessment' },
      { kind: '03. My Privacy Tasks', title: 'Fix My Privacy Gaps', subtitle: 'Organise privacy tasks by owner & status', href: '/app/action-plan' },
      { kind: '03. My Privacy Tasks', title: 'Customer Requests', subtitle: 'Handle customer access, correction & deletion requests', href: '/app/privacy-requests' },
      { kind: '03. My Privacy Tasks', title: 'Vendor Reviews', subtitle: 'Track external agreements & questionnaires', href: '/app/vendor-reviews' },
      { kind: '04. Documents & Records', title: 'Privacy Notice', subtitle: 'Draft, edit & publish your customer Privacy Notice', href: '/app/notices' },
      { kind: '04. Documents & Records', title: 'My Documents & Suggestions', subtitle: 'Templates & document extraction drafts', href: '/app/document-centre' },
      { kind: '04. Documents & Records', title: 'Evidence (Documents & Proof)', subtitle: 'Upload agreements, notices & screenshots securely', href: '/app/evidence' },
      { kind: 'Help', title: 'AI Assistant', subtitle: 'Ask plain-English privacy & next-step questions', href: '/app/privacy-assistant' },
      { kind: 'Help', title: 'Learning Centre', subtitle: 'Plain-English privacy basics & official DPDP timeline', href: '/app/learning' },
      { kind: 'Workspace', title: 'Settings & 2FA', subtitle: 'Authenticator QR, recovery codes, team & sessions', href: '/app/settings' },
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
      '/app/home': ['Home Overview', 'Shows your 5 business setup milestones, top 3 recommended actions, 4 real data counts, and recent workspace events.'],
      '/app/onboarding': ['5-Step Onboarding', 'Answer simple questions about your business, run a quick website check, Confirm/Edit/Reject suggested items, and get your Top 3 Action Plan.'],
      '/app/data-inventory': ['Customer Information List', 'Lists what customer details you collect. Extracted items stay marked Suggested until you confirm them.'],
      '/app/data-map': ['Where My Data Goes', 'Visual diagram of your confirmed Customer Information moving through internal systems to external services.'],
      '/app/vendors': ['Companies I Share Data With', 'External tools, labs, or partners that receive customer data on your instructions (cloud hosts, billing, SMS, CRM).'],
      '/app/vendor-reviews': ['Vendor Reviews', 'Check written agreement status and send restricted questionnaires to external companies.'],
      '/app/website-check': ['Website Check', 'Inspects public pages for Privacy Notice links, enquiry forms, and third-party scripts cleanly.'],
      '/app/assessment': ['Privacy Assessment', 'Answer 10 plain-English topics and attach real proof; TrustAudit never invents compliance certificates.'],
      '/app/privacy-requests': ['Customer Requests', 'Track requests from customers wanting to see, correct, or erase their personal details.'],
      '/app/notices': ['Privacy Notice', 'Draft and review the plain-English notice explaining to customers what you collect and who to contact.'],
      '/app/document-centre': ['My Documents', 'Ready-to-edit document templates and spreadsheets/PDF discovery tools—kept Draft until reviewed.'],
      '/app/evidence': ['Documents & Proof (Evidence)', 'Store signed vendor agreements, notices, and retention logs securely.'],
      '/app/settings': ['Settings & 2FA', 'Enroll offline Authenticator QR 2FA, inspect 8 single-use recovery codes, revoke other sessions, or change password.'],
    };
    const item = guide[p] || ['TrustAudit Guided Help', 'Press Ctrl+K (or Cmd+K) anytime to jump across Home, My Business Data, My Privacy Tasks, Documents & Records, or Help.'];
    openModal('Help: ' + item[0],
      '<p style="font-size:14.5px;line-height:1.6;margin-bottom:14px;">' + esc(item[1]) + '</p>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
      '<a href="/app/privacy-assistant" class="btn btn-primary btn-sm">Ask AI Assistant</a>' +
      '<a href="/app/learning" class="btn btn-outline btn-sm">Learning Centre</a>' +
      '<button type="button" class="btn btn-ghost btn-sm" onclick="TA.openReportProblemModal()">Report Issue</button></div>'
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
