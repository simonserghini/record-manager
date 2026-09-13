/*
 * All client behavior for Record Manager, replacing the former inline
 * onclick/onkeyup/onsubmit handlers and <script> blocks. Pages declare
 * behavior through data attributes; CSP script-src stays 'self'.
 */
(function () {
  'use strict';

  /* Forms marked data-confirm ask before submitting (destructive actions). */
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (form instanceof HTMLFormElement && form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
      e.preventDefault();
    }
  });

  /* Mobile drawer: body.nav-open slides the sidebar in; the scrim and the
   * Escape key close it again. */
  var navToggle = document.querySelector('[data-nav-toggle]');
  var closeNav = function () { document.body.classList.remove('nav-open'); };
  if (navToggle) navToggle.addEventListener('click', function () {
    document.body.classList.add('nav-open');
  });
  document.querySelectorAll('[data-nav-close]').forEach(function (el) {
    el.addEventListener('click', closeNav);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeNav();
  });

  /* Filter inputs: input[data-filter-target=".record-row"] hides elements
   * whose data-name (or text) does not contain the query. Used by the
   * dashboard's zone grid — the records table has its own combined filter
   * (type chips + text) below. */
  document.querySelectorAll('input[data-filter-target]').forEach(function (input) {
    input.addEventListener('input', function () {
      var query = input.value.toLowerCase();
      document.querySelectorAll(input.dataset.filterTarget).forEach(function (el) {
        var haystack = (el.getAttribute('data-name') || el.textContent || '').toLowerCase();
        el.style.display = haystack.indexOf(query) !== -1 ? '' : 'none';
      });
    });
  });

  /* Records table: type chips and the text search combine; the live count
   * and the "no matches" row stay truthful as filters narrow the view. */
  var chipBar = document.querySelector('[data-type-filters]');
  if (chipBar) {
    var rows = Array.prototype.slice.call(document.querySelectorAll('.record-row'));
    var searchInput = document.querySelector('[data-record-search]');
    var countEl = document.getElementById('record-count');
    var noMatches = document.querySelector('[data-no-matches]');
    var activeType = '*';

    var applyRecordFilters = function () {
      var query = searchInput ? searchInput.value.toLowerCase() : '';
      var visible = 0;
      rows.forEach(function (row) {
        var matchesType = activeType === '*' || row.getAttribute('data-type') === activeType;
        var haystack = (row.getAttribute('data-search') || '').toLowerCase();
        var show = matchesType && (!query || haystack.indexOf(query) !== -1);
        row.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      if (countEl) {
        countEl.textContent = 'Showing ' + visible + ' of ' + rows.length +
          (rows.length === 1 ? ' record' : ' records');
      }
      if (noMatches) noMatches.classList.toggle('hidden', visible !== 0 || rows.length === 0);
    };

    chipBar.querySelectorAll('[data-type-filter]').forEach(function (chip) {
      chip.addEventListener('click', function () {
        activeType = chip.getAttribute('data-type-filter');
        chipBar.querySelectorAll('[data-type-filter]').forEach(function (c) {
          c.classList.toggle('type-chip-active', c === chip);
        });
        applyRecordFilters();
      });
    });
    if (searchInput) searchInput.addEventListener('input', applyRecordFilters);
  }

  /* Panel togglers: button[data-toggle-target="#add-record-panel"]. */
  document.querySelectorAll('[data-toggle-target]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = document.querySelector(btn.dataset.toggleTarget);
      if (target) target.classList.toggle('hidden');
    });
  });

  /* Click-to-navigate cards: div[data-navigate="/domains/3"]. Inner links,
   * buttons and forms keep their own click behavior. */
  document.addEventListener('click', function (e) {
    if (e.target.closest('a, button, form, input, select')) return;
    var card = e.target.closest('[data-navigate]');
    if (card && card.dataset.navigate && card.dataset.navigate !== '#') {
      window.location.href = card.dataset.navigate;
    }
  });

  /* Copy-to-clipboard: button[data-copy="text"]. */
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      if (navigator.clipboard) navigator.clipboard.writeText(btn.dataset.copy);
      var original = btn.getAttribute('title');
      btn.setAttribute('title', 'Copied!');
      setTimeout(function () {
        if (original) btn.setAttribute('title', original); else btn.removeAttribute('title');
      }, 1200);
    });
  });

  /* Highlight the sidebar entry matching the current path. */
  var path = window.location.pathname;
  document.querySelectorAll('nav a').forEach(function (link) {
    var href = link.getAttribute('href');
    if (!href) return;
    if (href === path || (path.indexOf(href) === 0 && href !== '/' && href !== '/dashboard')) {
      link.classList.add('sidebar-active');
    }
  });

  /* Record forms: the proxy (orange cloud) toggle only applies to A/AAAA/CNAME
   * (the server forces it off otherwise), and the content field gets a
   * type-appropriate hint + placeholder so 20 record types stay learnable. */
  var PROXIABLE = ['A', 'AAAA', 'CNAME'];
  var CONTENT_HINTS = {
    A: { hint: 'IPv4 address, e.g. 203.0.113.10', placeholder: '203.0.113.10' },
    AAAA: { hint: 'IPv6 address, e.g. 2001:db8::1', placeholder: '2001:db8::1' },
    CNAME: { hint: 'Target hostname, e.g. host.example.com', placeholder: 'host.example.com' },
    TXT: { hint: 'Free-form text, e.g. "v=spf1 include:example.com ~all"', placeholder: '"v=spf1 ~all"' },
    MX: { hint: 'Mail server hostname — set its priority in the MX Priority field', placeholder: 'mail.example.com' },
    NS: { hint: 'Nameserver hostname, e.g. ns1.example.com', placeholder: 'ns1.example.com' },
    SRV: { hint: 'priority weight port target, e.g. 10 60 5060 sip.example.com', placeholder: '10 60 5060 sip.example.com' },
    CAA: { hint: 'flags tag "value", e.g. 0 issue "letsencrypt.org"', placeholder: '0 issue "letsencrypt.org"' }
  };
  document.querySelectorAll('select[name="type"]').forEach(function (select) {
    var form = select.closest('form');
    if (!form) return;
    var proxied = form.querySelector('input[name="proxied"]');
    var wrapper = proxied ? proxied.closest('div') : null;
    var content = form.querySelector('input[name="content"]');
    var hint = form.querySelector('[data-content-hint]');
    var sync = function () {
      if (wrapper) wrapper.classList.toggle('hidden', PROXIABLE.indexOf(select.value) === -1);
      var info = CONTENT_HINTS[select.value];
      if (content && info && info.placeholder && !content.value) content.placeholder = info.placeholder;
      if (hint) hint.textContent = info && info.hint ? info.hint : 'Record content (rdata), exactly as Cloudflare expects it.';
    };
    select.addEventListener('change', sync);
    sync();
  });

  /* Theme toggle: persists an explicit choice in localStorage. */
  document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var root = document.documentElement;
      var dark = root.classList.toggle('dark');
      try { localStorage.setItem('theme', dark ? 'dark' : 'light'); } catch (e) { /* ignore */ }
    });
  });
})();
