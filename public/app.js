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

  /* Filter inputs: input[data-filter-target=".record-row"] hides elements
   * whose data-name (or text) does not contain the query. */
  document.querySelectorAll('input[data-filter-target]').forEach(function (input) {
    input.addEventListener('input', function () {
      var query = input.value.toLowerCase();
      document.querySelectorAll(input.dataset.filterTarget).forEach(function (el) {
        var haystack = (el.getAttribute('data-name') || el.textContent || '').toLowerCase();
        el.style.display = haystack.indexOf(query) !== -1 ? '' : 'none';
      });
    });
  });

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

  /* Theme toggle: persists an explicit choice in localStorage. */
  document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var root = document.documentElement;
      var dark = root.classList.toggle('dark');
      try { localStorage.setItem('theme', dark ? 'dark' : 'light'); } catch (e) { /* ignore */ }
    });
  });
})();
