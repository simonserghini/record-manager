/*
 * Runs synchronously from <head> so the theme class is applied before first
 * paint (no flash of the wrong theme). Stored choice wins; otherwise follow
 * the OS preference. Kept dependency- and CSP-friendly: no inline handlers.
 */
(function () {
  try {
    var stored = localStorage.getItem('theme');
    var dark = stored ? stored === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (dark) document.documentElement.classList.add('dark');
  } catch (e) { /* storage blocked — stay on the light theme */ }
})();
