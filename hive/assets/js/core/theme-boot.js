/* ==========================================================================
   Hive — Pre-Paint Theme & Shell State Bootstrap
   Runs synchronously in <head> to prevent theme flash or sidebar jump.
   ========================================================================== */
(function () {
  var THEME_KEY = 'hive.theme';
  var LEGACY_THEME_KEY = 'quflows.theme';
  var SIDEBAR_KEY = 'hive.sidebarCollapsed';
  var LEGACY_SIDEBAR_KEY = 'quflows.sidebarCollapsed';
  var root = document.documentElement;

  function normalizeTheme(val) {
    if (val === 'light-honey' || val === 'light') return 'light-honey';
    return 'dark-honey';
  }

  try {
    var savedTheme = window.localStorage.getItem(THEME_KEY);
    if (!savedTheme) {
      var legacyTheme = window.localStorage.getItem(LEGACY_THEME_KEY);
      if (legacyTheme) {
        savedTheme = normalizeTheme(legacyTheme);
        window.localStorage.setItem(THEME_KEY, savedTheme);
      }
    }
    var theme = normalizeTheme(savedTheme);
    root.setAttribute('data-theme', theme);

    var collapsedRaw = window.localStorage.getItem(SIDEBAR_KEY);
    if (collapsedRaw === null) {
      collapsedRaw = window.localStorage.getItem(LEGACY_SIDEBAR_KEY);
    }
    if (collapsedRaw === 'true' && window.innerWidth > 992) {
      root.classList.add('q-sidebar-collapsed');
    }
  } catch (err) {
    root.setAttribute('data-theme', 'dark-honey');
  }
})();
