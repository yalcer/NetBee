/* ==========================================================================
   Hive — Theme Manager (Dark Honey default + Light Honey theme)
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});
  var STORAGE_KEY = (Hive.config && Hive.config.storageKeys.theme) || 'hive.theme';
  var LEGACY_KEY = 'quflows.theme';

  function normalizeTheme(theme) {
    if (theme === 'light-honey' || theme === 'light') return 'light-honey';
    return 'dark-honey';
  }

  function themeDisplayName(theme) {
    return theme === 'light-honey' ? 'Light Honey' : 'Dark Honey';
  }

  function getTheme() {
    var attr = document.documentElement.getAttribute('data-theme');
    return normalizeTheme(attr);
  }

  function syncControls(theme) {
    var isLight = theme === 'light-honey';
    var nextLabel = isLight ? 'Switch to Dark Honey theme' : 'Switch to Light Honey theme';
    var activeLabel = themeDisplayName(theme);

    $('[data-q-theme-toggle]').each(function () {
      var $btn = $(this);
      $btn.attr('aria-pressed', String(isLight));
      $btn.attr('aria-label', nextLabel);
      $btn.attr('data-tooltip', nextLabel + ' (Alt+T)');
    });

    $('[data-q-theme-label]').text(activeLabel);
    $('[data-q-set-theme]').each(function () {
      var $el = $(this);
      var target = normalizeTheme($el.attr('data-q-set-theme'));
      if ($el.closest('.ui.buttons').length) {
        $el.toggleClass('active', target === theme);
        $el.attr('aria-pressed', String(target === theme));
      }
    });
    $('[data-q-theme-select]').each(function () {
      var $el = $(this);
      if ($el.hasClass('dropdown') && typeof $el.dropdown === 'function') {
        $el.dropdown('set selected', theme);
      }
    });
  }

  function setTheme(theme, options) {
    var next = normalizeTheme(theme);
    var opts = options || {};

    document.documentElement.setAttribute('data-theme', next);

    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch (err) {
      // Ignore storage failures in restricted contexts
    }

    syncControls(next);

    var event = new CustomEvent('hive:themechange', {
      detail: { theme: next, label: themeDisplayName(next) }
    });
    window.dispatchEvent(event);

    if (opts.notify && Hive.ui && typeof Hive.ui.notify === 'function') {
      Hive.ui.notify({
        title: 'Theme Updated',
        message: 'Active theme set to ' + themeDisplayName(next) + '.',
        type: 'info',
        displayTime: 2200
      });
    }

    return next;
  }

  function toggleTheme(options) {
    var next = getTheme() === 'dark-honey' ? 'light-honey' : 'dark-honey';
    return setTheme(next, options);
  }

  function init() {
    var initial = 'dark-honey';
    try {
      var stored = window.localStorage.getItem(STORAGE_KEY) || window.localStorage.getItem(LEGACY_KEY);
      if (stored) {
        initial = normalizeTheme(stored);
      }
    } catch (err) {
      initial = getTheme();
    }

    setTheme(initial, { notify: false });

    $(document).on('click', '[data-q-theme-toggle]', function (e) {
      e.preventDefault();
      toggleTheme({ notify: false });
    });

    $(document).on('click', '[data-q-set-theme]', function (e) {
      e.preventDefault();
      var target = $(this).attr('data-q-set-theme');
      setTheme(target, { notify: true });
    });
  }

  Hive.theme = {
    get: getTheme,
    set: setTheme,
    toggle: toggleTheme,
    init: init
  };
})(window, window.jQuery);
