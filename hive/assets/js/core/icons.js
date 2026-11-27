/* ==========================================================================
   Hive — Lucide Icons Wrapper
   Provides safe initial and scoped icon rendering across dynamic DOM updates.
   ========================================================================== */
(function (window) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  function render(scope, options) {
    if (!window.lucide || typeof window.lucide.createIcons !== 'function') {
      return;
    }
    var hasScope = scope && (scope.nodeType === 1 || scope.nodeType === 9);
    var root = hasScope ? scope : document;
    var rawOpts = hasScope ? options : scope;
    if (!root.querySelector('i[data-lucide]')) {
      return;
    }
    var opts = Object.assign(
      {
        attrs: {
          'stroke-width': 1.75
        }
      },
      rawOpts || {}
    );
    window.lucide.createIcons(opts);
    var rendered = document.querySelectorAll('svg[data-lucide]');
    for (var i = 0; i < rendered.length; i++) {
      rendered[i].removeAttribute('data-lucide');
    }
  }

  Hive.icons = {
    render: render
  };
})(window);

