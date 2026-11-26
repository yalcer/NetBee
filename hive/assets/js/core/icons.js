/* ==========================================================================
   Hive — Lucide Icons Wrapper
   Provides safe initial and scoped icon rendering across dynamic DOM updates.
   ========================================================================== */
(function (window) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  function render(options) {
    if (!window.lucide || typeof window.lucide.createIcons !== 'function') {
      return;
    }
    var opts = Object.assign(
      {
        attrs: {
          'stroke-width': 1.75
        }
      },
      options || {}
    );
    window.lucide.createIcons(opts);
  }

  Hive.icons = {
    render: render
  };
})(window);

