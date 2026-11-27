/* ==========================================================================
   Hive — Modular Client-Side Hash Router
   Manages route registry, mount()/unmount() lifecycle, breadcrumbs & fallback.
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});
  var registry = {};
  var activeModule = null;
  var activeRoute = '';
  var DEFAULT_ROUTE = '/overview/system';

  function register(route, moduleDef) {
    registry[route] = moduleDef;
  }

  function parseHash() {
    var raw = window.location.hash ? window.location.hash.slice(1) : '';
    if (!raw || raw === '/') return DEFAULT_ROUTE;
    return raw.charAt(0) === '/' ? raw : '/' + raw;
  }

  function findNavItem(route) {
    var groups = (Hive.config && Hive.config.navigation) || [];
    for (var i = 0; i < groups.length; i++) {
      var items = groups[i].items || [];
      for (var j = 0; j < items.length; j++) {
        if (items[j].route === route) {
          return items[j];
        }
      }
    }
    return null;
  }

  function unmountCurrent() {
    if (activeModule && typeof activeModule.unmount === 'function') {
      try {
        activeModule.unmount();
      } catch (err) {
        // Ensure navigation continues even if a module teardown fails
      }
    }
    activeModule = null;

    // Clean any orphaned detached module modals and unlock body scroll if no shell modal is open
    $('.ui.dimmer.modals.page > .ui.modal:not(.q-shell-modal)').remove();
    if (!$('.ui.modal.q-shell-modal.active').length) {
      $('.ui.dimmer.modals.page').removeClass('visible active animating');
      $('body').removeClass('dimmed scrolling');
    }
  }

  function navigate(route) {
    var normalized = route.charAt(0) === '/' ? route : '/' + route;
    if (window.location.hash === '#' + normalized) {
      resolve(normalized);
    } else {
      window.location.hash = '#' + normalized;
    }
  }

  function triggerViewEnter($el) {
    if (!$el || !$el.length) return;
    $el.removeClass('q-view-animate');
    // Force reflow so animation replays cleanly on route change
    void $el[0].offsetWidth;
    $el.addClass('q-view-animate');
  }

  function resolve(explicitRoute) {
    var route = explicitRoute || parseHash();
    if (route === '/foundation/shell') {
      route = DEFAULT_ROUTE;
    }
    var $mount = $('#q-module-mount');
    var $placeholder = $('#q-shell-placeholder-view');

    if (!$mount.length) return;

    unmountCurrent();
    activeRoute = route;

    $('.q-nav-item').removeClass('is-active');

    // Registered interactive module
    var mod = registry[route];
    var navItem = findNavItem(route);

    if (mod) {
      $placeholder.attr('hidden', true);
      $mount.removeAttr('hidden').empty();

      $('.q-nav-item')
        .filter(function () { return $(this).attr('data-q-route') === route; })
        .addClass('is-active');

      var groupName = mod.group || (navItem ? navItem.group : 'Module');
      var title = mod.title || (navItem ? navItem.label : 'Hive');

      Hive.shell.updateBreadcrumbs([
        { label: 'Hive', href: '#/overview/system' },
        { label: groupName },
        { label: title }
      ]);
      document.title = title + ' — Hive';

      activeModule = mod;
      mod.mount($mount);
      triggerViewEnter($mount);

      if (Hive.icons) Hive.icons.render($mount[0]);
      if (Hive.ui) Hive.ui.init($mount);
      return;
    }

    // Fallback: Unknown route placeholder
    $mount.empty().attr('hidden', true);
    $placeholder.removeAttr('hidden');
    triggerViewEnter($placeholder);

    if (navItem) {
      $('.q-nav-item')
        .filter(function () { return $(this).attr('data-q-route') === navItem.route; })
        .addClass('is-active');
      $('#q-placeholder-group').text(navItem.group);
      $('#q-placeholder-title').text(navItem.label);
      $('#q-placeholder-desc').text(navItem.description);
      $('#q-placeholder-route').text(navItem.route);
      $('#q-placeholder-icon-wrap').html('<i data-lucide="' + navItem.icon + '" class="q-icon q-icon-xl"></i>');

      Hive.shell.updateBreadcrumbs([
        { label: 'Hive', href: '#/overview/system' },
        { label: navItem.group },
        { label: navItem.label }
      ]);
      document.title = navItem.label + ' — Hive';
    } else {
      $('#q-placeholder-group').text('Route');
      $('#q-placeholder-title').text('Module Not Found');
      $('#q-placeholder-desc').text('No module is registered at this route.');
      $('#q-placeholder-route').text(route);
      $('#q-placeholder-icon-wrap').html('<i data-lucide="compass" class="q-icon q-icon-xl"></i>');
    }

    if (Hive.icons) Hive.icons.render();
  }

  function start() {
    $(window).off('hashchange.qRouter').on('hashchange.qRouter', function () {
      resolve();
    });
    resolve();
  }

  Hive.router = {
    defaultRoute: DEFAULT_ROUTE,
    register: register,
    navigate: navigate,
    resolve: resolve,
    current: function () { return activeRoute; },
    start: start
  };
})(window, window.jQuery);

