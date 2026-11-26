/* ==========================================================================
   Hive — Centralized Fomantic-UI Initializer & Component Helpers
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  /**
   * Initialize all standard Fomantic-UI interactive widgets inside a scope.
   */
  function init(scope) {
    var $root = scope ? $(scope) : $(document);

    // Dropdowns (skip ones flagged with data-q-manual-init)
    $root.find('.ui.dropdown:not([data-q-manual-init])').each(function () {
      var $el = $(this);
      var allowAdditions = $el.is('[data-allow-additions]');
      $el.dropdown({
        allowAdditions: allowAdditions,
        fullTextSearch: 'exact'
      });
    });

    // Checkboxes, Radios & Toggles
    $root.find('.ui.checkbox').checkbox();

    // Tabs: initialize each menu's items as a single collection so the initial .active tab is preserved
    $root.find('.ui.menu').each(function () {
      var $menu = $(this);
      var $items = $menu.find('.item[data-tab]');
      if (!$items.length) return;
      var context = $menu.attr('data-tab-context');

      $items.tab({
        context: context || 'parent',
        autoTabActivation: false,
        onVisible: function () {
          var $pane = $(this);
          $pane.find('.ui.progress').progress();
          $pane.find('.ui.dropdown').dropdown('refresh');
        }
      });
    });

    // Progress bars
    $root.find('.ui.progress').each(function () {
      var $bar = $(this);
      var percent = $bar.attr('data-percent');
      if (percent !== undefined) {
        $bar.progress({ percent: Number(percent) });
      } else {
        $bar.progress();
      }
    });

    // Tooltips / Popups
    $root.find('[data-q-popup]').each(function () {
      var $trigger = $(this);
      var position = $trigger.attr('data-position') || 'top center';
      var htmlTarget = $trigger.attr('data-popup-target');

      var popupOpts = {
        position: position,
        hoverable: true,
        delay: { show: 120, hide: 80 }
      };

      if (htmlTarget) {
        popupOpts.popup = $(htmlTarget);
        popupOpts.on = $trigger.attr('data-popup-on') || 'hover';
      }

      $trigger.popup(popupOpts);
    });

    // Dismissible Alerts (.ui.message)
    $root.off('click.qMessage').on('click.qMessage', '.ui.message .q-message-close', function () {
      $(this).closest('.ui.message').transition('fade');
    });
  }

  /**
   * Show a styled Fomantic-UI toast notification.
   */
  function notify(options) {
    var opts = options || {};
    var typeClass = opts.type || 'info'; // info | success | warning | error | honey

    if (typeof $.toast === 'function') {
      $.toast({
        title: opts.title || '',
        message: opts.message || '',
        class: typeClass === 'honey' || typeClass === 'ocean' ? '' : typeClass,
        displayTime: opts.displayTime !== undefined ? opts.displayTime : 3600,
        showProgress: opts.showProgress !== undefined ? opts.showProgress : 'bottom',
        position: opts.position || 'top right',
        closeIcon: opts.closeIcon !== undefined ? opts.closeIcon : false,
        compact: false
      });
    }
  }

  /**
   * Open a Fomantic-UI modal cleanly with accessible focus handling.
   */
  function openModal(selector, options) {
    var $modal = $(selector);
    if (!$modal.length) return;

    var config = Object.assign(
      {
        autofocus: true,
        restoreFocus: true,
        transition: 'scale',
        duration: 180,
        onShow: function () {
          if (Hive.icons) {
            Hive.icons.render();
          }
          $modal.find('.ui.dropdown:not([data-q-manual-init])').each(function () {
            var $dd = $(this);
            if ($dd.data('moduleDropdown')) {
              $dd.dropdown('refresh');
            } else {
              $dd.dropdown();
            }
          });
          $modal.find('.ui.checkbox').each(function () {
            var $chk = $(this);
            if (!$chk.data('moduleCheckbox')) {
              $chk.checkbox();
            }
          });
        }
      },
      options || {}
    );

    $modal.modal(config).modal('show');
  }

  // Handle modal header close (X) buttons cleanly across all inline and body-detached modals
  $(document)
    .off('click.qModalHeaderClose')
    .on('click.qModalHeaderClose', '.ui.modal > .header .cancel, .ui.modal [data-q-modal-close]', function (e) {
      e.preventDefault();
      $(this).closest('.ui.modal').modal('hide');
    });

  Hive.ui = {
    init: init,
    notify: notify,
    openModal: openModal
  };
})(window, window.jQuery);

