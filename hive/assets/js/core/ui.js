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

  function safeEscape(str) {
    if (Hive.format && Hive.format.escapeHtml) return Hive.format.escapeHtml(str);
    return String(str === undefined || str === null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Show a styled Fomantic-UI toast notification safely (XSS-hardened).
   */
  function notify(options) {
    var opts = options || {};
    var typeClass = opts.type || 'info'; // info | success | warning | error | honey

    if (typeof $.toast === 'function') {
      $.toast({
        title: String(opts.title || ''),
        message: String(opts.message || ''),
        preserveHTML: false,
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
            Hive.icons.render($modal[0]);
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

  /**
   * Show a unified accessible Fomantic-UI confirmation modal for destructive actions.
   */
  function confirm(options) {
    var opts = options || {};
    var $modal = $('#q-global-confirm-modal');
    if (!$modal.length) {
      $modal = $(
        '<div class="ui tiny modal q-shell-modal" id="q-global-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="q-global-confirm-title">' +
        '  <div class="header">' +
        '    <span id="q-global-confirm-title">Confirm Action</span>' +
        '    <button type="button" class="ui mini icon button q-btn-ghost" data-q-modal-close aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
        '  </div>' +
        '  <div class="content"><p class="q-text-secondary" id="q-global-confirm-msg" style="margin:0;line-height:1.55;"></p></div>' +
        '  <div class="actions">' +
        '    <button type="button" class="ui secondary cancel button" id="q-global-confirm-cancel">Cancel</button>' +
        '    <button type="button" class="ui button" id="q-global-confirm-ok">Confirm</button>' +
        '  </div>' +
        '</div>'
      ).appendTo('body');
    }

    $modal.find('#q-global-confirm-title').text(opts.title || 'Confirm Action');
    $modal.find('#q-global-confirm-msg').text(opts.message || 'Are you sure you want to proceed?');
    $modal.find('#q-global-confirm-cancel').text(opts.cancelText || 'Cancel');

    var isDanger = opts.danger !== false;
    var $okBtn = $modal.find('#q-global-confirm-ok');
    $okBtn
      .attr('class', isDanger ? 'ui negative button' : 'ui primary button')
      .html(safeEscape(opts.confirmText || 'Confirm'));

    $okBtn.off('click.qConfirm').on('click.qConfirm', function () {
      $modal.modal('hide');
      if (typeof opts.onConfirm === 'function') {
        opts.onConfirm();
      }
    });

    openModal($modal);
  }

  /**
   * Trigger a client-side file download from string/ArrayBuffer/Blob content.
   */
  function downloadBlob(filename, content, mimeType) {
    var blob = content instanceof Blob ? content : new Blob([content], { type: mimeType || 'text/plain;charset=utf-8' });
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename || 'download.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.setTimeout(function () {
      window.URL.revokeObjectURL(url);
    }, 1000);
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
    openModal: openModal,
    confirm: confirm,
    downloadBlob: downloadBlob
  };
})(window, window.jQuery);

