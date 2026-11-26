/* ==========================================================================
   Hive — Design System / UI Component Showcase Interactions
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  function rgbToHex(rgb) {
    if (!rgb || rgb.indexOf('rgb') !== 0) return rgb || '';
    var parts = rgb.match(/\d+/g);
    if (!parts || parts.length < 3) return rgb;
    return (
      '#' +
      parts
        .slice(0, 3)
        .map(function (n) {
          var hex = parseInt(n, 10).toString(16).toUpperCase();
          return hex.length === 1 ? '0' + hex : hex;
        })
        .join('')
    );
  }

  function refreshSwatchReadouts() {
    var computed = window.getComputedStyle(document.documentElement);
    $('[data-q-token]').each(function () {
      var $card = $(this);
      var token = $card.attr('data-q-token');
      var raw = computed.getPropertyValue(token).trim();
      if (!raw) {
        raw = rgbToHex(window.getComputedStyle($card.find('.q-swatch-color')[0]).backgroundColor);
      }
      $card.find('[data-q-token-value]').text(raw.toUpperCase());
    });
  }

  function initSwatches() {
    refreshSwatchReadouts();
    window.addEventListener('hive:themechange', refreshSwatchReadouts);

    $(document).on('click', '[data-q-token]', function () {
      var token = $(this).attr('data-q-token');
      var val = $(this).find('[data-q-token-value]').text();
      var copyStr = 'var(' + token + ')';

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(copyStr).catch(function () {});
      }

      Hive.ui.notify({
        title: 'Token Copied',
        message: copyStr + ' (' + val + ')',
        type: 'info',
        displayTime: 2200
      });
    });
  }

  function initButtonDemos() {
    $('#q-demo-loading-btn').on('click', function () {
      var $btn = $(this);
      if ($btn.hasClass('loading')) return;

      $btn.addClass('loading disabled');
      window.setTimeout(function () {
        $btn.removeClass('loading disabled');
        Hive.ui.notify({
          title: 'Action Complete',
          message: 'Simulated policy syntax check passed cleanly.',
          type: 'success',
          displayTime: 2600
        });
      }, 1100);
    });

    // Interactive segmented button group
    $('#q-demo-btn-group .button').on('click', function () {
      $(this).addClass('active').siblings().removeClass('active');
    });

    // Make all showcase demo buttons responsive with subtle toast feedback
    $('#buttons').on('click', '.ui.button:not(#q-demo-loading-btn):not(#q-demo-btn-group .button):not(:disabled)', function () {
      var label = $.trim($(this).text()) || $(this).attr('aria-label') || 'Action';
      var type = $(this).hasClass('negative') ? 'error' : $(this).hasClass('warning') ? 'warning' : $(this).hasClass('positive') ? 'success' : 'info';
      Hive.ui.notify({
        title: 'Button Triggered',
        message: '"' + label + '" button clicked (showcase preview).',
        type: type,
        displayTime: 1800
      });
    });

    $('#theme-comparison .q-card').on('click', '.ui.button', function () {
      var label = $.trim($(this).text()) || 'Action';
      var frameTheme = $(this).closest('.q-theme-frame').attr('data-theme') === 'light-honey' ? 'Light Honey' : 'Dark Honey';
      Hive.ui.notify({
        title: frameTheme + ' Preview',
        message: '"' + label + '" clicked inside scoped ' + frameTheme + ' card.',
        type: 'info',
        displayTime: 1800
      });
    });
  }

  function initFormDemo() {
    var ipv4CidrRe = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(\/([0-9]|[12]\d|3[0-2]))?$/;

    $('#q-demo-form').on('submit', function (e) {
      e.preventDefault();
      var $cidrField = $('#q-demo-cidr-field');
      var $cidrInput = $('#q-demo-cidr-input');
      var $cidrError = $('#q-demo-cidr-error');
      var val = $.trim($cidrInput.val());

      if (!ipv4CidrRe.test(val)) {
        $cidrField.addClass('error');
        $cidrError.removeAttr('hidden');
        Hive.ui.notify({
          title: 'Validation Failed',
          message: 'Enter a valid IPv4 address or CIDR prefix (e.g. 10.20.0.0/24).',
          type: 'error',
          displayTime: 3200
        });
        $cidrInput.trigger('focus');
        return;
      }

      $cidrField.removeClass('error');
      $cidrError.attr('hidden', true);
      Hive.ui.notify({
        title: 'Form Validated',
        message: 'Sample subnet ' + val + ' validated (frontend preview only).',
        type: 'success',
        displayTime: 2800
      });
    });

    $('#q-demo-form-reset').on('click', function () {
      $('#q-demo-cidr-field').removeClass('error');
      $('#q-demo-cidr-error').attr('hidden', true);
    });
  }

  function initTableDemo() {
    var $table = $('#q-demo-table');
    var $search = $('#q-table-search');
    var $zoneFilter = $('#q-table-zone-filter');
    var $countBadge = $('#q-table-selected-count');

    function applyFilters() {
      var query = $.trim($search.val()).toLowerCase();
      var zone = $zoneFilter.dropdown('get value') || 'all';
      var visible = 0;

      $table.find('tbody tr[data-zone]').each(function () {
        var $row = $(this);
        var rowZone = $row.attr('data-zone');
        var text = $row.text().toLowerCase();
        var matchZone = zone === 'all' || rowZone === zone;
        var matchQuery = !query || text.indexOf(query) !== -1;

        $row.toggle(matchZone && matchQuery);
        if (matchZone && matchQuery) visible++;
      });

      $('#q-table-empty-row').toggle(visible === 0);
      var total = $table.find('tbody tr[data-zone]').length;
      $('#q-table-record-count').text('Sample data · ' + visible + ' of ' + total + ' records');
      syncCheckAllState();
    }

    function syncCheckAllState() {
      var $visibleChecks = $table.find('tbody tr[data-zone]:visible .q-row-check input');
      var total = $visibleChecks.length;
      var checked = $visibleChecks.filter(':checked').length;
      var $all = $('#q-table-check-all');
      if (total > 0 && checked === total) {
        $all.checkbox('set checked');
      } else if (checked > 0) {
        $all.checkbox('set indeterminate');
      } else {
        $all.checkbox('set unchecked');
      }
    }

    function updateSelectionCount() {
      var checked = $table.find('tbody .q-row-check input:checked').length;
      if (checked > 0) {
        $countBadge.text(checked + ' selected').removeAttr('hidden');
      } else {
        $countBadge.attr('hidden', true);
      }
      syncCheckAllState();
    }

    $search.on('input', applyFilters);
    $zoneFilter.dropdown({
      onChange: applyFilters
    });

    $table.on('change', '.q-row-check input', function () {
      var $row = $(this).closest('tr');
      $row.toggleClass('active', this.checked);
      updateSelectionCount();
    });

    $('#q-table-check-all').on('change', 'input', function () {
      var isChecked = this.checked;
      $table.find('tbody tr[data-zone]:visible .q-row-check').each(function () {
        $(this).checkbox(isChecked ? 'check' : 'uncheck');
      });
      updateSelectionCount();
    });
  }

  function initAlertsAndToasts() {
    $(document).on('click', '[data-q-toast-demo]', function () {
      var kind = $(this).attr('data-q-toast-demo');
      var presets = {
        honey: {
          title: 'Hive Ready',
          message: 'Hive Honey notification dispatched from Fomantic-UI toast.',
          type: 'honey'
        },
        success: {
          title: 'Configuration Applied',
          message: 'Rule set revision #418 committed without packet loss.',
          type: 'success'
        },
        warning: {
          title: 'Gateway Latency Elevated',
          message: 'Primary uplink RTT reached 48ms on eth0.',
          type: 'warning'
        },
        error: {
          title: 'Handshake Failed',
          message: 'Peer 198.51.100.42:51820 did not respond within 5s.',
          type: 'error'
        },
        info: {
          title: 'Backup Snapshot Exported',
          message: 'Encrypted XML snapshot saved locally (mock preview).',
          type: 'info'
        }
      };

      Hive.ui.notify(presets[kind] || presets.honey);
    });

    $('#q-restore-alerts-btn').on('click', function () {
      $('#q-demo-alerts .ui.message')
        .removeClass('hidden transition visible')
        .css({ display: '', opacity: '' });
    });
  }

  function initModals() {
    $('#q-open-confirm-modal').on('click', function () {
      Hive.ui.openModal('#q-demo-confirm-modal', {
        onApprove: function () {
          Hive.ui.notify({
            title: 'Confirmed',
            message: 'Changes applied cleanly.',
            type: 'success'
          });
        }
      });
    });

    $('#q-open-form-modal').on('click', function () {
      Hive.ui.openModal('#q-demo-form-modal', {
        onApprove: function () {
          var alias = $.trim($('#q-modal-alias-name').val()) || 'trusted_nets';
          Hive.ui.notify({
            title: 'Alias Saved',
            message: 'Network alias "' + alias + '" saved (preview only).',
            type: 'success'
          });
        }
      });
    });

    $('#q-open-danger-modal').on('click', function () {
      Hive.ui.openModal('#q-demo-danger-modal', {
        onApprove: function () {
          Hive.ui.notify({
            title: 'State Flushed',
            message: 'Simulated connection state table reset completed.',
            type: 'warning'
          });
        }
      });
    });
  }

  function initProgressDemo() {
    var $bar = $('#q-interactive-progress');
    var current = 64;

    function updateProgress(val) {
      current = Math.max(0, Math.min(100, val));
      $bar.removeClass('success warning error');
      if (current === 100) {
        $bar.addClass('success');
      } else if (current >= 90) {
        $bar.addClass('error');
      } else if (current >= 75) {
        $bar.addClass('warning');
      }
      $bar.progress('set percent', current);
      $('#q-interactive-progress-val').text(current + '%');
    }

    $('#q-prog-dec').on('click', function () {
      updateProgress(current - 15);
    });

    $('#q-prog-inc').on('click', function () {
      updateProgress(current + 15);
    });

    $('#q-prog-complete').on('click', function () {
      updateProgress(100);
    });

    $('#q-prog-reset').on('click', function () {
      updateProgress(35);
    });
  }

  function initJumpNav() {
    $('.q-ds-nav-link').on('click', function () {
      $('.q-ds-nav-link').removeClass('is-active');
      $(this).addClass('is-active');
    });

    // Scroll-spy keeps active jump pill synchronized as user scrolls
    if ('IntersectionObserver' in window) {
      var sections = document.querySelectorAll('.q-ds-section[id]');
      var observer = new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) {
              var id = entry.target.getAttribute('id');
              $('.q-ds-nav-link').removeClass('is-active').filter('[href="#' + id + '"]').addClass('is-active');
            }
          });
        },
        { rootMargin: '-20% 0px -65% 0px', threshold: 0 }
      );
      sections.forEach(function (sec) { observer.observe(sec); });
    }

    // Demo link card click
    $('#q-demo-link-card').on('click', function (e) {
      e.preventDefault();
      Hive.ui.notify({
        title: 'Interactive Card',
        message: 'Link card surface clicked.',
        type: 'info',
        displayTime: 2200
      });
    });

    // Demo vertical secondary menu & pagination clicks
    $('#q-demo-vertical-menu').on('click', '.item', function (e) {
      e.preventDefault();
      $(this).addClass('active').siblings('.item').removeClass('active');
    });

    $('#q-demo-pagination').on('click', '.item[data-page]', function (e) {
      e.preventDefault();
      $(this).addClass('active').siblings('.item[data-page]').removeClass('active');
    });

    $('#q-demo-pagination').on('click', '.item[data-dir]', function (e) {
      e.preventDefault();
      var dir = $(this).attr('data-dir');
      var $pages = $('#q-demo-pagination .item[data-page]');
      var idx = $pages.index($pages.filter('.active'));
      var nextIdx = dir === 'next' ? Math.min($pages.length - 1, idx + 1) : Math.max(0, idx - 1);
      $pages.removeClass('active').eq(nextIdx).addClass('active');
    });
  }

  $(document).ready(function () {
    if (document.body.getAttribute('data-q-page') !== 'design-system') return;

    initSwatches();
    initButtonDemos();
    initFormDemo();
    initTableDemo();
    initAlertsAndToasts();
    initModals();
    initProgressDemo();
    initJumpNav();
  });
})(window, window.jQuery);

