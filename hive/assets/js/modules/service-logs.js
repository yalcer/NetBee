/* ==========================================================================
   Hive — System Module: Service Logs (#/system/service-logs)
   Live BusyBox RAM Syslog (/var/log/messages), Rotate/Clear & CSV/JSON Export
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    logs: [],
    linesLimit: 300,
    search: '',
    moduleFilter: 'all',
    severityFilter: 'all',
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-svc-log-modal').modal('hide').remove();
  }

  function getFiltered() {
    var q = state.search.toLowerCase();
    return state.logs.filter(function (row) {
      if (state.moduleFilter !== 'all' && row.module !== state.moduleFilter) return false;
      if (state.severityFilter !== 'all' && row.severity !== state.severityFilter) return false;
      if (q) {
        var hay = (row.timestamp + ' ' + row.actor + ' ' + row.sourceIp + ' ' + row.module + ' ' + row.summary).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
  }

  function downloadBlob(content, mime, filename) {
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function refreshProcessDropdown() {
    if (!state.$root) return;
    var esc = Hive.format.escapeHtml;
    var seen = {};
    var procs = [];
    state.logs.forEach(function (r) {
      if (r.module && !seen[r.module]) {
        seen[r.module] = true;
        procs.push(r.module);
      }
    });
    procs.sort();
    var items = '<div class="item" data-value="all">All Processes</div>' +
      procs.map(function (p) { return '<div class="item" data-value="' + esc(p) + '">' + esc(p) + '</div>'; }).join('');
    var $dd = $('#q-slog-mod-dd');
    if ($dd.length) {
      $dd.find('.menu').html(items);
      $dd.dropdown('refresh');
    }
  }

  function renderTable() {
    if (!state.$root) return;
    var rows = getFiltered();
    var esc = Hive.format.escapeHtml;

    state.$root.find('#q-slog-count').text(rows.length + ' of ' + state.logs.length + ' lines');

    var $tbody = state.$root.find('#q-slog-tbody');
    if (!rows.length) {
      $tbody.html('<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--q-text-muted);">No syslog entries match the active filters.</td></tr>');
      return;
    }

    var sevMap = {
      success: { cls: 'q-status-success', dot: 'is-success' },
      warning: { cls: 'q-status-warning', dot: 'is-warning' },
      error:   { cls: 'q-status-danger',  dot: 'is-danger' },
      info:    { cls: 'q-status-info',    dot: 'is-info' }
    };

    var html = rows
      .map(function (r) {
        var s = sevMap[r.severity] || sevMap.info;
        return (
          '<tr class="q-audit-row-clickable" data-id="' + esc(r.id) + '">' +
          '  <td class="q-mono q-text-secondary" style="white-space:nowrap;">' + esc(r.timestamp) + '</td>' +
          '  <td><span class="ui label ' + s.cls + '"><span class="q-status-dot ' + s.dot + '"></span>' + esc(r.severity) + '</span></td>' +
          '  <td><span class="ui label q-badge-square q-mono">' + esc(r.module) + '</span></td>' +
          '  <td class="q-mono q-text-secondary">' + esc(r.actor) + '</td>' +
          '  <td class="q-mono" style="font-size:12.5px;">' + esc(r.summary) + '</td>' +
          '  <td><button type="button" class="ui mini icon button q-btn-ghost q-slog-view-btn" data-id="' + esc(r.id) + '" aria-label="Inspect syslog line"><i data-lucide="eye" class="q-icon q-icon-sm"></i></button></td>' +
          '</tr>'
        );
      })
      .join('');

    $tbody.html(html);
    if (Hive.icons) Hive.icons.render();
  }

  function openDetailModal(id) {
    var r = state.logs.find(function (x) { return x.id === id; });
    if (!r) return;
    var esc = Hive.format.escapeHtml;
    $('#q-slog-det-id').text(r.id);
    $('#q-slog-det-meta').html(
      '<div class="q-kv-row"><span class="q-kv-label">Timestamp</span><span class="q-kv-value q-mono">' + esc(r.timestamp) + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Process / PID</span><span class="q-kv-value q-mono">' + esc(r.module + ' (' + r.actor + ')') + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Facility.Level</span><span class="q-kv-value q-mono">' + esc(((r.details && r.details.facility) || 'daemon') + '.' + ((r.details && r.details.level) || r.severity)) + '</span></div>'
    );
    $('#q-slog-det-raw').text(r.raw || r.summary);
    Hive.ui.openModal('#q-svc-log-modal');
  }

  function loadAndRender() {
    var token = state.mountToken;
    return Hive.services.logs.listService(state.linesLimit).then(function (list) {
      if (!state.$root || token !== state.mountToken) return;
      state.logs = list;
      refreshProcessDropdown();
      renderTable();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.search = '';
    state.moduleFilter = 'all';
    state.severityFilter = 'all';
    state.linesLimit = 300;
    cleanupDetachedModals();

    Hive.services.logs.listService(state.linesLimit).then(function (list) {
      if (!state.$root || token !== state.mountToken) return;
      state.logs = list;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Service Logs</h1>' +
        '    <p class="q-page-subtitle">Live BusyBox RAM syslog (<code>/var/log/messages</code>) across <code>netbeed</code>, Dropbear, AdGuardHome, dhcpcd, PPPoE, and crond.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <a href="#/system/kernel-logs" class="ui basic button"><i data-lucide="cpu" class="q-icon q-icon-sm"></i><span>Kernel Logs</span></a>' +
        '    <button type="button" class="ui basic button" id="q-slog-rotate-btn"><i data-lucide="archive" class="q-icon q-icon-sm"></i><span>Rotate</span></button>' +
        '    <button type="button" class="ui basic negative button" id="q-slog-clear-btn"><i data-lucide="trash-2" class="q-icon q-icon-sm"></i><span>Clear</span></button>' +
        '    <button type="button" class="ui secondary button" id="q-slog-refresh-btn"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Refresh</span></button>' +
        '    <button type="button" class="ui basic primary button" id="q-slog-export-csv"><i data-lucide="download" class="q-icon q-icon-sm"></i><span>CSV</span></button>' +
        '  </div>' +
        '</div>' +

        '<div class="q-toolbar">' +
        '  <div class="q-toolbar-left">' +
        '    <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-slog-search" placeholder="Search process, PID, message..."></div>' +
        '    <div class="ui selection dropdown" id="q-slog-mod-dd" data-q-manual-init style="min-width:154px;">' +
        '      <input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Processes</div>' +
        '      <div class="menu"><div class="item" data-value="all">All Processes</div></div>' +
        '    </div>' +
        '    <div class="ui selection dropdown" id="q-slog-sev-dd" data-q-manual-init style="min-width:135px;">' +
        '      <input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Severities</div>' +
        '      <div class="menu">' +
        '        <div class="item" data-value="all">All Severities</div>' +
        '        <div class="item" data-value="info">Info</div>' +
        '        <div class="item" data-value="success">Success</div>' +
        '        <div class="item" data-value="warning">Warning</div>' +
        '        <div class="item" data-value="error">Error</div>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +
        '  <div class="q-toolbar-right"><span class="ui label q-mono" id="q-slog-count"></span></div>' +
        '</div>' +

        '<div class="q-table-wrap">' +
        '  <table class="ui selectable striped table">' +
        '    <thead><tr><th style="width:142px;">Timestamp</th><th style="width:104px;">Severity</th><th style="width:132px;">Process</th><th style="width:94px;">PID</th><th>Syslog Message</th><th style="width:56px;">View</th></tr></thead>' +
        '    <tbody id="q-slog-tbody"></tbody>' +
        '  </table>' +
        '</div>' +

        '<div class="ui small modal" id="q-svc-log-modal" role="dialog" aria-labelledby="q-slog-det-title">' +
        '  <div class="header">' +
        '    <span class="q-modal-header-title" id="q-slog-det-title"><i data-lucide="scroll-text" class="q-icon q-text-accent"></i><span>Syslog Entry <span class="q-mono" id="q-slog-det-id"></span></span></span>' +
        '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
        '  </div>' +
        '  <div class="content">' +
        '    <div class="q-kv-list" id="q-slog-det-meta" style="margin-bottom:var(--q-space-4);"></div>' +
        '    <div class="q-ds-group-label" style="margin-bottom:6px;font-size:11px;text-transform:uppercase;color:var(--q-text-muted);font-weight:600;">Raw Syslog Line</div>' +
        '    <pre class="q-code-block" id="q-slog-det-raw" style="white-space:pre-wrap;word-break:break-word;"></pre>' +
        '  </div>' +
        '  <div class="actions"><button type="button" class="ui primary cancel button">Close</button></div>' +
        '</div>';

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);

      $('#q-slog-mod-dd').dropdown({ onChange: function (v) { state.moduleFilter = v || 'all'; renderTable(); } });
      $('#q-slog-sev-dd').dropdown({ onChange: function (v) { state.severityFilter = v || 'all'; renderTable(); } });

      refreshProcessDropdown();
      renderTable();
    });

    $container.on('input.qSvcLogs', '#q-slog-search', function () {
      state.search = $.trim($(this).val());
      renderTable();
    });

    $container.on('click.qSvcLogs', '#q-slog-refresh-btn', function () {
      var $btn = $(this);
      $btn.addClass('loading');
      loadAndRender().finally(function () {
        if (state.$root) $btn.removeClass('loading');
      });
    });

    $container.on('click.qSvcLogs', '#q-slog-rotate-btn', function () {
      Hive.services.logs.rotate().then(function () {
        Hive.ui.notify({ title: 'Logs Rotated', message: 'Executed logrotate -f /etc/logrotate.conf.', type: 'success' });
        loadAndRender();
      });
    });

    $container.on('click.qSvcLogs', '#q-slog-clear-btn', function () {
      Hive.services.logs.clear().then(function () {
        Hive.ui.notify({ title: 'RAM Syslog Cleared', message: 'Truncated /var/log/messages.', type: 'warning' });
        loadAndRender();
      });
    });

    $container.on('click.qSvcLogs', '.q-audit-row-clickable', function () {
      openDetailModal($(this).attr('data-id'));
    });

    $container.on('click.qSvcLogs', '#q-slog-export-csv', function () {
      var rows = getFiltered();
      downloadBlob(Hive.services.logs.toServiceCsv(rows), 'text/csv;charset=utf-8', 'netbee-syslog.csv');
      Hive.ui.notify({ title: 'Syslog Exported', message: 'Downloaded ' + rows.length + ' lines as CSV.', type: 'success' });
    });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (reason === 'telemetry' || reason === 'flows-tick' || reason === 'kernel-log' || reason === 'syslog-refresh') return;
      loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qSvcLogs');
      state.$root = null;
    }
  }

  Hive.router.register('/system/service-logs', {
    title: 'Service Logs',
    group: 'System',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
