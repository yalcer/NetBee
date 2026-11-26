/* ==========================================================================
   Hive — System Module: Kernel Logs (#/system/kernel-logs)
   Live Linux Kernel Ring Buffer (dmesg) via /api/v1/logs/kernel
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    logs: [],
    search: '',
    subsystemFilter: 'all',
    levelFilter: 'all',
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-kern-log-modal').modal('hide').remove();
  }

  function getFiltered() {
    var q = state.search.toLowerCase();
    return state.logs.filter(function (row) {
      if (state.subsystemFilter !== 'all' && row.subsystem !== state.subsystemFilter) return false;
      if (state.levelFilter !== 'all' && row.level !== state.levelFilter) return false;
      if (q) {
        var hay = (row.bootTime + ' ' + row.subsystem + ' ' + row.level + ' ' + row.device + ' ' + row.message).toLowerCase();
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

  function refreshSubsystemDropdown() {
    if (!state.$root) return;
    var esc = Hive.format.escapeHtml;
    var seen = {};
    var subs = [];
    state.logs.forEach(function (r) {
      if (r.subsystem && !seen[r.subsystem]) {
        seen[r.subsystem] = true;
        subs.push(r.subsystem);
      }
    });
    subs.sort();
    var items = '<div class="item" data-value="all">All Subsystems</div>' +
      subs.map(function (s) { return '<div class="item" data-value="' + esc(s) + '">' + esc(s) + '</div>'; }).join('');
    var $dd = $('#q-klog-sub-dd');
    if ($dd.length) {
      $dd.find('.menu').html(items);
      $dd.dropdown('refresh');
    }
  }

  function renderTable() {
    if (!state.$root) return;
    var rows = getFiltered();
    var esc = Hive.format.escapeHtml;

    state.$root.find('#q-klog-count').text(rows.length + ' of ' + state.logs.length + ' ring entries');

    var $tbody = state.$root.find('#q-klog-tbody');
    if (!rows.length) {
      $tbody.html('<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--q-text-muted);">No kernel ring-buffer messages match the active filters.</td></tr>');
      return;
    }

    var lvlMap = {
      err:    { cls: 'q-status-danger',  dot: 'is-danger' },
      warn:   { cls: 'q-status-warning', dot: 'is-warning' },
      notice: { cls: 'q-status-success', dot: 'is-success' },
      info:   { cls: 'q-status-info',    dot: 'is-info' }
    };

    var html = rows
      .map(function (r) {
        var lv = lvlMap[r.level] || lvlMap.info;
        return (
          '<tr class="q-audit-row-clickable" data-id="' + esc(r.id) + '">' +
          '  <td class="q-mono q-text-muted" style="white-space:nowrap;">[' + esc(r.bootTime) + ']</td>' +
          '  <td><span class="ui label ' + lv.cls + ' q-mono"><span class="q-status-dot ' + lv.dot + '"></span>' + esc(r.level) + '</span></td>' +
          '  <td><span class="ui label q-badge-square q-mono">' + esc(r.subsystem) + '</span></td>' +
          '  <td class="q-mono q-text-secondary">' + esc(r.device || '—') + '</td>' +
          '  <td class="q-mono" style="font-size:12.5px;">' + esc(r.message) + '</td>' +
          '  <td><button type="button" class="ui mini icon button q-btn-ghost q-klog-view-btn" data-id="' + esc(r.id) + '" aria-label="Inspect kernel message"><i data-lucide="eye" class="q-icon q-icon-sm"></i></button></td>' +
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

    $('#q-klog-det-id').text(r.id);
    $('#q-klog-det-meta').html(
      '<div class="q-kv-row"><span class="q-kv-label">Monotonic Boot Offset</span><span class="q-kv-value q-mono">[' + esc(r.bootTime) + ']</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Subsystem / Device</span><span class="q-kv-value q-mono">' + esc(r.subsystem + ' · ' + (r.device || 'kernel')) + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Severity</span><span class="q-kv-value q-mono">kern.' + esc(r.level) + '</span></div>'
    );
    $('#q-klog-det-raw').text(r.raw || ('[' + r.bootTime + '] ' + r.subsystem + ': ' + r.message));
    Hive.ui.openModal('#q-kern-log-modal');
  }

  function loadAndRender() {
    var token = state.mountToken;
    return Hive.services.logs.listKernel(400).then(function (list) {
      if (!state.$root || token !== state.mountToken) return;
      state.logs = list;
      refreshSubsystemDropdown();
      renderTable();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.search = '';
    state.subsystemFilter = 'all';
    state.levelFilter = 'all';
    cleanupDetachedModals();

    Hive.services.logs.listKernel(400).then(function (list) {
      if (!state.$root || token !== state.mountToken) return;
      state.logs = list;

      var kernelName = (Hive.store && Hive.store.getState().system.kernel) || 'Linux aarch64';
      var esc = Hive.format.escapeHtml;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Kernel Logs</h1>' +
        '    <p class="q-page-subtitle">Live kernel ring buffer (<code>dmesg</code>) for <span class="q-mono">' + esc(kernelName) + '</span> — netfilter, NIC drivers, WireGuard, USB WAN, and CAKE.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <a href="#/system/service-logs" class="ui basic button"><i data-lucide="scroll-text" class="q-icon q-icon-sm"></i><span>Service Logs</span></a>' +
        '    <button type="button" class="ui secondary button" id="q-klog-poll-btn"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Refresh dmesg</span></button>' +
        '    <button type="button" class="ui basic primary button" id="q-klog-export-dmesg"><i data-lucide="download" class="q-icon q-icon-sm"></i><span>Export .log</span></button>' +
        '  </div>' +
        '</div>' +

        '<div class="q-toolbar">' +
        '  <div class="q-toolbar-left">' +
        '    <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-klog-search" placeholder="Search dmesg, eth0, eth1, nft..."></div>' +
        '    <div class="ui selection dropdown" id="q-klog-sub-dd" data-q-manual-init style="min-width:154px;">' +
        '      <input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Subsystems</div>' +
        '      <div class="menu"><div class="item" data-value="all">All Subsystems</div></div>' +
        '    </div>' +
        '    <div class="ui selection dropdown" id="q-klog-lvl-dd" data-q-manual-init style="min-width:130px;">' +
        '      <input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Levels</div>' +
        '      <div class="menu">' +
        '        <div class="item" data-value="all">All Levels</div>' +
        '        <div class="item" data-value="err">err</div>' +
        '        <div class="item" data-value="warn">warn</div>' +
        '        <div class="item" data-value="notice">notice</div>' +
        '        <div class="item" data-value="info">info</div>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +
        '  <div class="q-toolbar-right"><span class="ui label q-mono" id="q-klog-count"></span></div>' +
        '</div>' +

        '<div class="q-table-wrap">' +
        '  <table class="ui selectable striped table">' +
        '    <thead><tr><th style="width:136px;">Boot Offset</th><th style="width:94px;">Level</th><th style="width:128px;">Subsystem</th><th style="width:86px;">Device</th><th>Kernel Ring Message</th><th style="width:56px;">View</th></tr></thead>' +
        '    <tbody id="q-klog-tbody"></tbody>' +
        '  </table>' +
        '</div>' +

        '<div class="ui small modal" id="q-kern-log-modal" role="dialog" aria-labelledby="q-klog-det-title">' +
        '  <div class="header">' +
        '    <span class="q-modal-header-title" id="q-klog-det-title"><i data-lucide="cpu" class="q-icon q-text-accent"></i><span>Kernel Ring Entry <span class="q-mono" id="q-klog-det-id"></span></span></span>' +
        '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
        '  </div>' +
        '  <div class="content">' +
        '    <div class="q-kv-list" id="q-klog-det-meta" style="margin-bottom:var(--q-space-4);"></div>' +
        '    <div class="q-ds-group-label" style="margin-bottom:6px;font-size:11px;text-transform:uppercase;color:var(--q-text-muted);font-weight:600;">Raw dmesg Output</div>' +
        '    <pre class="q-code-block" id="q-klog-det-raw" style="white-space:pre-wrap;word-break:break-word;"></pre>' +
        '  </div>' +
        '  <div class="actions"><button type="button" class="ui primary cancel button">Close</button></div>' +
        '</div>';

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);

      $('#q-klog-sub-dd').dropdown({ onChange: function (v) { state.subsystemFilter = v || 'all'; renderTable(); } });
      $('#q-klog-lvl-dd').dropdown({ onChange: function (v) { state.levelFilter = v || 'all'; renderTable(); } });

      refreshSubsystemDropdown();
      renderTable();
    });

    $container.on('input.qKernLogs', '#q-klog-search', function () {
      state.search = $.trim($(this).val());
      renderTable();
    });

    $container.on('click.qKernLogs', '.q-audit-row-clickable', function () {
      openDetailModal($(this).attr('data-id'));
    });

    $container.on('click.qKernLogs', '#q-klog-poll-btn', function () {
      var $btn = $(this);
      $btn.addClass('loading');
      loadAndRender()
        .then(function () {
          Hive.ui.notify({ title: 'Kernel Ring Refreshed', message: 'Fetched latest dmesg lines.', type: 'info', displayTime: 1800 });
        })
        .finally(function () {
          if (state.$root) $btn.removeClass('loading');
        });
    });

    $container.on('click.qKernLogs', '#q-klog-export-dmesg', function () {
      var rows = getFiltered();
      downloadBlob(Hive.services.logs.toDmesgText(rows), 'text/plain;charset=utf-8', 'netbee-dmesg.log');
      Hive.ui.notify({ title: 'Kernel Log Exported', message: 'Downloaded netbee-dmesg.log (' + rows.length + ' lines).', type: 'success' });
    });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (reason === 'telemetry' || reason === 'flows-tick' || reason === 'audit' || reason === 'dmesg-refresh') return;
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
      state.$root.off('.qKernLogs');
      state.$root = null;
    }
  }

  Hive.router.register('/system/kernel-logs', {
    title: 'Kernel Logs',
    group: 'System',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
