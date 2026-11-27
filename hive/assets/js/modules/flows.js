/* ==========================================================================
   Hive — Flow Summary (#/overview/flows)
   Live nf_conntrack table inspection, single-flow termination & table flush.
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    flows: [],
    search: '',
    zone: 'all',
    proto: 'all',
    flowState: 'all',
    liveEnabled: true,
    timerId: null
  };

  function cleanupDetachedModals() {
    $('#q-flow-inspect-modal').modal('hide').remove();
  }

  function formatDuration(sec) {
    var s = Math.max(0, Math.floor(Number(sec || 0)));
    if (s < 60) return s + 's';
    var m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + (s % 60) + 's';
    var h = Math.floor(m / 60);
    return h + 'h ' + (m % 60) + 'm';
  }

  function formatTransferMb(mb) {
    var val = Number(mb || 0);
    if (val >= 1024) return (val / 1024).toFixed(2) + ' GB';
    if (val >= 10) return val.toFixed(1) + ' MB';
    return val.toFixed(2) + ' MB';
  }

  function getFiltered() {
    var q = state.search.toLowerCase();
    return state.flows.filter(function (f) {
      if (state.zone !== 'all' && f.zone !== state.zone) return false;
      if (state.proto !== 'all' && f.protocol !== state.proto) return false;
      if (state.flowState !== 'all' && f.state.indexOf(state.flowState) === -1) return false;
      if (q) {
        var hay = (f.protocol + ' ' + f.srcIp + ':' + f.srcPort + ' ' + f.dstIp + ':' + f.dstPort + ' ' + f.state + ' ' + f.raw).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
  }

  function renderModalsHtml() {
    return (
      '<div class="ui small modal" id="q-flow-inspect-modal" role="dialog" aria-labelledby="q-flow-insp-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-flow-insp-title"><i data-lucide="waves" class="q-icon q-text-accent"></i><span>Conntrack State Inspector</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content"><div class="q-kv-list" id="q-fi-details"></div></div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui basic negative button" id="q-fi-kill-btn"><i data-lucide="circle-x" class="q-icon q-icon-sm"></i><span>Terminate Flow</span></button>' +
      '    <button type="button" class="ui primary cancel button">Close</button>' +
      '  </div>' +
      '</div>'
    );
  }

  function updateSummaryAndTable() {
    if (!state.$root) return;
    var fmt = Hive.format;
    var esc = fmt.escapeHtml;
    var sys = Hive.store.getState().system || {};

    var established = state.flows.filter(function (f) { return f.state.indexOf('ESTABLISHED') !== -1 || f.state.indexOf('ASSURED') !== -1; });
    var totalMb = state.flows.reduce(function (acc, f) { return acc + Number(f.bytesMb || 0); }, 0);
    var totalPkts = state.flows.reduce(function (acc, f) { return acc + Number(f.packets || 0); }, 0);

    state.$root.find('#q-fl-kpi-active').text(fmt.number(sys.statesActive || state.flows.length));
    state.$root.find('#q-fl-kpi-total').text('Max ' + fmt.number(sys.statesMax || 131072));
    state.$root.find('#q-fl-kpi-est').text(fmt.number(established.length));
    state.$root.find('#q-fl-kpi-vol').text(formatTransferMb(totalMb));
    state.$root.find('#q-fl-kpi-pkts').text(fmt.number(totalPkts) + ' packets');

    var zoneTotals = {};
    state.flows.forEach(function (f) {
      zoneTotals[f.zone] = (zoneTotals[f.zone] || 0) + Math.max(0.01, Number(f.bytesMb || 0));
    });
    var topZone = null;
    var topVol = -1;
    Object.keys(zoneTotals).forEach(function (z) {
      if (zoneTotals[z] > topVol) {
        topVol = zoneTotals[z];
        topZone = z;
      }
    });
    state.$root.find('#q-fl-kpi-top-zone').text(topZone ? fmt.zoneLabel(topZone) : '—');
    state.$root.find('#q-fl-kpi-top-vol').text(topZone ? (state.flows.filter(function (f) { return f.zone === topZone; }).length + ' sessions') : 'No active flows');

    var buckets = { tcp: 0, udp: 0, vpn: 0, icmp: 0 };
    state.flows.forEach(function (f) {
      var w = Math.max(1, Number(f.packets || 1));
      if (f.zone === 'vpn') buckets.vpn += w;
      else if (f.protocol === 'TCP') buckets.tcp += w;
      else if (f.protocol === 'UDP') buckets.udp += w;
      else buckets.icmp += w;
    });
    var sum = Math.max(1, buckets.tcp + buckets.udp + buckets.vpn + buckets.icmp);
    var pTcp = Math.round((buckets.tcp / sum) * 100);
    var pVpn = Math.round((buckets.vpn / sum) * 100);
    var pUdp = Math.round((buckets.udp / sum) * 100);
    var pIcmp = Math.max(0, 100 - pTcp - pVpn - pUdp);

    state.$root.find('#q-fl-seg-tcp').css('width', pTcp + '%');
    state.$root.find('#q-fl-seg-vpn').css('width', pVpn + '%');
    state.$root.find('#q-fl-seg-udp').css('width', pUdp + '%');
    state.$root.find('#q-fl-seg-icmp').css('width', pIcmp + '%');
    state.$root.find('#q-fl-leg-tcp').text(pTcp + '%');
    state.$root.find('#q-fl-leg-vpn').text(pVpn + '%');
    state.$root.find('#q-fl-leg-udp').text(pUdp + '%');
    state.$root.find('#q-fl-leg-icmp').text(pIcmp + '%');

    state.$root.find('#q-fl-live-toggle').attr('aria-pressed', String(state.liveEnabled));
    state.$root.find('#q-fl-live-label').text(state.liveEnabled ? 'Pause Refresh' : 'Resume Refresh');
    state.$root.find('#q-fl-live-icon').html('<i data-lucide="' + (state.liveEnabled ? 'pause' : 'play') + '" class="q-icon q-icon-sm"></i>');

    var rows = getFiltered();
    state.$root.find('#q-fl-count').text(rows.length + ' of ' + state.flows.length + ' flows');

    var $tbody = state.$root.find('#q-fl-tbody');
    if (!rows.length) {
      $tbody.html('<tr><td colspan="8" style="text-align:center;padding:28px;color:var(--q-text-muted);">No conntrack entries match the current filter.</td></tr>');
      if (Hive.icons) Hive.icons.render();
      return;
    }

    var html = rows
      .slice(0, 250)
      .map(function (f) {
        var isEst = f.state.indexOf('ESTABLISHED') !== -1 || f.state.indexOf('ASSURED') !== -1;
        var stCls = isEst ? 'q-status-success' : 'q-status-info';
        var dotCls = isEst ? 'is-success' : 'is-info';
        var srcEndpoint = f.srcPort && f.srcPort !== '—' ? f.srcIp + ':' + f.srcPort : f.srcIp;
        var dstEndpoint = f.dstPort && f.dstPort !== '—' ? f.dstIp + ':' + f.dstPort : f.dstIp;

        return (
          '<tr>' +
          '  <td><span class="ui label q-badge-square q-mono">' + esc(f.protocol) + '</span></td>' +
          '  <td class="q-mono">' + esc(srcEndpoint) + '</td>' +
          '  <td class="q-mono">' + esc(dstEndpoint) + '</td>' +
          '  <td><span class="ui label ' + fmt.zoneBadgeClass(f.zone) + ' q-badge-square q-mono">' + esc(fmt.zoneLabel(f.zone)) + '</span></td>' +
          '  <td><span class="ui label ' + stCls + '"><span class="q-status-dot ' + dotCls + '"></span>' + esc(f.state) + '</span></td>' +
          '  <td class="q-mono"><strong>' + formatTransferMb(f.bytesMb) + '</strong><span class="q-rule-desc">' + fmt.number(f.packets) + ' pkts</span></td>' +
          '  <td class="q-mono q-text-secondary">TTL ' + formatDuration(f.timeoutSec) + '</td>' +
          '  <td><div class="q-row-actions">' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-fl-inspect-btn" data-id="' + esc(f.id) + '" title="Inspect flow" aria-label="Inspect flow ' + esc(srcEndpoint + ' to ' + dstEndpoint) + '"><i data-lucide="eye" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-fl-kill-btn" data-id="' + esc(f.id) + '" title="Terminate state" aria-label="Terminate flow ' + esc(srcEndpoint + ' to ' + dstEndpoint) + '"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');

    $tbody.html(html);
    if (Hive.icons) Hive.icons.render();
  }

  function openInspectModal(id) {
    var f = state.flows.find(function (x) { return x.id === id; });
    if (!f) return;
    var esc = Hive.format.escapeHtml;
    $('#q-fi-kill-btn').attr('data-id', f.id);
    $('#q-fi-details').html(
      '<div class="q-kv-row"><span class="q-kv-label">Protocol</span><span class="q-kv-value q-mono">' + esc(f.protocol) + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Source</span><span class="q-kv-value q-mono">' + esc(f.srcIp + (f.srcPort !== '—' ? ':' + f.srcPort : '')) + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Destination</span><span class="q-kv-value q-mono">' + esc(f.dstIp + (f.dstPort !== '—' ? ':' + f.dstPort : '')) + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">State / Timeout</span><span class="q-kv-value q-mono">' + esc(f.state) + ' · ' + formatDuration(f.timeoutSec) + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Counters</span><span class="q-kv-value q-mono">' + formatTransferMb(f.bytesMb) + ' · ' + Hive.format.number(f.packets) + ' pkts</span></div>' +
      '<div style="margin-top:8px;"><span class="q-kv-label" style="display:block;margin-bottom:4px;">Kernel Entry</span><pre class="q-code-block" style="white-space:pre-wrap;word-break:break-all;font-size:11px;">' + esc(f.raw) + '</pre></div>'
    );
    Hive.ui.openModal('#q-flow-inspect-modal');
  }

  function startTicker() {
    stopTicker();
    if (!state.liveEnabled) return;
    var token = state.mountToken;
    state.timerId = window.setInterval(function () {
      if (!state.$root || token !== state.mountToken || $('#q-flow-inspect-modal').hasClass('active')) return;
      Hive.services.flows.list().then(function (list) {
        if (!state.$root || token !== state.mountToken) return;
        state.flows = list;
        updateSummaryAndTable();
      });
    }, 4000);
  }

  function stopTicker() {
    if (state.timerId) {
      window.clearInterval(state.timerId);
      state.timerId = null;
    }
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.search = '';
    state.zone = 'all';
    state.proto = 'all';
    state.flowState = 'all';
    cleanupDetachedModals();

    Hive.services.flows.list().then(function (list) {
      if (!state.$root || token !== state.mountToken) return;
      state.flows = list;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Flow Summary</h1>' +
        '    <p class="q-page-subtitle">Real-time Linux kernel <code>nf_conntrack</code> session tracking, protocol breakdown, and state termination.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <button type="button" class="ui secondary button" id="q-fl-live-toggle" aria-pressed="true">' +
        '      <span id="q-fl-live-icon"><i data-lucide="pause" class="q-icon q-icon-sm"></i></span>' +
        '      <span id="q-fl-live-label">Pause Refresh</span>' +
        '    </button>' +
        '    <button type="button" class="ui basic negative button" id="q-fl-flush-btn"><i data-lucide="trash-2" class="q-icon q-icon-sm"></i><span>Flush All Flows</span></button>' +
        '  </div>' +
        '</div>' +

        '<div class="q-kpi-grid">' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Kernel Entries</span><span class="q-kpi-icon"><i data-lucide="waves" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-fl-kpi-active">0</div><div class="q-kpi-sub"><span id="q-fl-kpi-total"></span><span>nf_conntrack</span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Established / Assured</span><span class="q-kpi-icon"><i data-lucide="check-circle-2" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-fl-kpi-est">0</div><div class="q-kpi-sub"><span>Verified 2-way</span><span class="q-text-success">Active</span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Tracked Volume</span><span class="q-kpi-icon"><i data-lucide="activity" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-fl-kpi-vol">0 MB</div><div class="q-kpi-sub"><span id="q-fl-kpi-pkts"></span><span>Accounted</span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Top Source Zone</span><span class="q-kpi-icon"><i data-lucide="network" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" style="font-size:18px;" id="q-fl-kpi-top-zone">—</div><div class="q-kpi-sub"><span id="q-fl-kpi-top-vol">—</span><span>Origin</span></div></div>' +
        '</div>' +

        '<div class="q-card" style="margin-bottom: var(--q-space-5);">' +
        '  <div class="q-card-header" style="margin-bottom:var(--q-space-3);padding-bottom:var(--q-space-2);">' +
        '    <div><h2 class="q-card-title" style="font-size:var(--q-text-base);">Session Distribution by Protocol &amp; Tunnel</h2></div>' +
        '    <span class="ui label q-mono" id="q-fl-count"></span>' +
        '  </div>' +
        '  <div class="q-proto-bar" role="img" aria-label="Protocol distribution">' +
        '    <div class="q-proto-seg is-vpn" id="q-fl-seg-vpn"></div>' +
        '    <div class="q-proto-seg is-tcp" id="q-fl-seg-tcp"></div>' +
        '    <div class="q-proto-seg is-udp" id="q-fl-seg-udp"></div>' +
        '    <div class="q-proto-seg is-icmp" id="q-fl-seg-icmp"></div>' +
        '  </div>' +
        '  <div class="q-proto-legend">' +
        '    <span class="q-legend-item"><span class="q-legend-dot is-vpn"></span> WireGuard <strong class="q-mono" id="q-fl-leg-vpn"></strong></span>' +
        '    <span class="q-legend-item"><span class="q-legend-dot is-rx"></span> TCP <strong class="q-mono" id="q-fl-leg-tcp"></strong></span>' +
        '    <span class="q-legend-item"><span class="q-legend-dot is-tx"></span> UDP <strong class="q-mono" id="q-fl-leg-udp"></strong></span>' +
        '    <span class="q-legend-item"><span class="q-legend-dot is-icmp"></span> ICMP / Other <strong class="q-mono" id="q-fl-leg-icmp"></strong></span>' +
        '  </div>' +
        '</div>' +

        '<div class="q-toolbar">' +
        '  <div class="q-toolbar-left">' +
        '    <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-fl-search" placeholder="Search IP, port, state..."></div>' +
        '    <div class="ui selection dropdown" id="q-fl-zone-dd" data-q-manual-init style="min-width:130px;"><input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Zones</div><div class="menu"><div class="item" data-value="all">All Zones</div><div class="item" data-value="lan">LAN</div><div class="item" data-value="wan">WAN</div><div class="item" data-value="vpn">VPN</div></div></div>' +
        '    <div class="ui selection dropdown" id="q-fl-proto-dd" data-q-manual-init style="min-width:120px;"><input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Protos</div><div class="menu"><div class="item" data-value="all">All Protos</div><div class="item" data-value="TCP">TCP</div><div class="item" data-value="UDP">UDP</div><div class="item" data-value="ICMP">ICMP</div></div></div>' +
        '    <div class="ui selection dropdown" id="q-fl-state-dd" data-q-manual-init style="min-width:150px;"><input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All States</div><div class="menu"><div class="item" data-value="all">All States</div><div class="item" data-value="ESTABLISHED">ESTABLISHED</div><div class="item" data-value="TIME_WAIT">TIME_WAIT</div><div class="item" data-value="ASSURED">ASSURED</div></div></div>' +
        '  </div>' +
        '</div>' +

        '<div class="q-table-wrap">' +
        '  <table class="ui selectable striped table">' +
        '    <thead><tr><th>Proto</th><th>Source</th><th>Destination</th><th>Origin</th><th>State</th><th>Volume</th><th>Timeout</th><th style="width:84px;">Actions</th></tr></thead>' +
        '    <tbody id="q-fl-tbody"></tbody>' +
        '  </table>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);

      $('#q-fl-zone-dd').dropdown({ onChange: function (v) { state.zone = v || 'all'; updateSummaryAndTable(); } });
      $('#q-fl-proto-dd').dropdown({ onChange: function (v) { state.proto = v || 'all'; updateSummaryAndTable(); } });
      $('#q-fl-state-dd').dropdown({ onChange: function (v) { state.flowState = v || 'all'; updateSummaryAndTable(); } });

      updateSummaryAndTable();
      startTicker();
    });

    $container.on('input.qFlows', '#q-fl-search', function () {
      state.search = $.trim($(this).val());
      updateSummaryAndTable();
    });

    $container.on('click.qFlows', '#q-fl-live-toggle', function () {
      state.liveEnabled = !state.liveEnabled;
      if (state.liveEnabled) startTicker();
      else stopTicker();
      updateSummaryAndTable();
    });

    $container.on('click.qFlows', '#q-fl-flush-btn', function () {
      Hive.ui.confirm({
        title: 'Flush Conntrack State Table',
        message: 'Flush the entire nf_conntrack table? Active LAN/WAN TCP and VPN sessions may briefly reset.',
        confirmText: 'Flush All Flows',
        danger: true,
        onConfirm: function () {
          Hive.services.flows
            .flushAll()
            .then(function (list) {
              state.flows = list;
              updateSummaryAndTable();
              Hive.ui.notify({ title: 'Conntrack Flushed', message: 'Cleared kernel connection tracking table.', type: 'warning' });
            })
            .catch(function (err) {
              Hive.ui.notify({ title: 'Flush Failed', message: err.message, type: 'error' });
            });
        }
      });
    });

    $container.on('click.qFlows', '.q-fl-inspect-btn', function () {
      openInspectModal($(this).attr('data-id'));
    });

    function executeKillFlow(target) {
      Hive.services.flows
        .terminate(target)
        .then(function () {
          $('#q-flow-inspect-modal').modal('hide');
          state.flows = Hive.store.getState().flows || [];
          updateSummaryAndTable();
          Hive.ui.notify({ title: 'Flow Terminated', message: 'Removed ' + target.srcIp + ' -> ' + target.dstIp + ' from conntrack.', type: 'warning' });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Terminate Failed', message: err.message, type: 'error' });
        });
    }

    function killFlowById(id) {
      var target = state.flows.find(function (x) { return x.id === id; });
      if (!target) return;
      var lanIp = (Hive.store.getState().lanConfig && Hive.store.getState().lanConfig.ip) || '192.168.10.1';
      var isMgmt =
        (target.dstIp === lanIp || target.dstIp === window.location.hostname) &&
        (String(target.dstPort) === '443' || String(target.dstPort) === '22');
      if (isMgmt) {
        Hive.ui.confirm({
          title: 'Terminate Management Session?',
          message: 'This flow targets router port :' + target.dstPort + ' (' + target.dstIp + '). Terminating it may disconnect your active Web UI or SSH session.',
          confirmText: 'Terminate Flow',
          danger: true,
          onConfirm: function () {
            executeKillFlow(target);
          }
        });
        return;
      }
      executeKillFlow(target);
    }

    $container.on('click.qFlows', '.q-fl-kill-btn', function () {
      killFlowById($(this).attr('data-id'));
    });

    $(document).on('click.qFlowsModal', '#q-fi-kill-btn', function () {
      killFlowById($(this).attr('data-id'));
    });
  }

  function unmount() {
    state.mountToken += 1;
    stopTicker();
    $(document).off('.qFlowsModal');
    cleanupDetachedModals();
    if (state.$root) {
      state.$root.off('.qFlows');
      state.$root = null;
    }
  }

  Hive.router.register('/overview/flows', {
    title: 'Flow Summary',
    group: 'Overview',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
