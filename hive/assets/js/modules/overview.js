/* ==========================================================================
   Hive — System Overview (#/overview/system)
   Live SSE telemetry, RPi 5 hardware health, vnStat + live WAN throughput.
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    rendered: false,
    range: '15m',
    liveEnabled: true,
    chartHovering: false,
    stateListener: null
  };

  function buildGatewaysHtml(gateways) {
    var esc = Hive.format.escapeHtml;
    if (!gateways || !gateways.length) {
      return '<div class="q-text-muted" style="font-size:12px;">No WAN gateway detected yet.</div>';
    }
    return gateways
      .map(function (gw) {
        var isOnline = gw.status === 'online';
        var badgeCls = isOnline ? 'q-status-success' : 'q-status-warning';
        var dotCls = isOnline ? 'is-success' : 'is-warning';
        var statusText = isOnline ? 'Online' : 'Waiting';
        return (
          '<div class="q-gateway-item">' +
          '  <div class="q-gateway-top">' +
          '    <span class="q-gateway-name"><span class="q-status-dot ' + dotCls + '"></span><span class="q-mono">' + esc(gw.name) + '</span></span>' +
          '    <span class="ui label ' + badgeCls + '">' + statusText + '</span>' +
          '  </div>' +
          '  <div class="q-text-muted" style="font-size:12px;">' + esc(gw.role || 'Primary WAN') + ' · Dev <span class="q-mono">' + esc(gw.iface) + '</span></div>' +
          '  <div class="q-gateway-metrics">' +
          '    <div><span class="q-gateway-metric-label">Next Hop</span><span class="q-gateway-metric-val q-mono">' + esc(gw.address || '—') + '</span></div>' +
          '    <div><span class="q-gateway-metric-label">Interface</span><span class="q-gateway-metric-val q-mono">' + esc(gw.iface || 'eth1') + '</span></div>' +
          '  </div>' +
          '</div>'
        );
      })
      .join('');
  }

  function buildHardwareHtml(sys) {
    var esc = Hive.format.escapeHtml;
    var tempStr = sys.cpuTempC !== null && sys.cpuTempC !== undefined ? Number(sys.cpuTempC).toFixed(1) + ' °C' : 'N/A';
    var tempCls = sys.cpuTempC >= 80 ? 'q-text-danger' : sys.cpuTempC >= 68 ? 'q-text-warning' : 'q-text-success';
    var fanStr = sys.fanRpm !== null && sys.fanRpm !== undefined ? sys.fanRpm + ' RPM' : 'Passive / Idle';
    var freqStr = (sys.cpuFreqMhz ? sys.cpuFreqMhz + ' MHz' : 'Auto') + (sys.cpuGovernor ? ' (' + sys.cpuGovernor + ')' : '');
    var powerHtml = sys.undervoltage
      ? '<span class="ui label q-status-danger">Undervoltage!</span>'
      : '<span class="ui label q-status-success">5V Nominal</span>';

    var disksHtml = (sys.disks || [])
      .map(function (d) {
        return (
          '<div class="q-kv-row">' +
          '  <span class="q-kv-label">Mount <code class="q-mono">' + esc(d.mount) + '</code></span>' +
          '  <span class="q-kv-value q-mono">' + d.used_mb + ' / ' + d.total_mb + ' MB (' + d.used_pct + '%)</span>' +
          '</div>'
        );
      })
      .join('');

    return (
      '<div class="q-kv-list">' +
      '  <div class="q-kv-row"><span class="q-kv-label">Board</span><span class="q-kv-value q-mono">' + esc(sys.model || 'Raspberry Pi 5') + '</span></div>' +
      '  <div class="q-kv-row"><span class="q-kv-label">SoC Thermal</span><span class="q-kv-value q-mono ' + tempCls + '">' + esc(tempStr) + '</span></div>' +
      '  <div class="q-kv-row"><span class="q-kv-label">Active Cooler</span><span class="q-kv-value q-mono">' + esc(fanStr) + '</span></div>' +
      '  <div class="q-kv-row"><span class="q-kv-label">CPU Clock</span><span class="q-kv-value q-mono">' + esc(freqStr) + '</span></div>' +
      '  <div class="q-kv-row"><span class="q-kv-label">Power Rail</span><span class="q-kv-value">' + powerHtml + '</span></div>' +
      disksHtml +
      '</div>'
    );
  }

  function buildIfacesMiniHtml(ifaces) {
    var fmt = Hive.format;
    var esc = fmt.escapeHtml;
    return (ifaces || [])
      .slice(0, 6)
      .map(function (iface) {
        var dot = iface.status === 'up' ? 'is-success' : 'is-danger';
        return (
          '<div class="q-iface-mini-row">' +
          '  <span style="display:inline-flex;align-items:center;gap:8px;"><span class="q-status-dot ' + dot + '"></span><strong class="q-mono">' + esc(iface.device) + '</strong></span>' +
          '  <span><span class="ui label ' + fmt.zoneBadgeClass(iface.zone) + ' q-badge-square q-mono">' + esc(fmt.zoneLabel(iface.zone)) + '</span></span>' +
          '  <span class="q-mono q-text-secondary" style="font-size:12px;overflow:hidden;text-overflow:ellipsis;">' + esc(iface.ipv4) + '</span>' +
          '  <span class="q-mono q-text-muted" style="font-size:12px;white-space:nowrap;">↓ ' + fmt.mbps(iface.rxMbps) + ' · ↑ ' + fmt.mbps(iface.txMbps) + '</span>' +
          '</div>'
        );
      })
      .join('');
  }

  function updateProgressBar($bar, pct) {
    var clamped = Math.max(0, Math.min(100, Number(pct || 0)));
    var sev = Hive.format.progressSeverityClass(clamped);
    $bar.removeClass('success warning error').addClass(sev);
    $bar.find('.bar').css('width', clamped + '%');
  }

  function renderInitial(snapshot) {
    if (!state.$root) return;
    var sys = snapshot.system;
    var esc = Hive.format.escapeHtml;

    var html =
      '<div class="q-page-header">' +
      '  <div>' +
      '    <h1 class="q-page-title">System Overview</h1>' +
      '    <p class="q-page-subtitle">Raspberry Pi 5 hardware health, gateway reachability, and live interface telemetry for <span class="q-mono">' + esc(sys.hostname) + '</span>.</p>' +
      '  </div>' +
      '  <div class="q-page-actions">' +
      '    <button type="button" class="ui secondary button" id="q-ov-live-toggle" aria-pressed="true">' +
      '      <span id="q-ov-live-icon"><i data-lucide="pause" class="q-icon q-icon-sm"></i></span>' +
      '      <span id="q-ov-live-label">Pause Live Stream</span>' +
      '    </button>' +
      '    <a href="#/security/firewall" class="ui primary button">' +
      '      <i data-lucide="shield" class="q-icon q-icon-sm"></i>' +
      '      <span>Firewall Rules</span>' +
      '    </a>' +
      '  </div>' +
      '</div>' +

      '<div class="q-kpi-grid">' +
      '  <div class="q-kpi-card">' +
      '    <div class="q-kpi-head"><span class="q-kpi-label">CPU Load</span><span class="q-kpi-icon"><i data-lucide="cpu" class="q-icon q-icon-sm"></i></span></div>' +
      '    <div class="q-kpi-value" id="q-ov-cpu-val">0%</div>' +
      '    <div class="q-kpi-sub"><span id="q-ov-cpu-sub"></span><span class="q-mono" id="q-ov-temp-chip"></span></div>' +
      '    <div class="ui tiny progress" id="q-ov-cpu-bar"><div class="bar"></div></div>' +
      '  </div>' +

      '  <div class="q-kpi-card">' +
      '    <div class="q-kpi-head"><span class="q-kpi-label">Memory</span><span class="q-kpi-icon"><i data-lucide="memory-stick" class="q-icon q-icon-sm"></i></span></div>' +
      '    <div class="q-kpi-value" id="q-ov-mem-val">0%</div>' +
      '    <div class="q-kpi-sub"><span class="q-mono" id="q-ov-mem-sub"></span><span class="q-mono" id="q-ov-load-sub"></span></div>' +
      '    <div class="ui tiny progress" id="q-ov-mem-bar"><div class="bar"></div></div>' +
      '  </div>' +

      '  <div class="q-kpi-card">' +
      '    <div class="q-kpi-head"><span class="q-kpi-label">Conntrack Table</span><span class="q-kpi-icon"><i data-lucide="activity" class="q-icon q-icon-sm"></i></span></div>' +
      '    <div class="q-kpi-value" id="q-ov-states-val">0</div>' +
      '    <div class="q-kpi-sub"><span id="q-ov-states-limit"></span><span class="q-mono" id="q-ov-states-pct"></span></div>' +
      '    <div class="ui tiny progress" id="q-ov-states-bar"><div class="bar"></div></div>' +
      '  </div>' +

      '  <div class="q-kpi-card">' +
      '    <div class="q-kpi-head"><span class="q-kpi-label">Policy &amp; Uptime</span><span class="q-kpi-icon"><i data-lucide="shield-check" class="q-icon q-icon-sm"></i></span></div>' +
      '    <div class="q-kpi-value" id="q-ov-links-val"></div>' +
      '    <div class="q-kpi-sub"><span id="q-ov-rules-sub"></span><span class="q-mono" id="q-ov-uptime"></span></div>' +
      '    <div class="ui tiny success progress" id="q-ov-links-bar"><div class="bar"></div></div>' +
      '  </div>' +
      '</div>' +

      '<div class="q-overview-grid">' +
      '  <div class="q-span-8">' +
      '    <div class="q-card">' +
      '      <div class="q-card-header">' +
      '        <div>' +
      '          <h2 class="q-card-title"><i data-lucide="waves" class="q-icon q-text-accent"></i><span id="q-ov-wan-chart-title">WAN Throughput</span></h2>' +
      '          <p class="q-card-subtitle">Live 2s SSE stream (15m) and persistent vnStat bandwidth history (1h / 24h).</p>' +
      '        </div>' +
      '        <div class="ui small buttons" id="q-ov-range-group" role="group" aria-label="Throughput timeframe">' +
      '          <button type="button" class="ui button' + (state.range === '15m' ? ' active' : '') + '" data-range="15m">Live</button>' +
      '          <button type="button" class="ui button' + (state.range === '1h' ? ' active' : '') + '" data-range="1h">1h</button>' +
      '          <button type="button" class="ui button' + (state.range === '24h' ? ' active' : '') + '" data-range="24h">24h</button>' +
      '        </div>' +
      '      </div>' +
      '      <div id="q-ov-throughput-chart"></div>' +
      '      <div class="q-chart-legend">' +
      '        <span class="q-legend-item"><span class="q-legend-dot is-rx"></span> Download (RX): <strong class="q-mono" id="q-ov-rx-now"></strong> <span class="q-text-muted q-mono" id="q-ov-rx-peak"></span></span>' +
      '        <span class="q-legend-item"><span class="q-legend-dot is-tx"></span> Upload (TX): <strong class="q-mono" id="q-ov-tx-now"></strong> <span class="q-text-muted q-mono" id="q-ov-tx-peak"></span></span>' +
      '      </div>' +
      '    </div>' +
      '  </div>' +

      '  <div class="q-span-4">' +
      '    <div class="q-card" style="height:100%;display:flex;flex-direction:column;gap:var(--q-space-4);">' +
      '      <div class="q-card-header" style="margin-bottom:0;">' +
      '        <div>' +
      '          <h2 class="q-card-title"><i data-lucide="git-fork" class="q-icon q-text-accent"></i><span>WAN Uplink</span></h2>' +
      '          <p class="q-card-subtitle">Active default route &amp; OS runtime</p>' +
      '        </div>' +
      '      </div>' +
      '      <div class="q-gateway-list" id="q-ov-gateways"></div>' +
      '      <div class="q-kv-list" style="margin-top:auto;padding-top:var(--q-space-3);border-top:1px solid var(--q-border-subtle);">' +
      '        <div class="q-kv-row"><span class="q-kv-label">OS Release</span><span class="q-kv-value q-mono" id="q-ov-fw-ver">' + esc(sys.firmware) + '</span></div>' +
      '        <div class="q-kv-row"><span class="q-kv-label">Kernel</span><span class="q-kv-value q-mono" id="q-ov-kern-ver">' + esc(sys.kernel) + '</span></div>' +
      '        <div class="q-kv-row"><span class="q-kv-label">Fastpath Offload</span><span class="q-kv-value" id="q-ov-offload-badge"></span></div>' +
      '      </div>' +
      '    </div>' +
      '  </div>' +

      '  <div class="q-span-6">' +
      '    <div class="q-card">' +
      '      <div class="q-card-header">' +
      '        <div>' +
      '          <h2 class="q-card-title"><i data-lucide="network" class="q-icon q-text-accent"></i><span>Interfaces Snapshot</span></h2>' +
      '          <p class="q-card-subtitle">LAN (eth0), WAN (eth1/ppp0), and WireGuard (wg0)</p>' +
      '        </div>' +
      '        <a href="#/network/interfaces" class="ui mini secondary button">Configure →</a>' +
      '      </div>' +
      '      <div class="q-iface-mini-list" id="q-ov-ifaces-mini"></div>' +
      '    </div>' +
      '  </div>' +

      '  <div class="q-span-6">' +
      '    <div class="q-card">' +
      '      <div class="q-card-header">' +
      '        <div>' +
      '          <h2 class="q-card-title"><i data-lucide="thermometer" class="q-icon q-text-accent"></i><span>Hardware &amp; Storage Health</span></h2>' +
      '          <p class="q-card-subtitle">Thermal sensors, PWM cooling, power rail &amp; partitions</p>' +
      '        </div>' +
      '        <span class="ui label q-mono" id="q-ov-sim-badge"></span>' +
      '      </div>' +
      '      <div id="q-ov-hw-health"></div>' +
      '    </div>' +
      '  </div>' +
      '</div>';

    state.$root.html(html);
    state.rendered = true;
    if (Hive.icons) Hive.icons.render();

    state.$root
      .find('#q-ov-throughput-chart')
      .on('mouseenter', function () { state.chartHovering = true; })
      .on('mouseleave', function () { state.chartHovering = false; });

    patchTelemetry(snapshot, true);
  }

  function patchTelemetry(snapshot, forceChart) {
    if (!state.$root || !state.rendered) return;
    var sys = snapshot.system;
    var ifaces = snapshot.interfaces || [];
    var fwCfg = snapshot.firewallConfig || {};
    var fmt = Hive.format;

    var memTotal = Math.max(1, Number(sys.memTotalMb || 4096));
    var memUsed = Number(sys.memUsedMb || 0);
    var memPct = Math.round((memUsed / memTotal) * 100);
    var statesMax = Math.max(1, Number(sys.statesMax || 131072));
    var statePct = Math.round((Number(sys.statesActive || 0) / statesMax) * 100);
    var upCount = ifaces.filter(function (i) { return i.status === 'up'; }).length;

    state.$root.find('#q-ov-cpu-val').text(sys.cpuPercent + '%');
    state.$root.find('#q-ov-cpu-sub').text((sys.cpuCores || 4) + ' cores · idle ' + Math.max(0, 100 - sys.cpuPercent) + '%');
    state.$root.find('#q-ov-temp-chip').text(sys.cpuTempC !== null && sys.cpuTempC !== undefined ? Number(sys.cpuTempC).toFixed(1) + '°C' : sys.arch || 'arm64');
    updateProgressBar(state.$root.find('#q-ov-cpu-bar'), sys.cpuPercent);

    state.$root.find('#q-ov-mem-val').text(memPct + '%');
    state.$root.find('#q-ov-mem-sub').text(memUsed + ' / ' + memTotal + ' MB');
    state.$root.find('#q-ov-load-sub').text('Load ' + (sys.loadAvg ? Number(sys.loadAvg[0] || 0).toFixed(2) : '0.00'));
    updateProgressBar(state.$root.find('#q-ov-mem-bar'), memPct);

    state.$root.find('#q-ov-states-val').text(fmt.number(sys.statesActive));
    state.$root.find('#q-ov-states-limit').text('Max ' + fmt.number(statesMax));
    state.$root.find('#q-ov-states-pct').text(statePct + '%');
    updateProgressBar(state.$root.find('#q-ov-states-bar'), statePct);

    state.$root.find('#q-ov-links-val').html(upCount + '/' + ifaces.length + ' <span style="font-size:13px;color:var(--q-text-muted);font-weight:500;">links up</span>');
    state.$root.find('#q-ov-rules-sub').text((snapshot.firewallEnabledCount || 0) + ' custom rules');
    state.$root.find('#q-ov-uptime').text(fmt.uptime(sys.uptimeSeconds));
    state.$root.find('#q-ov-links-bar .bar').css('width', Math.round((upCount / Math.max(1, ifaces.length)) * 100) + '%');

    var wanDev = (sys.gateways && sys.gateways[0] && sys.gateways[0].iface) || 'eth1';
    state.$root.find('#q-ov-wan-chart-title').text('WAN Throughput (' + wanDev + ')');
    state.$root.find('#q-ov-fw-ver').text(sys.firmware || 'NetBee OS');
    state.$root.find('#q-ov-kern-ver').text(sys.kernel || 'Linux aarch64');
    state.$root.find('#q-ov-offload-badge').html(
      fwCfg.offloadActive
        ? '<span class="ui mini label q-status-success">Active</span>'
        : '<span class="ui mini label">Off</span>'
    );

    state.$root.find('#q-ov-live-toggle').attr('aria-pressed', String(state.liveEnabled));
    state.$root.find('#q-ov-live-label').text(state.liveEnabled ? 'Pause Live Stream' : 'Resume Live Stream');
    state.$root.find('#q-ov-live-icon').html('<i data-lucide="' + (state.liveEnabled ? 'pause' : 'play') + '" class="q-icon q-icon-sm"></i>');
    state.$root.find('#q-ov-sim-badge').html(
      state.liveEnabled
        ? '<span class="q-status-dot is-success"></span>SSE 2s Live'
        : '<span class="q-status-dot"></span>Paused'
    );

    var series = (sys.throughput && sys.throughput[state.range]) || [{ label: 'Now', rx: 0, tx: 0 }];
    if (!series.length) series = [{ label: 'Now', rx: 0, tx: 0 }];
    var latestPt = series[series.length - 1] || { rx: 0, tx: 0 };
    var peakRx = series.reduce(function (m, p) { return Math.max(m, Number(p.rx || 0)); }, 0);
    var peakTx = series.reduce(function (m, p) { return Math.max(m, Number(p.tx || 0)); }, 0);

    state.$root.find('#q-ov-rx-now').text(fmt.mbps(latestPt.rx));
    state.$root.find('#q-ov-rx-peak').text('(peak ' + fmt.mbps(peakRx) + ')');
    state.$root.find('#q-ov-tx-now').text(fmt.mbps(latestPt.tx));
    state.$root.find('#q-ov-tx-peak').text('(peak ' + fmt.mbps(peakTx) + ')');

    if (forceChart || !state.chartHovering) {
      Hive.charts.renderThroughput(state.$root.find('#q-ov-throughput-chart'), series);
    }

    state.$root.find('#q-ov-gateways').html(buildGatewaysHtml(sys.gateways));
    state.$root.find('#q-ov-ifaces-mini').html(buildIfacesMiniHtml(ifaces));
    state.$root.find('#q-ov-hw-health').html(buildHardwareHtml(sys));

    if (Hive.icons) Hive.icons.render();
  }

  function snapshotFromStore() {
    var st = Hive.store.getState();
    return {
      system: st.system,
      interfaces: st.interfaces,
      firewallConfig: st.firewallConfig,
      firewallCount: (st.firewallRules || []).length,
      firewallEnabledCount: (st.firewallRules || []).filter(function (r) { return r.enabled; }).length
    };
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.rendered = false;
    state.chartHovering = false;

    $container.on('click.qOverview', '#q-ov-range-group .button', function () {
      var nextRange = $(this).attr('data-range');
      if (nextRange && nextRange !== state.range) {
        state.range = nextRange;
        $(this).addClass('active').siblings().removeClass('active');
        patchTelemetry(snapshotFromStore(), true);
      }
    });

    $container.on('click.qOverview', '#q-ov-live-toggle', function () {
      state.liveEnabled = !state.liveEnabled;
      patchTelemetry(snapshotFromStore(), false);
    });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (reason === 'telemetry' && !state.liveEnabled) return;
      if (state.rendered) {
        patchTelemetry(snapshotFromStore(), reason !== 'telemetry');
      }
    };
    window.addEventListener('hive:statechange', state.stateListener);

    renderInitial(snapshotFromStore());
    Hive.services.system.getSnapshot().then(function (snap) {
      if (!state.$root || token !== state.mountToken) return;
      patchTelemetry(snap, true);
    });
  }

  function unmount() {
    state.mountToken += 1;
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qOverview');
      state.$root = null;
    }
    state.rendered = false;
  }

  Hive.router.register('/overview/system', {
    title: 'System Overview',
    group: 'Overview',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
