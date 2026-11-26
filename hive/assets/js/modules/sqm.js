/* ==========================================================================
   Hive — SQM CAKE QoS (#/network/sqm)
   NetBee OS Anti-Bufferbloat CAKE Shaping (/etc/netbee/sqm.conf + ifb0).
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    sqm: null,
    firewallConfig: null,
    interfaces: [],
    stateListener: null
  };

  function formatKbpsHint(kbps) {
    var n = Number(kbps);
    if (!Number.isFinite(n) || n <= 0) return 'Invalid rate';
    if (n >= 1000000) return '≈ ' + (n / 1000000).toFixed(2) + ' Gbps';
    if (n >= 1000) return '≈ ' + (n / 1000).toFixed(1) + ' Mbps';
    return n + ' kbit/s';
  }

  function readDraftFromForm() {
    if (!state.$root) return state.sqm;
    return {
      enabled: $('#q-sqm-enabled').is(':checked'),
      iface: $('#q-sqm-iface').val() || (state.sqm ? state.sqm.iface : 'eth1'),
      downloadKbps: Number($.trim($('#q-sqm-down').val()) || 0),
      uploadKbps: Number($.trim($('#q-sqm-up').val()) || 0),
      overheadBytes: Number($.trim($('#q-sqm-overhead').val()) || 0)
    };
  }

  function updateLivePreviewAndKpis(cfg) {
    if (!state.$root || !cfg) return;
    var fmt = Hive.format;

    state.$root.find('#q-sqm-down-hint').text(formatKbpsHint(cfg.downloadKbps));
    state.$root.find('#q-sqm-up-hint').text(formatKbpsHint(cfg.uploadKbps));

    state.$root.find('#q-sqm-kpi-state').html(cfg.enabled ? '<span class="q-text-success">Active</span>' : '<span class="q-text-muted">Disabled</span>');
    state.$root.find('#q-sqm-kpi-iface').text(cfg.iface);
    state.$root.find('#q-sqm-kpi-down').text(fmt.mbps(cfg.downloadKbps / 1000));
    state.$root.find('#q-sqm-kpi-down-sub').text(fmt.number(cfg.downloadKbps) + ' kbit/s');
    state.$root.find('#q-sqm-kpi-up').text(fmt.mbps(cfg.uploadKbps / 1000));
    state.$root.find('#q-sqm-kpi-up-sub').text(fmt.number(cfg.uploadKbps) + ' kbit/s');
    state.$root.find('#q-sqm-kpi-ovh').text('+' + cfg.overheadBytes + ' B');

    state.$root.find('.q-sqm-preset-btn').each(function () {
      var $btn = $(this);
      $btn.toggleClass('active', Number($btn.attr('data-overhead')) === Number(cfg.overheadBytes));
    });

    var preview = [
      '# /etc/netbee/sqm.conf — Managed by netbeed',
      'ENABLED=' + (cfg.enabled ? '1' : '0') + '  WAN_IF="' + cfg.iface + '"',
      'tc qdisc replace dev ' + cfg.iface + ' root cake bandwidth ' + cfg.uploadKbps + 'kbit diffserv4 nat dual-srchost overhead ' + cfg.overheadBytes,
      'tc qdisc replace dev ifb0 root cake bandwidth ' + cfg.downloadKbps + 'kbit besteffort nat dual-dsthost ingress overhead ' + cfg.overheadBytes
    ];
    if (state.sqm && state.sqm.statusOutput) {
      preview.push('', '# Live kernel qdisc status:', state.sqm.statusOutput.trim());
    }
    state.$root.find('#q-sqm-preview-code').text(preview.join('\n'));
  }

  function populateFormFromState() {
    if (!state.$root || !state.sqm) return;
    var s = state.sqm;
    var esc = Hive.format.escapeHtml;

    var ifaceHtml = state.interfaces
      .filter(function (i) { return i.zone !== 'lan'; })
      .map(function (i) {
        return '<div class="item" data-value="' + esc(i.device) + '"><span class="q-mono">' + esc(i.device) + '</span> — ' + esc(i.label) + '</div>';
      })
      .join('');
    if (!ifaceHtml) {
      ifaceHtml = '<div class="item" data-value="eth1"><span class="q-mono">eth1</span> — WAN Interface</div>';
    }
    var $ifDd = $('#q-sqm-iface-dd');
    $ifDd.find('.menu').html(ifaceHtml);
    $ifDd.dropdown('refresh').dropdown('set selected', s.iface || 'eth1');

    $('#q-sqm-enabled-chk').checkbox(s.enabled ? 'set checked' : 'set unchecked');
    $('#q-sqm-down').val(s.downloadKbps);
    $('#q-sqm-up').val(s.uploadKbps);
    $('#q-sqm-overhead').val(s.overheadBytes);

    $('#q-sqm-down-field, #q-sqm-up-field, #q-sqm-overhead-field').removeClass('error');
    $('#q-sqm-down-err, #q-sqm-up-err, #q-sqm-overhead-err').attr('hidden', true);

    updateLivePreviewAndKpis(s);
  }

  function stageForm() {
    var draft = readDraftFromForm();
    var ok = true;

    $('#q-sqm-down-field, #q-sqm-up-field, #q-sqm-overhead-field').removeClass('error');
    $('#q-sqm-down-err, #q-sqm-up-err, #q-sqm-overhead-err').attr('hidden', true);

    if (!Number.isInteger(draft.downloadKbps) || draft.downloadKbps < 500 || draft.downloadKbps > 10000000) {
      $('#q-sqm-down-field').addClass('error');
      $('#q-sqm-down-err').removeAttr('hidden');
      ok = false;
    }
    if (!Number.isInteger(draft.uploadKbps) || draft.uploadKbps < 250 || draft.uploadKbps > 10000000) {
      $('#q-sqm-up-field').addClass('error');
      $('#q-sqm-up-err').removeAttr('hidden');
      ok = false;
    }
    if (!Number.isInteger(draft.overheadBytes) || draft.overheadBytes < 0 || draft.overheadBytes > 128) {
      $('#q-sqm-overhead-field').addClass('error');
      $('#q-sqm-overhead-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    Hive.services.sqm.update(draft).then(function () {
      Hive.ui.notify({
        title: 'SQM CAKE Staged',
        message: 'CAKE shaping on ' + draft.iface + ' queued for commit.',
        type: 'success'
      });
    });
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.sqm.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.sqm = data.sqm;
      state.firewallConfig = data.firewallConfig;
      state.interfaces = data.interfaces;
      populateFormFromState();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;

    Hive.services.sqm.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.sqm = data.sqm;
      state.firewallConfig = data.firewallConfig;
      state.interfaces = data.interfaces;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">SQM CAKE QoS</h1>' +
        '    <p class="q-page-subtitle">Kernel <code>sch_cake</code> + <code>ifb0</code> anti-bufferbloat traffic shaping and per-host fairness.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <div class="ui toggle checkbox" id="q-sqm-enabled-chk" style="margin-right:8px;">' +
        '      <input type="checkbox" id="q-sqm-enabled">' +
        '      <label for="q-sqm-enabled">Enable SQM CAKE</label>' +
        '    </div>' +
        '    <button type="button" class="ui primary button" id="q-sqm-save-btn"><i data-lucide="check" class="q-icon q-icon-sm"></i><span>Stage SQM Changes</span></button>' +
        '  </div>' +
        '</div>' +

        '<div class="q-kpi-grid">' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Shaping Status</span><span class="q-kpi-icon"><i data-lucide="gauge" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-sqm-kpi-state">—</div><div class="q-kpi-sub"><span>WAN <strong class="q-mono" id="q-sqm-kpi-iface">eth1</strong></span><span>CAKE</span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Download (Ingress)</span><span class="q-kpi-icon"><i data-lucide="download" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-sqm-kpi-down">—</div><div class="q-kpi-sub"><span class="q-mono" id="q-sqm-kpi-down-sub">0 kbit/s</span><span>ifb0</span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Upload (Egress)</span><span class="q-kpi-icon"><i data-lucide="upload" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-sqm-kpi-up">—</div><div class="q-kpi-sub"><span class="q-mono" id="q-sqm-kpi-up-sub">0 kbit/s</span><span>diffserv4</span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Framing Overhead</span><span class="q-kpi-icon"><i data-lucide="layers" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-sqm-kpi-ovh">+44 B</div><div class="q-kpi-sub"><span>dual-srchost / dsthost</span><span>NAT aware</span></div></div>' +
        '</div>' +

        '<form class="ui form" id="q-sqm-form" novalidate>' +
        '  <div class="q-card">' +
        '    <div class="q-card-header">' +
        '      <div>' +
        '        <h2 class="q-card-title"><i data-lucide="sliders-horizontal" class="q-icon q-text-accent"></i><span>CAKE Shaper Parameters</span></h2>' +
        '        <p class="q-card-subtitle">Note: Enabling SQM CAKE automatically pauses nftables fastpath flow offload so packets traverse kernel queues; disabling SQM restores flow offload.</p>' +
        '      </div>' +
        '    </div>' +

        '    <div class="two fields">' +
        '      <div class="field required">' +
        '        <label>WAN Uplink Interface</label>' +
        '        <div class="ui fluid selection dropdown" id="q-sqm-iface-dd" data-q-manual-init>' +
        '          <input type="hidden" id="q-sqm-iface" value="eth1"><i class="dropdown icon"></i><div class="text">eth1</div>' +
        '          <div class="menu"></div>' +
        '        </div>' +
        '        <span class="q-field-hint">Select <code>eth1</code> for DHCP WAN or <code>ppp0</code> for PPPoE / Fiber ONT sessions.</span>' +
        '      </div>' +
        '      <div class="field required" id="q-sqm-overhead-field">' +
        '        <label for="q-sqm-overhead">Link Layer Overhead (0 – 128 bytes)</label>' +
        '        <input id="q-sqm-overhead" type="number" class="q-mono" min="0" max="128" value="44">' +
        '        <span class="q-field-error" id="q-sqm-overhead-err" hidden>Enter an integer between 0 and 128 bytes.</span>' +
        '      </div>' +
        '    </div>' +

        '    <div class="two fields">' +
        '      <div class="field required" id="q-sqm-down-field">' +
        '        <label for="q-sqm-down">Download Bandwidth (kbit/s)</label>' +
        '        <input id="q-sqm-down" type="number" class="q-mono" min="500" max="10000000" step="500">' +
        '        <span class="q-field-hint">Set to 90–95% of line speed (<span class="q-mono" id="q-sqm-down-hint"></span>). Range: 500 – 10,000,000.</span>' +
        '        <span class="q-field-error" id="q-sqm-down-err" hidden>Enter 500 – 10,000,000 kbit/s.</span>' +
        '      </div>' +
        '      <div class="field required" id="q-sqm-up-field">' +
        '        <label for="q-sqm-up">Upload Bandwidth (kbit/s)</label>' +
        '        <input id="q-sqm-up" type="number" class="q-mono" min="250" max="10000000" step="250">' +
        '        <span class="q-field-hint">Set to 90–95% of line speed (<span class="q-mono" id="q-sqm-up-hint"></span>). Range: 250 – 10,000,000.</span>' +
        '        <span class="q-field-error" id="q-sqm-up-err" hidden>Enter 250 – 10,000,000 kbit/s.</span>' +
        '      </div>' +
        '    </div>' +

        '    <div>' +
        '      <div class="q-field-hint" style="margin-top:0;margin-bottom:8px;">Quick Overhead Presets:</div>' +
        '      <div class="q-sqm-preset-row">' +
        '        <button type="button" class="ui mini secondary button q-sqm-preset-btn" data-overhead="0">Raw IP · 0 B</button>' +
        '        <button type="button" class="ui mini secondary button q-sqm-preset-btn" data-overhead="18">Ethernet / Cable · 18 B</button>' +
        '        <button type="button" class="ui mini secondary button q-sqm-preset-btn" data-overhead="22">VDSL2 · 22 B</button>' +
        '        <button type="button" class="ui mini secondary button q-sqm-preset-btn" data-overhead="44">Fiber ONT / PPPoE · 44 B</button>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +
        '</form>' +

        '<div class="q-card" style="margin-top:var(--q-space-5);">' +
        '  <div class="q-card-header" style="margin-bottom:var(--q-space-3);padding-bottom:var(--q-space-2);">' +
        '    <div><h2 class="q-card-title" style="font-size:var(--q-text-base);"><i data-lucide="terminal" class="q-icon q-text-accent"></i><span>Effective CAKE Qdisc &amp; Runtime Status</span></h2></div>' +
        '  </div>' +
        '  <pre class="q-code-block" id="q-sqm-preview-code"></pre>' +
        '</div>';

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);

      $('#q-sqm-iface-dd').dropdown({
        onChange: function () { updateLivePreviewAndKpis(readDraftFromForm()); }
      });

      populateFormFromState();
    });

    $container.on('input.qSqm', '#q-sqm-down, #q-sqm-up, #q-sqm-overhead', function () {
      updateLivePreviewAndKpis(readDraftFromForm());
    });

    $container.on('change.qSqm', '#q-sqm-enabled', function () {
      var enabled = this.checked;
      updateLivePreviewAndKpis(readDraftFromForm());
      Hive.services.sqm.toggleEnabled(enabled);
    });

    $container.on('click.qSqm', '#q-sqm-save-btn', stageForm);
    $container.on('submit.qSqm', '#q-sqm-form', function (e) { e.preventDefault(); stageForm(); });

    $container.on('click.qSqm', '.q-sqm-preset-btn', function () {
      $('#q-sqm-overhead').val($(this).attr('data-overhead'));
      updateLivePreviewAndKpis(readDraftFromForm());
    });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (reason === 'telemetry' || reason === 'audit' || reason === 'sqm-status') return;
      if (reason === 'inline-toggle') return;
      loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qSqm');
      state.$root = null;
    }
  }

  Hive.router.register('/network/sqm', {
    title: 'SQM QoS',
    group: 'Network',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
