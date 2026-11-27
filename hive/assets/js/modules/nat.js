/* ==========================================================================
   Hive — Security Module: NAT & Port Forward (#/security/nat)
   NetBee OS WAN Masquerade Status & Inbound DNAT Port Forwarding
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    nat: null,
    wanConfig: null,
    interfaces: [],
    editingPfId: null,
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-pf-modal').modal('hide').remove();
  }

  function isSingleOrRangePort(val) {
    var s = String(val || '').trim();
    if (!s || s.toLowerCase() === 'any' || s.indexOf(',') !== -1) return false;
    return Hive.validators.isPortSpec(s);
  }

  function renderModalsHtml() {
    return (
      '<div class="ui small modal" id="q-pf-modal" role="dialog" aria-labelledby="q-pf-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-pf-title"><i data-lucide="arrow-left-right" class="q-icon q-text-accent"></i><span id="q-pf-heading">Add Port Forward (DNAT)</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-pf-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field"><label>Protocol</label>' +
      '          <div class="ui fluid selection dropdown" id="q-pf-proto-dd">' +
      '            <input type="hidden" id="q-pf-proto" value="TCP"><i class="dropdown icon"></i><div class="text">TCP</div>' +
      '            <div class="menu">' +
      '              <div class="item" data-value="TCP">TCP</div>' +
      '              <div class="item" data-value="UDP">UDP</div>' +
      '              <div class="item" data-value="TCP+UDP">TCP + UDP</div>' +
      '            </div>' +
      '          </div>' +
      '        </div>' +
      '        <div class="field required" id="q-pf-ext-field">' +
      '          <label for="q-pf-ext">External WAN Port / Range</label>' +
      '          <input id="q-pf-ext" type="text" class="q-mono" placeholder="8443 or 8000-8010">' +
      '          <span class="q-field-error" id="q-pf-ext-err" hidden>Enter a port (1-65535) or range (8000-8010).</span>' +
      '        </div>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-pf-ip-field">' +
      '          <label for="q-pf-ip">Internal LAN Target IPv4</label>' +
      '          <input id="q-pf-ip" type="text" class="q-mono" placeholder="192.168.10.20">' +
      '          <span class="q-field-error" id="q-pf-ip-err" hidden>Enter a valid IPv4 host address.</span>' +
      '        </div>' +
      '        <div class="field" id="q-pf-tport-field">' +
      '          <label for="q-pf-tport">Internal Target Port</label>' +
      '          <input id="q-pf-tport" type="text" class="q-mono" placeholder="Same as external (or 1-65535)">' +
      '          <span class="q-field-error" id="q-pf-tport-err" hidden>Enter a single port 1-65535 (leave blank for port ranges).</span>' +
      '        </div>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field" id="q-pf-src-field">' +
      '          <label for="q-pf-src">Allowed Source IPv4 / CIDR (Optional)</label>' +
      '          <input id="q-pf-src" type="text" class="q-mono" placeholder="Any WAN source (or 203.0.113.0/24)">' +
      '          <span class="q-field-error" id="q-pf-src-err" hidden>Enter a valid IPv4 address or CIDR, or leave blank.</span>' +
      '        </div>' +
      '        <div class="field">' +
      '          <label for="q-pf-desc">Description</label>' +
      '          <input id="q-pf-desc" type="text" placeholder="Home HTTPS reverse proxy">' +
      '        </div>' +
      '      </div>' +
      '      <div class="field" style="margin-bottom:0;">' +
      '        <div class="ui toggle checkbox" id="q-pf-enabled-chk"><input type="checkbox" id="q-pf-enabled" checked><label for="q-pf-enabled">Rule enabled (auto-generates matching WAN forward accept rule)</label></div>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-pf-save-btn">Stage Port Forward</button>' +
      '  </div>' +
      '</div>'
    );
  }

  function renderTables() {
    if (!state.$root || !state.nat) return;
    var esc = Hive.format.escapeHtml;
    var wanCfg = state.wanConfig || {};
    var wanMode = (wanCfg.mode || 'dhcp').toUpperCase();
    var wanDev = wanCfg.mode === 'pppoe' || wanCfg.mode === 'ont_vlan' ? 'ppp0 (' + (wanCfg.interface || 'eth1') + ')' : (wanCfg.interface || 'eth1');

    state.$root.find('#q-nat-wan-summary').html(
      '<span class="ui label q-net-wan q-badge-square q-mono">' + esc(wanDev) + '</span> ' +
      '<span class="q-text-secondary" style="margin-left:6px;">Mode: <strong class="q-mono">' + esc(wanMode) + '</strong> · Outbound <code>masquerade</code> active on <code>$WAN_IFS</code></span>'
    );

    var list = state.nat.portForwards || [];
    state.$root.find('[data-nat-count="dnat"]').text(list.length);

    if (!list.length) {
      state.$root.find('#q-nat-dnat-tbody').html('<tr><td colspan="7" style="text-align:center;padding:28px;color:var(--q-text-muted);">No inbound port forwarding rules configured. All unsolicited inbound WAN traffic is dropped.</td></tr>');
      return;
    }

    var dnatRows = list
      .map(function (r) {
        var srcLabel = r.sourceCidr ? '<span class="q-mono">' + esc(r.sourceCidr) + '</span>' : '<span class="q-text-muted">Any WAN</span>';
        var tgtPort = r.intPortRaw === 0 ? esc(r.extPort) : esc(r.targetPort || r.extPort);
        return (
          '<tr class="' + (r.enabled ? '' : 'q-rule-disabled') + '">' +
          '  <td><span class="ui label q-net-wan q-badge-square q-mono">$WAN_IFS</span></td>' +
          '  <td class="q-mono">' + esc(r.protocol) + '</td>' +
          '  <td class="q-mono"><strong>:' + esc(r.extPort) + '</strong></td>' +
          '  <td>' + srcLabel + '</td>' +
          '  <td class="q-mono">' + esc(r.targetIp) + '<span class="q-text-muted">:</span>' + tgtPort + '<span class="q-rule-desc">' + esc(r.description) + '</span></td>' +
          '  <td><div class="ui fitted toggle checkbox q-pf-toggle" data-id="' + esc(r.id) + '"><input type="checkbox"' + (r.enabled ? ' checked' : '') + ' aria-label="Toggle port forward ' + esc(r.extPort) + '"><label></label></div></td>' +
          '  <td><div class="q-row-actions">' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-pf-edit-btn" data-id="' + esc(r.id) + '" aria-label="Edit port forward"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-pf-del-btn" data-id="' + esc(r.id) + '" aria-label="Delete port forward"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-nat-dnat-tbody').html(dnatRows);

    if (Hive.icons) Hive.icons.render();
    state.$root.find('#q-nat-dnat-tbody .ui.checkbox').checkbox();
  }

  function syncTargetPortState() {
    var extVal = $.trim($('#q-pf-ext').val());
    var isRange = extVal.indexOf('-') !== -1;
    var $tport = $('#q-pf-tport');
    $tport.prop('disabled', isRange);
    if (isRange) {
      $tport.val('');
      $tport.attr('placeholder', '1:1 range preserved');
    } else {
      $tport.attr('placeholder', 'Same as external (or 1-65535)');
    }
  }

  function openPfModal(id) {
    state.editingPfId = id || null;
    var r = id ? (state.nat.portForwards || []).find(function (x) { return x.id === id; }) : null;
    $('#q-pf-heading').text(r ? 'Edit Port Forward (' + r.id + ')' : 'Add Port Forward (DNAT)');
    $('#q-pf-proto-dd').dropdown('set selected', r ? r.protocol : 'TCP');
    $('#q-pf-ext').val(r ? r.extPort : '');
    $('#q-pf-ip').val(r ? r.targetIp : '');
    $('#q-pf-tport').val(r && r.intPortRaw > 0 ? String(r.intPortRaw) : '');
    $('#q-pf-src').val(r ? (r.sourceCidr || '') : '');
    $('#q-pf-desc').val(r ? r.description : '');
    $('#q-pf-enabled-chk').checkbox(!r || r.enabled ? 'set checked' : 'set unchecked');
    syncTargetPortState();

    $('#q-pf-ext-field, #q-pf-ip-field, #q-pf-tport-field, #q-pf-src-field').removeClass('error');
    $('#q-pf-ext-err, #q-pf-ip-err, #q-pf-tport-err, #q-pf-src-err').attr('hidden', true);
    Hive.ui.openModal('#q-pf-modal');
  }

  function savePfModal() {
    var v = Hive.validators;
    var protocol = $('#q-pf-proto').val() || 'TCP';
    var extPort = $.trim($('#q-pf-ext').val());
    var targetIp = $.trim($('#q-pf-ip').val());
    var targetPortRaw = $.trim($('#q-pf-tport').val());
    var sourceCidr = $.trim($('#q-pf-src').val());
    var description = $.trim($('#q-pf-desc').val()) || ('DNAT ' + protocol + '/' + extPort + ' -> ' + targetIp);
    var enabled = $('#q-pf-enabled').is(':checked');

    var ok = true;
    $('#q-pf-ext-field, #q-pf-ip-field, #q-pf-tport-field, #q-pf-src-field').removeClass('error');
    $('#q-pf-ext-err, #q-pf-ip-err, #q-pf-tport-err, #q-pf-src-err').attr('hidden', true);

    if (!isSingleOrRangePort(extPort)) {
      $('#q-pf-ext-field').addClass('error');
      $('#q-pf-ext-err').removeAttr('hidden');
      ok = false;
    }
    if (!v.isIPv4(targetIp)) {
      $('#q-pf-ip-field').addClass('error');
      $('#q-pf-ip-err').removeAttr('hidden');
      ok = false;
    }
    var isRange = extPort.indexOf('-') !== -1;
    if (!isRange && targetPortRaw !== '' && !v.isPortNumber(targetPortRaw)) {
      $('#q-pf-tport-field').addClass('error');
      $('#q-pf-tport-err').removeAttr('hidden');
      ok = false;
    }
    if (sourceCidr !== '' && !v.isIPv4OrCIDR(sourceCidr)) {
      $('#q-pf-src-field').addClass('error');
      $('#q-pf-src-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    var intPortNum = !isRange && targetPortRaw !== '' ? Number(targetPortRaw) : 0;

    Hive.services.nat
      .savePortForward({
        id: state.editingPfId,
        protocol: protocol,
        extPort: extPort,
        targetIp: targetIp,
        targetPort: intPortNum > 0 ? String(intPortNum) : extPort,
        intPortRaw: intPortNum,
        sourceCidr: sourceCidr,
        description: description,
        enabled: enabled
      })
      .then(function () {
        $('#q-pf-modal').modal('hide');
        Hive.ui.notify({
          title: 'Port Forward Staged',
          message: 'DNAT + matching forward accept rule queued in pending changes.',
          type: 'success'
        });
      });
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.nat.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.nat = data.nat;
      state.wanConfig = data.wanConfig;
      state.interfaces = data.interfaces || [];
      renderTables();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    cleanupDetachedModals();

    Hive.services.nat.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.nat = data.nat;
      state.wanConfig = data.wanConfig;
      state.interfaces = data.interfaces || [];

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">NAT &amp; Port Forward</h1>' +
        '    <p class="q-page-subtitle">Inbound WAN destination NAT (DNAT) port forwarding and automatic outbound WAN masquerade.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <button type="button" class="ui primary button" id="q-add-pf-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add Port Forward</span></button>' +
        '  </div>' +
        '</div>' +

        // Outbound Masquerade Architecture Card
        '<div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">' +
        '    <div>' +
        '      <h2 class="q-card-title" style="margin-bottom:4px;"><i data-lucide="shield-check" class="q-icon q-text-accent"></i><span>Outbound WAN Masquerade (SNAT)</span></h2>' +
        '      <div id="q-nat-wan-summary"></div>' +
        '    </div>' +
        '    <span class="ui label q-status-success q-mono">Hardened Auto-Masquerade</span>' +
        '  </div>' +
        '  <p class="q-text-secondary" style="margin:var(--q-space-3) 0 0;font-size:12.5px;">NetBee OS automatically masquerades LAN and WireGuard egress traffic across active WAN interfaces (DHCP, PPPoE, or ONT VLAN) with TCP MSS clamping. Every enabled Port Forward below emits both <code>prerouting dnat</code> and <code>custom_forward accept</code> rules atomically.</p>' +
        '</div>' +

        // Port Forwarding Table Card
        '<div class="q-card">' +
        '  <div class="q-card-header">' +
        '    <div>' +
        '      <h2 class="q-card-title">Inbound Port Forwarding Rules (DNAT) <span class="ui label q-mono" data-nat-count="dnat" style="margin-left:6px;">0</span></h2>' +
        '      <p class="q-card-subtitle">Forward external TCP/UDP ports or ranges to internal LAN hosts with optional source CIDR restriction.</p>' +
        '    </div>' +
        '  </div>' +
        '  <div class="q-table-wrap">' +
        '    <table class="ui selectable striped table">' +
        '      <thead><tr><th style="width:104px;">Ingress</th><th style="width:92px;">Proto</th><th style="width:124px;">Ext Port</th><th>Allowed Source</th><th>Internal Target &amp; Description</th><th style="width:66px;">State</th><th style="width:86px;">Edit</th></tr></thead>' +
        '      <tbody id="q-nat-dnat-tbody"></tbody>' +
        '    </table>' +
        '  </div>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);
      renderTables();
    });

    $container.on('click.qNat', '#q-add-pf-btn', function () { openPfModal(null); });
    $container.on('click.qNat', '.q-pf-edit-btn', function () { openPfModal($(this).attr('data-id')); });

    $container.on('change.qNat', '.q-pf-toggle input', function () {
      var $toggle = $(this).closest('.q-pf-toggle');
      var id = $toggle.attr('data-id');
      var enabled = this.checked;
      $toggle.closest('tr').toggleClass('q-rule-disabled', !enabled);
      Hive.services.nat.togglePortForward(id, enabled);
    });

    $container.on('click.qNat', '.q-pf-del-btn', function () {
      Hive.services.nat.deletePortForward($(this).attr('data-id')).then(function () {
        Hive.ui.notify({ title: 'Port Forward Removed', message: 'Rule deletion staged.', type: 'warning' });
      });
    });

    $(document).on('input.qNatModal', '#q-pf-ext', syncTargetPortState);
    $(document).on('click.qNatModal', '#q-pf-save-btn', savePfModal);
    $(document).on('submit.qNatModal', '#q-pf-form', function (e) { e.preventDefault(); savePfModal(); });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (Hive.store.isRuntimeOnlyReason(reason)) return;
      if (reason === 'inline-toggle') {
        Hive.services.nat.getOverview().then(function (data) { state.nat = data.nat; });
        return;
      }
      loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    $(document).off('.qNatModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qNat');
      state.$root = null;
    }
  }

  Hive.router.register('/security/nat', {
    title: 'NAT & Port Forward',
    group: 'Security',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
