/* ==========================================================================
   Hive — Network Interfaces (#/network/interfaces)
   NetBee OS Single-LAN (eth0) + WAN (DHCP / PPPoE / ONT VLAN) + IPv6 + Ethtool.
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var ETHTOOL_OFFLOAD_LABELS = {
    rx: 'RX Checksumming',
    tx: 'TX Checksumming',
    sg: 'Scatter-Gather',
    tso: 'TCP Segmentation Offload (TSO)',
    gso: 'Generic Segmentation Offload (GSO)',
    gro: 'Generic Receive Offload (GRO)',
    rxvlan: 'RX VLAN Hardware Acceleration',
    txvlan: 'TX VLAN Hardware Acceleration'
  };

  var state = {
    $root: null,
    mountToken: 0,
    interfaces: [],
    lanConfig: null,
    wanConfig: null,
    ipv6Config: null,
    search: '',
    zone: 'all',
    viewMode: 'table',
    ethtoolIface: '',
    ethtoolData: null,
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-lan-modal, #q-wan-modal, #q-ethtool-modal, #q-iface-ping-modal').modal('hide').remove();
  }

  function getFiltered() {
    var q = state.search.toLowerCase();
    return state.interfaces.filter(function (item) {
      if (state.zone !== 'all' && item.zone !== state.zone) return false;
      if (q) {
        var hay = (item.device + ' ' + item.label + ' ' + item.ipv4 + ' ' + item.ipv6 + ' ' + item.mac + ' ' + item.mode).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
  }

  function renderModalsHtml() {
    return (
      // Configure LAN (eth0) Modal
      '<div class="ui small modal" id="q-lan-modal" role="dialog" aria-labelledby="q-lan-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-lan-title"><i data-lucide="network" class="q-icon q-text-accent"></i><span>Configure LAN Interface (<span class="q-mono" id="q-lan-dev-lbl">eth0</span>)</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-lan-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-lan-ip-field"><label for="q-lan-ip">LAN Gateway IPv4</label><input id="q-lan-ip" type="text" class="q-mono" placeholder="192.168.10.1"><span class="q-field-error" id="q-lan-ip-err" hidden>Enter a valid IPv4 host address.</span></div>' +
      '        <div class="field required" id="q-lan-mask-field"><label for="q-lan-mask">IPv4 Subnet Mask</label><input id="q-lan-mask" type="text" class="q-mono" placeholder="255.255.255.0"><span class="q-field-error" id="q-lan-mask-err" hidden>Enter a valid subnet mask (e.g. 255.255.255.0).</span></div>' +
      '      </div>' +
      '      <div class="field" style="margin-bottom:0;">' +
      '        <div class="ui toggle checkbox" id="q-lan-radvd-chk"><input type="checkbox" id="q-lan-radvd"><label for="q-lan-radvd">Enable IPv6 Router Advertisements (SLAAC via <code>radvd</code>)</label></div>' +
      '      </div>' +
      '      <p class="q-field-hint" style="margin-top:10px;">Updating the LAN IP automatically updates AdGuardHome DNS/DHCP bind addresses, Dropbear SSH listener, and nftables rules (protected by 60s rollback).</p>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-lan-save-btn">Stage LAN Settings</button>' +
      '  </div>' +
      '</div>' +

      // Configure WAN (eth1 / PPPoE / ONT VLAN) Modal
      '<div class="ui small modal" id="q-wan-modal" role="dialog" aria-labelledby="q-wan-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-wan-title"><i data-lucide="globe" class="q-icon q-text-accent"></i><span>Configure WAN Uplink</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-wan-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field"><label>WAN Connection Mode</label>' +
      '          <div class="ui fluid selection dropdown" id="q-wan-mode-dd" data-q-manual-init>' +
      '            <input type="hidden" id="q-wan-mode" value="dhcp"><i class="dropdown icon"></i><div class="text">DHCP (Automatic IP)</div>' +
      '            <div class="menu">' +
      '              <div class="item" data-value="dhcp">DHCP (Cable / Bridged Modem)</div>' +
      '              <div class="item" data-value="pppoe">PPPoE (Direct Untagged)</div>' +
      '              <div class="item" data-value="ont_vlan">Fiber ONT VLAN + PPPoE (802.1Q)</div>' +
      '            </div>' +
      '          </div>' +
      '        </div>' +
      '        <div class="field required"><label for="q-wan-dev">Physical WAN NIC</label><input id="q-wan-dev" type="text" class="q-mono" value="eth1"></div>' +
      '      </div>' +

      '      <div id="q-wan-vlan-wrap" hidden style="margin-bottom:var(--q-space-3);">' +
      '        <div class="field required" id="q-wan-vlan-field"><label for="q-wan-vlan">ISP 802.1Q VLAN ID (e.g. 35 for Fiber ONT)</label><input id="q-wan-vlan" type="number" class="q-mono" min="1" max="4094" value="35"><span class="q-field-error" id="q-wan-vlan-err" hidden>Enter a valid VLAN tag between 1 and 4094.</span></div>' +
      '      </div>' +

      '      <div id="q-wan-pppoe-wrap" hidden style="margin-bottom:var(--q-space-3);">' +
      '        <div class="two fields">' +
      '          <div class="field required" id="q-wan-user-field"><label for="q-wan-user">PPPoE Username</label><input id="q-wan-user" type="text" class="q-mono" placeholder="user@isp"><span class="q-field-error" id="q-wan-user-err" hidden>PPPoE username is required.</span></div>' +
      '          <div class="field"><label for="q-wan-pass">PPPoE Password</label><input id="q-wan-pass" type="password" autocomplete="new-password" placeholder="Leave blank to keep stored password"></div>' +
      '        </div>' +
      '      </div>' +

      '      <div class="two fields">' +
      '        <div class="field required" id="q-wan-mtu-field"><label for="q-wan-mtu">MTU (576 – 1500)</label><input id="q-wan-mtu" type="number" class="q-mono" min="576" max="1500" value="1500"><span class="q-field-error" id="q-wan-mtu-err" hidden>MTU must be between 576 and 1500.</span></div>' +
      '        <div class="field" id="q-wan-mac-field"><label for="q-wan-mac">MAC Address Clone (Optional)</label><input id="q-wan-mac" type="text" class="q-mono" placeholder="AA:BB:CC:DD:EE:FF"><span class="q-field-error" id="q-wan-mac-err" hidden>Enter a valid MAC (AA:BB:CC:DD:EE:FF) or leave blank.</span></div>' +
      '      </div>' +

      '      <div class="field" style="margin-bottom:0;">' +
      '        <div class="ui toggle checkbox" id="q-wan-v6pd-chk"><input type="checkbox" id="q-wan-v6pd"><label for="q-wan-v6pd">Enable DHCPv6 Prefix Delegation (IPv6-PD to LAN)</label></div>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-wan-save-btn">Stage WAN Settings</button>' +
      '  </div>' +
      '</div>' +

      // Ethtool Hardware & Offloads Modal
      '<div class="ui small modal" id="q-ethtool-modal" role="dialog" aria-labelledby="q-eth-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-eth-title"><i data-lucide="cpu" class="q-icon q-text-accent"></i><span>NIC Hardware &amp; Offloads (<span class="q-mono" id="q-eth-dev-lbl"></span>)</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <div class="q-kv-list" id="q-eth-link-summary" style="margin-bottom:var(--q-space-4);"></div>' +
      '    <form class="ui form" id="q-ethtool-form" novalidate>' +
      '      <div class="field"><div class="ui toggle checkbox" id="q-eth-autoneg-chk"><input type="checkbox" id="q-eth-autoneg" checked><label for="q-eth-autoneg">Enable Ethernet Auto-Negotiation (Recommended)</label></div></div>' +
      '      <div class="two fields" id="q-eth-manual-wrap" hidden>' +
      '        <div class="field"><label>Forced Speed (Mb/s)</label>' +
      '          <div class="ui fluid selection dropdown" id="q-eth-speed-dd"><input type="hidden" id="q-eth-speed" value="1000"><i class="dropdown icon"></i><div class="text">1000 Mb/s</div><div class="menu"><div class="item" data-value="100">100 Mb/s</div><div class="item" data-value="1000">1000 Mb/s (1GbE)</div><div class="item" data-value="2500">2500 Mb/s (2.5GbE)</div></div></div>' +
      '        </div>' +
      '        <div class="field"><label>Duplex</label>' +
      '          <div class="ui fluid selection dropdown" id="q-eth-duplex-dd"><input type="hidden" id="q-eth-duplex" value="full"><i class="dropdown icon"></i><div class="text">Full Duplex</div><div class="menu"><div class="item" data-value="full">Full Duplex</div><div class="item" data-value="half">Half Duplex</div></div></div>' +
      '        </div>' +
      '      </div>' +
      '      <div class="field"><label>Wake-on-LAN (WoL)</label>' +
      '        <div class="ui fluid selection dropdown" id="q-eth-wol-dd"><input type="hidden" id="q-eth-wol" value=""><i class="dropdown icon"></i><div class="text">Leave Unchanged</div><div class="menu"><div class="item" data-value="">Leave Unchanged</div><div class="item" data-value="d">Disabled (d)</div><div class="item" data-value="g">Wake on MagicPacket (g)</div></div></div>' +
      '      </div>' +
      '      <div class="field" style="margin-bottom:0;"><label>Hardware Checksum &amp; Segmentation Offloads</label><div id="q-eth-offloads-list" class="q-kv-list" style="margin-top:8px;"></div></div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-eth-save-btn">Apply NIC Settings</button>' +
      '  </div>' +
      '</div>' +

      // Quick Ping Modal
      '<div class="ui small modal" id="q-iface-ping-modal" role="dialog" aria-labelledby="q-ifping-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-ifping-title"><i data-lucide="terminal" class="q-icon q-text-accent"></i><span>Live ICMP Ping Probe</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-ifping-form" novalidate style="margin-bottom:var(--q-space-3);">' +
      '      <div class="fields" style="align-items:end;margin:0;">' +
      '        <div class="twelve wide field"><label for="q-ifping-host">Target IP / Host</label><input id="q-ifping-host" type="text" class="q-mono" value="1.1.1.1"></div>' +
      '        <div class="four wide field"><button type="submit" class="ui fluid primary button" id="q-ifping-run">Ping</button></div>' +
      '      </div>' +
      '    </form>' +
      '    <div class="q-console"><div class="q-console-header"><span>netbeed ping</span><span id="q-ifping-st">ready</span></div><pre class="q-console-body" id="q-ifping-out">Click Ping to run a live 4-packet probe from the router.</pre></div>' +
      '  </div>' +
      '  <div class="actions"><button type="button" class="ui secondary cancel button">Close</button></div>' +
      '</div>'
    );
  }

  function renderViewContent() {
    if (!state.$root) return;
    var fmt = Hive.format;
    var esc = fmt.escapeHtml;
    var items = getFiltered();
    var lanIf = (state.lanConfig && state.lanConfig.interface) || 'eth0';
    var wanIf = (state.wanConfig && state.wanConfig.interface) || 'eth1';

    state.$root.find('#q-if-count').text(items.length + ' of ' + state.interfaces.length + ' interfaces');

    // Summary Role Cards for LAN & WAN
    var lanSummary = state.lanConfig ? (state.lanConfig.ip + ' / ' + state.lanConfig.netmask) : '192.168.10.1 / 255.255.255.0';
    var wanSummary = state.wanConfig
      ? (state.wanConfig.mode.toUpperCase() + (state.wanConfig.mode === 'ont_vlan' ? ' (VLAN ' + state.wanConfig.vlanId + ')' : '') + ' · MTU ' + state.wanConfig.mtu)
      : 'DHCP · MTU 1500';
    state.$root.find('#q-if-lan-summary').text(lanIf + ' · ' + lanSummary);
    state.$root.find('#q-if-wan-summary').text(wanIf + ' · ' + wanSummary);

    var $host = state.$root.find('#q-if-view-host');
    if (!items.length) {
      $host.html('<div class="q-card q-empty-state"><i data-lucide="search-x" class="q-icon q-icon-xl"></i><div>No interfaces match the current filter.</div></div>');
      if (Hive.icons) Hive.icons.render();
      return;
    }

    if (state.viewMode === 'cards') {
      var cards = items
        .map(function (it) {
          var isUp = it.status === 'up';
          var isPhys = it.type === 'physical';
          return (
            '<div class="q-card">' +
            '  <div class="q-iface-card-top">' +
            '    <div style="display:flex;align-items:center;gap:8px;"><span class="q-status-dot ' + (isUp ? 'is-success' : 'is-danger') + '"></span><strong class="q-mono" style="font-size:15px;">' + esc(it.device) + '</strong> <span class="ui label ' + fmt.zoneBadgeClass(it.zone) + ' q-badge-square q-mono">' + esc(fmt.zoneLabel(it.zone)) + '</span></div>' +
            '    <span class="ui label ' + (isUp ? 'q-status-success' : 'q-status-danger') + '">' + (isUp ? 'UP' : 'DOWN') + '</span>' +
            '  </div>' +
            '  <div class="q-kv-list" style="margin:12px 0;">' +
            '    <div class="q-kv-row"><span class="q-kv-label">Mode</span><span class="q-kv-value q-mono">' + esc(it.mode) + '</span></div>' +
            '    <div class="q-kv-row"><span class="q-kv-label">IPv4</span><span class="q-kv-value q-mono">' + esc(it.ipv4) + '</span></div>' +
            '    <div class="q-kv-row"><span class="q-kv-label">Link / MTU</span><span class="q-kv-value q-mono">' + esc(it.speed) + ' · ' + it.mtu + '</span></div>' +
            '    <div class="q-kv-row"><span class="q-kv-label">Live Rate</span><span class="q-kv-value q-mono">↓ ' + fmt.mbps(it.rxMbps) + ' · ↑ ' + fmt.mbps(it.txMbps) + '</span></div>' +
            '  </div>' +
            '  <div style="display:flex;gap:6px;flex-wrap:wrap;">' +
            (it.device === lanIf ? '<button type="button" class="ui mini primary button q-open-lan-btn">Edit LAN</button>' : '') +
            (it.device === wanIf || it.device === 'ppp0' ? '<button type="button" class="ui mini primary button q-open-wan-btn">Edit WAN</button>' : '') +
            (isPhys ? '<button type="button" class="ui mini secondary button q-open-eth-btn" data-dev="' + esc(it.device) + '">Ethtool</button>' : '') +
            '  </div>' +
            '</div>'
          );
        })
        .join('');
      $host.html('<div class="q-scope-grid">' + cards + '</div>');
      if (Hive.icons) Hive.icons.render();
      return;
    }

    var rows = items
      .map(function (it) {
        var isUp = it.status === 'up';
        var isPhys = it.type === 'physical';
        return (
          '<tr>' +
          '  <td><div style="display:flex;align-items:center;gap:8px;"><span class="q-status-dot ' + (isUp ? 'is-success' : 'is-danger') + '"></span><div><strong class="q-mono">' + esc(it.device) + '</strong><span class="q-rule-desc">' + esc(it.label) + ' · ' + esc(it.mac) + '</span></div></div></td>' +
          '  <td><span class="ui label ' + fmt.zoneBadgeClass(it.zone) + ' q-badge-square q-mono">' + esc(fmt.zoneLabel(it.zone)) + '</span></td>' +
          '  <td class="q-mono">' + esc(it.mode) + '</td>' +
          '  <td class="q-mono"><strong>' + esc(it.ipv4) + '</strong><span class="q-rule-desc">' + esc(it.ipv6 !== '—' ? it.ipv6 : (it.gateway !== '—' ? 'GW ' + it.gateway : '')) + '</span></td>' +
          '  <td class="q-mono">' + esc(it.speed) + '<span class="q-rule-desc">MTU ' + it.mtu + '</span></td>' +
          '  <td class="q-mono">↓ ' + fmt.mbps(it.rxMbps) + ' / ↑ ' + fmt.mbps(it.txMbps) + '<span class="q-rule-desc">Total ↓' + fmt.bytesGb(it.rxTotalGb) + ' · ↑' + fmt.bytesGb(it.txTotalGb) + '</span></td>' +
          '  <td><span class="ui label ' + (isUp ? 'q-status-success' : 'q-status-danger') + '">' + (isUp ? 'UP' : 'DOWN') + '</span></td>' +
          '  <td><div class="q-row-actions">' +
          (it.device === lanIf ? '<button type="button" class="ui mini icon button q-btn-ghost q-open-lan-btn" title="Configure LAN"><i data-lucide="sliders-horizontal" class="q-icon q-icon-sm"></i></button>' : '') +
          (it.device === wanIf || it.device === 'ppp0' ? '<button type="button" class="ui mini icon button q-btn-ghost q-open-wan-btn" title="Configure WAN"><i data-lucide="globe" class="q-icon q-icon-sm"></i></button>' : '') +
          (it.type === 'wireguard' ? '<a href="#/security/vpn" class="ui mini icon button q-btn-ghost" title="Configure WireGuard"><i data-lucide="lock-keyhole" class="q-icon q-icon-sm"></i></a>' : '') +
          (isPhys ? '<button type="button" class="ui mini icon button q-btn-ghost q-open-eth-btn" data-dev="' + esc(it.device) + '" title="Hardware & Offloads (ethtool)"><i data-lucide="cpu" class="q-icon q-icon-sm"></i></button>' : '') +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-open-ping-btn" data-dev="' + esc(it.device) + '" title="Ping probe"><i data-lucide="terminal" class="q-icon q-icon-sm"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');

    $host.html(
      '<div class="q-table-wrap">' +
      '  <table class="ui selectable striped table">' +
      '    <thead><tr><th>Interface</th><th>Zone</th><th>Mode</th><th>IPv4 / IPv6</th><th>Link &amp; MTU</th><th>Throughput</th><th>State</th><th style="width:118px;">Actions</th></tr></thead>' +
      '    <tbody>' + rows + '</tbody>' +
      '  </table>' +
      '</div>'
    );
    if (Hive.icons) Hive.icons.render();
  }

  function openLanModal() {
    var lan = state.lanConfig || { interface: 'eth0', ip: '192.168.10.1', netmask: '255.255.255.0' };
    var v6 = state.ipv6Config || { radvdEnabled: false };
    $('#q-lan-dev-lbl').text(lan.interface);
    $('#q-lan-ip').val(lan.ip);
    $('#q-lan-mask').val(lan.netmask);
    $('#q-lan-radvd-chk').checkbox(v6.radvdEnabled ? 'set checked' : 'set unchecked');
    $('#q-lan-ip-field, #q-lan-mask-field').removeClass('error');
    $('#q-lan-ip-err, #q-lan-mask-err').attr('hidden', true);
    Hive.ui.openModal('#q-lan-modal');
  }

  function saveLanModal() {
    var ip = $.trim($('#q-lan-ip').val());
    var mask = $.trim($('#q-lan-mask').val());
    var radvd = $('#q-lan-radvd').is(':checked');

    var ok = true;
    $('#q-lan-ip-field, #q-lan-mask-field').removeClass('error');
    $('#q-lan-ip-err, #q-lan-mask-err').attr('hidden', true);

    if (!Hive.validators.isIPv4(ip)) {
      $('#q-lan-ip-field').addClass('error');
      $('#q-lan-ip-err').removeAttr('hidden');
      ok = false;
    }
    if (!Hive.validators.isIPv4(mask)) {
      $('#q-lan-mask-field').addClass('error');
      $('#q-lan-mask-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    Promise.all([
      Hive.services.interfaces.stageLan({ interface: (state.lanConfig && state.lanConfig.interface) || 'eth0', ip: ip, netmask: mask }),
      Hive.services.interfaces.stageIpv6({ radvdEnabled: radvd, ipv6Pd: state.ipv6Config ? state.ipv6Config.ipv6Pd : false })
    ]).then(function () {
      $('#q-lan-modal').modal('hide');
      Hive.ui.notify({ title: 'LAN Settings Staged', message: 'Click Apply in the bottom dock to commit LAN changes.', type: 'info' });
    });
  }

  function syncWanModeFields(mode) {
    var isVlan = mode === 'ont_vlan';
    var isPpp = mode === 'pppoe' || mode === 'ont_vlan';
    if (isVlan) $('#q-wan-vlan-wrap').removeAttr('hidden');
    else $('#q-wan-vlan-wrap').attr('hidden', true);
    if (isPpp) $('#q-wan-pppoe-wrap').removeAttr('hidden');
    else $('#q-wan-pppoe-wrap').attr('hidden', true);

    var curMtu = Number($('#q-wan-mtu').val());
    if (isPpp && curMtu === 1500) $('#q-wan-mtu').val(1492);
    if (!isPpp && curMtu === 1492) $('#q-wan-mtu').val(1500);
  }

  function openWanModal() {
    var wan = state.wanConfig || { mode: 'dhcp', interface: 'eth1', vlanId: 35, pppoeUser: '', macClone: '', mtu: 1500, ipv6Pd: false };
    $('#q-wan-mode-dd').dropdown({ onChange: syncWanModeFields }).dropdown('set selected', wan.mode || 'dhcp');
    $('#q-wan-dev').val(wan.interface || 'eth1');
    $('#q-wan-vlan').val(wan.vlanId || 35);
    $('#q-wan-user').val(wan.pppoeUser || '');
    $('#q-wan-pass').val('');
    $('#q-wan-mtu').val(wan.mtu || (wan.mode === 'dhcp' ? 1500 : 1492));
    $('#q-wan-mac').val(wan.macClone || '');
    $('#q-wan-v6pd-chk').checkbox(wan.ipv6Pd ? 'set checked' : 'set unchecked');
    syncWanModeFields(wan.mode || 'dhcp');
    $('#q-wan-form .field.error').removeClass('error');
    $('#q-wan-form .q-field-error').attr('hidden', true);
    Hive.ui.openModal('#q-wan-modal');
  }

  function saveWanModal() {
    var mode = $('#q-wan-mode').val() || 'dhcp';
    var dev = $.trim($('#q-wan-dev').val()) || 'eth1';
    var vlanId = Number($('#q-wan-vlan').val() || 35);
    var pppUser = $.trim($('#q-wan-user').val());
    var pppPass = $('#q-wan-pass').val();
    var mtu = Number($('#q-wan-mtu').val() || 1500);
    var mac = $.trim($('#q-wan-mac').val()).toUpperCase();
    var v6pd = $('#q-wan-v6pd').is(':checked');

    $('#q-wan-form .field.error').removeClass('error');
    $('#q-wan-form .q-field-error').attr('hidden', true);
    var ok = true;

    if (mode === 'ont_vlan' && (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094)) {
      $('#q-wan-vlan-field').addClass('error');
      $('#q-wan-vlan-err').removeAttr('hidden');
      ok = false;
    }
    if ((mode === 'pppoe' || mode === 'ont_vlan') && !pppUser) {
      $('#q-wan-user-field').addClass('error');
      $('#q-wan-user-err').removeAttr('hidden');
      ok = false;
    }
    if (!Number.isInteger(mtu) || mtu < 576 || mtu > 1500) {
      $('#q-wan-mtu-field').addClass('error');
      $('#q-wan-mtu-err').removeAttr('hidden');
      ok = false;
    }
    if (mac && !Hive.validators.isMAC(mac)) {
      $('#q-wan-mac-field').addClass('error');
      $('#q-wan-mac-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    var patch = {
      mode: mode,
      interface: dev,
      vlanId: vlanId,
      pppoeUser: pppUser,
      macClone: mac,
      mtu: mtu,
      ipv6Pd: v6pd,
      radvdEnabled: state.ipv6Config ? state.ipv6Config.radvdEnabled : false
    };
    if (pppPass) patch.pppoePassword = pppPass;

    Hive.services.interfaces.stageWan(patch).then(function () {
      $('#q-wan-modal').modal('hide');
      Hive.ui.notify({ title: 'WAN Settings Staged', message: 'Click Apply in the bottom dock to commit WAN changes.', type: 'info' });
    });
  }

  function openEthtoolModal(dev) {
    state.ethtoolIface = dev;
    $('#q-eth-dev-lbl').text(dev);
    $('#q-eth-link-summary').html('<div class="q-text-muted">Reading NIC registers via ethtool...</div>');
    $('#q-eth-offloads-list').empty();
    Hive.ui.openModal('#q-ethtool-modal');

    Hive.services.interfaces
      .getEthtool(dev)
      .then(function (data) {
        state.ethtoolData = data;
        var esc = Hive.format.escapeHtml;
        var link = data.link || {};
        var offloads = data.offloads || {};
        var persisted = data.persisted || null;

        $('#q-eth-link-summary').html(
          '<div class="q-kv-row"><span class="q-kv-label">Negotiated Speed / Duplex</span><span class="q-kv-value q-mono">' + esc((link.speed || 'Unknown') + ' · ' + (link.duplex || 'Unknown')) + '</span></div>' +
          '<div class="q-kv-row"><span class="q-kv-label">Carrier Link</span><span class="q-kv-value">' + (link.link_detected ? '<span class="ui mini label q-status-success">Detected</span>' : '<span class="ui mini label q-status-danger">No Carrier</span>') + '</span></div>' +
          '<div class="q-kv-row"><span class="q-kv-label">Wake-on-LAN Support</span><span class="q-kv-value q-mono">' + esc((link.supports_wake_on || '—') + ' (active: ' + (link.wake_on || '—') + ')') + '</span></div>'
        );

        var autoneg = persisted ? Boolean(persisted.autoneg) : link.autoneg !== false;
        $('#q-eth-autoneg-chk').checkbox(autoneg ? 'set checked' : 'set unchecked');
        if (autoneg) $('#q-eth-manual-wrap').attr('hidden', true);
        else $('#q-eth-manual-wrap').removeAttr('hidden');

        if (persisted && persisted.speed) $('#q-eth-speed-dd').dropdown('set selected', String(persisted.speed));
        if (persisted && persisted.duplex) $('#q-eth-duplex-dd').dropdown('set selected', persisted.duplex);
        $('#q-eth-wol-dd').dropdown('set selected', persisted && persisted.wol ? persisted.wol : '');

        var offHtml = Object.keys(ETHTOOL_OFFLOAD_LABELS)
          .map(function (k) {
            var feat = offloads[k] || { active: false, fixed: true };
            return (
              '<div class="q-kv-row">' +
              '  <span class="q-kv-label">' + esc(ETHTOOL_OFFLOAD_LABELS[k]) + (feat.fixed ? ' <span class="q-mono">[fixed]</span>' : '') + '</span>' +
              '  <span class="q-kv-value"><div class="ui fitted toggle checkbox"><input type="checkbox" class="q-eth-off-chk" data-feat="' + esc(k) + '"' + (feat.active ? ' checked' : '') + (feat.fixed ? ' disabled' : '') + '><label></label></div></span>' +
              '</div>'
            );
          })
          .join('');
        $('#q-eth-offloads-list').html(offHtml);
        $('#q-eth-offloads-list .ui.checkbox').checkbox();
      })
      .catch(function (err) {
        $('#q-eth-link-summary').html('<div class="q-text-danger">' + Hive.format.escapeHtml(err.message) + '</div>');
      });
  }

  function saveEthtoolModal() {
    var autoneg = $('#q-eth-autoneg').is(':checked');
    var speed = Number($('#q-eth-speed').val() || 1000);
    var duplex = $('#q-eth-duplex').val() || 'full';
    var wol = $('#q-eth-wol').val() || '';
    var offloads = {};

    $('#q-eth-offloads-list .q-eth-off-chk:not(:disabled)').each(function () {
      var k = $(this).attr('data-feat');
      offloads[k] = this.checked;
    });

    var payload = {
      autoneg: autoneg,
      speed: autoneg ? 0 : speed,
      duplex: autoneg ? '' : duplex,
      wol: wol,
      offloads: offloads
    };

    var $btn = $('#q-eth-save-btn').addClass('loading disabled');
    Hive.services.interfaces
      .saveEthtool(state.ethtoolIface, payload)
      .then(function () {
        $('#q-ethtool-modal').modal('hide');
        Hive.ui.notify({ title: 'Ethtool Applied', message: 'Updated hardware link & offload parameters for ' + state.ethtoolIface + '.', type: 'success' });
      })
      .catch(function (err) {
        Hive.ui.notify({ title: 'Ethtool Error', message: err.message, type: 'error' });
      })
      .then(function () {
        $btn.removeClass('loading disabled');
      });
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.interfaces.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.interfaces = data.interfaces;
      state.lanConfig = data.lanConfig;
      state.wanConfig = data.wanConfig;
      state.ipv6Config = data.ipv6Config;
      renderViewContent();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.search = '';
    state.zone = 'all';
    cleanupDetachedModals();

    Hive.services.interfaces.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.interfaces = data.interfaces;
      state.lanConfig = data.lanConfig;
      state.wanConfig = data.wanConfig;
      state.ipv6Config = data.ipv6Config;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Network Interfaces</h1>' +
        '    <p class="q-page-subtitle">Configure single-LAN (<code>eth0</code>), WAN uplink (DHCP / PPPoE / Fiber ONT VLAN), IPv6 SLAAC/PD, and NIC offloads.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <button type="button" class="ui secondary button" id="q-wan-reconnect-btn"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Reconnect WAN</span></button>' +
        '    <button type="button" class="ui secondary button q-open-lan-btn"><i data-lucide="network" class="q-icon q-icon-sm"></i><span>Configure LAN</span></button>' +
        '    <button type="button" class="ui primary button q-open-wan-btn"><i data-lucide="globe" class="q-icon q-icon-sm"></i><span>Configure WAN</span></button>' +
        '  </div>' +
        '</div>' +

        '<div class="q-backup-grid" style="margin-bottom:var(--q-space-4);">' +
        '  <div class="q-card" style="display:flex;align-items:center;justify-content:space-between;gap:12px;">' +
        '    <div><div class="q-kpi-label">LAN Configuration</div><div class="q-mono" style="margin-top:4px;font-weight:600;" id="q-if-lan-summary"></div></div>' +
        '    <button type="button" class="ui mini secondary button q-open-lan-btn">Edit LAN</button>' +
        '  </div>' +
        '  <div class="q-card" style="display:flex;align-items:center;justify-content:space-between;gap:12px;">' +
        '    <div><div class="q-kpi-label">WAN Uplink Mode</div><div class="q-mono" style="margin-top:4px;font-weight:600;" id="q-if-wan-summary"></div></div>' +
        '    <button type="button" class="ui mini primary button q-open-wan-btn">Edit WAN</button>' +
        '  </div>' +
        '</div>' +

        '<div class="q-toolbar">' +
        '  <div class="q-toolbar-left">' +
        '    <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-if-search" placeholder="Search device, IP, MAC..."></div>' +
        '    <div class="ui selection dropdown" id="q-if-zone-filter" data-q-manual-init style="min-width:140px;"><input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Zones</div><div class="menu"><div class="item" data-value="all">All Zones</div><div class="item" data-value="lan">LAN</div><div class="item" data-value="wan">WAN</div><div class="item" data-value="vpn">WireGuard VPN</div></div></div>' +
        '  </div>' +
        '  <div class="q-toolbar-right">' +
        '    <span class="ui label q-mono" id="q-if-count"></span>' +
        '    <div class="ui mini icon buttons" id="q-if-view-btns">' +
        '      <button type="button" class="ui button active" data-view="table" title="Table view"><i data-lucide="list" class="q-icon q-icon-sm"></i></button>' +
        '      <button type="button" class="ui button" data-view="cards" title="Card view"><i data-lucide="layout-grid" class="q-icon q-icon-sm"></i></button>' +
        '    </div>' +
        '  </div>' +
        '</div>' +

        '<div id="q-if-view-host"></div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);

      $('#q-if-zone-filter').dropdown({
        onChange: function (v) {
          state.zone = v || 'all';
          renderViewContent();
        }
      });

      renderViewContent();
    });

    $container.on('input.qIfaces', '#q-if-search', function () {
      state.search = $.trim($(this).val());
      renderViewContent();
    });

    $container.on('click.qIfaces', '#q-if-view-btns .button', function () {
      state.viewMode = $(this).attr('data-view') || 'table';
      $(this).addClass('active').siblings().removeClass('active');
      renderViewContent();
    });

    $container.on('click.qIfaces', '.q-open-lan-btn', openLanModal);
    $container.on('click.qIfaces', '.q-open-wan-btn', openWanModal);
    $container.on('click.qIfaces', '.q-open-eth-btn', function () {
      openEthtoolModal($(this).attr('data-dev'));
    });

    $container.on('click.qIfaces', '#q-wan-reconnect-btn', function () {
      var $btn = $(this).addClass('loading disabled');
      Hive.services.interfaces
        .reconnectWan()
        .then(function (res) {
          Hive.ui.notify({ title: 'WAN Reconnected', message: 'Triggered WAN session renewal (' + (res.mode || 'dhcp').toUpperCase() + ').', type: 'success' });
          loadAndRender();
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Reconnect Failed', message: err.message, type: 'error' });
        })
        .then(function () {
          $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qIfaces', '.q-open-ping-btn', function () {
      $('#q-ifping-out').text('Ready to run ICMP ping.');
      $('#q-ifping-st').text('ready');
      Hive.ui.openModal('#q-iface-ping-modal');
    });

    $(document).on('change.qIfacesModal', '#q-eth-autoneg', function () {
      if (this.checked) $('#q-eth-manual-wrap').attr('hidden', true);
      else $('#q-eth-manual-wrap').removeAttr('hidden');
    });

    $(document).on('click.qIfacesModal', '#q-lan-save-btn', saveLanModal);
    $(document).on('submit.qIfacesModal', '#q-lan-form', function (e) { e.preventDefault(); saveLanModal(); });
    $(document).on('click.qIfacesModal', '#q-wan-save-btn', saveWanModal);
    $(document).on('submit.qIfacesModal', '#q-wan-form', function (e) { e.preventDefault(); saveWanModal(); });
    $(document).on('click.qIfacesModal', '#q-eth-save-btn', saveEthtoolModal);

    $(document).on('submit.qIfacesModal', '#q-ifping-form', function (e) {
      e.preventDefault();
      var host = $.trim($('#q-ifping-host').val());
      if (!host) return;
      var $btn = $('#q-ifping-run').addClass('loading disabled');
      $('#q-ifping-st').text('probing...');
      $('#q-ifping-out').text('Running ping -c 4 ' + host + ' ...');
      Hive.services.diagnostics
        .ping(host, 4)
        .then(function (res) {
          $('#q-ifping-out').text(res.output || 'No output');
          $('#q-ifping-st').text(res.ok ? 'completed' : 'packet loss / error');
        })
        .catch(function (err) {
          $('#q-ifping-out').text(err.message);
          $('#q-ifping-st').text('error');
        })
        .then(function () {
          $btn.removeClass('loading disabled');
        });
    });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (reason === 'audit') return;
      loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    $(document).off('.qIfacesModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qIfaces');
      state.$root = null;
    }
  }

  Hive.router.register('/network/interfaces', {
    title: 'Interfaces',
    group: 'Network',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
