/* ==========================================================================
   Hive — Dynamic Network Interfaces (#/network/interfaces)
   NetBee OS Dynamic LAN/WAN Role Assignment, Role Swap, Orthogonal 802.1Q VLAN,
   DHCP / Static IP / PPPoE WAN, Custom WAN DNS, MAC Pinning, Link State & Ethtool.
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
    labelIface: '',
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-lan-modal, #q-wan-modal, #q-swap-modal, #q-label-modal, #q-ethtool-modal, #q-iface-ping-modal').modal('hide').remove();
  }

  function getPhysicalInterfaces(ensureDevs) {
    var seen = {};
    var list = [];
    (state.interfaces || []).forEach(function (it) {
      if (it.type === 'physical') {
        seen[it.device] = true;
        list.push(it);
      }
    });
    (ensureDevs || []).forEach(function (dev) {
      if (dev && !seen[dev] && dev.indexOf('.') === -1 && dev !== 'ppp0' && dev.indexOf('wg') !== 0) {
        seen[dev] = true;
        list.push({ device: dev, type: 'physical', driver: '', speed: 'Configured', mac: '—', zone: 'unassigned' });
      }
    });
    return list;
  }

  function buildPhysicalDropdownMenuHtml(currentOtherRoleDev, otherRoleLabel) {
    var esc = Hive.format.escapeHtml;
    var lanIf = (state.lanConfig && state.lanConfig.interface) || 'eth0';
    var wanIf = (state.wanConfig && state.wanConfig.interface) || 'eth1';
    var phys = getPhysicalInterfaces([lanIf, wanIf]);
    return phys
      .map(function (it) {
        var meta = [];
        if (it.driver) meta.push(it.driver);
        if (it.speed && it.speed !== 'Virtual') meta.push(it.speed);
        if (it.device === currentOtherRoleDev) meta.push('currently ' + otherRoleLabel + ' — auto-swap');
        var sub = meta.length ? ' — ' + esc(meta.join(' · ')) : '';
        return '<div class="item" data-value="' + esc(it.device) + '"><span class="q-mono">' + esc(it.device) + '</span>' + sub + '</div>';
      })
      .join('');
  }

  function findDeviceMac(dev) {
    var hit = (state.interfaces || []).find(function (i) { return i.device === dev; });
    return hit && hit.mac && hit.mac !== '—' && Hive.validators.isMAC(hit.mac) ? hit.mac.toUpperCase() : '';
  }

  function getFiltered() {
    var q = state.search.toLowerCase();
    return state.interfaces.filter(function (item) {
      if (state.zone !== 'all' && item.zone !== state.zone) return false;
      if (q) {
        var hay = (item.device + ' ' + item.label + ' ' + (item.driver || '') + ' ' + item.ipv4 + ' ' + item.ipv6 + ' ' + item.mac + ' ' + item.mode).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
  }

  function renderModalsHtml() {
    return (
      // Configure LAN Modal (Dynamic Physical Port + IPv4 + MTU + MAC Pinning + SLAAC)
      '<div class="ui small modal" id="q-lan-modal" role="dialog" aria-labelledby="q-lan-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-lan-title"><i data-lucide="network" class="q-icon q-text-accent"></i><span>Configure LAN Interface</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-lan-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field required"><label>Physical LAN Port</label>' +
      '          <div class="ui fluid selection dropdown" id="q-lan-dev-dd" data-q-manual-init><input type="hidden" id="q-lan-dev" value="eth0"><i class="dropdown icon"></i><div class="text">eth0</div><div class="menu"></div></div>' +
      '        </div>' +
      '        <div class="field required" id="q-lan-mtu-field"><label for="q-lan-mtu">LAN MTU (576 – 9000)</label><input id="q-lan-mtu" type="number" class="q-mono" min="576" max="9000" value="1500"><span class="q-field-error" id="q-lan-mtu-err" hidden>MTU must be between 576 and 9000.</span></div>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-lan-ip-field"><label for="q-lan-ip">LAN Gateway IPv4</label><input id="q-lan-ip" type="text" class="q-mono" placeholder="192.168.10.1"><span class="q-field-error" id="q-lan-ip-err" hidden>Enter a valid IPv4 host address.</span></div>' +
      '        <div class="field required" id="q-lan-mask-field"><label for="q-lan-mask">IPv4 Subnet Mask</label><input id="q-lan-mask" type="text" class="q-mono" placeholder="255.255.255.0"><span class="q-field-error" id="q-lan-mask-err" hidden>Enter a valid subnet mask (e.g. 255.255.255.0).</span></div>' +
      '      </div>' +
      '      <div class="field">' +
      '        <div class="ui toggle checkbox" id="q-lan-pinmac-chk"><input type="checkbox" id="q-lan-pinmac"><label for="q-lan-pinmac">Pin LAN port name to hardware MAC (<span class="q-mono" id="q-lan-pinmac-lbl">auto</span>)</label></div>' +
      '      </div>' +
      '      <div class="field" style="margin-bottom:0;">' +
      '        <div class="ui toggle checkbox" id="q-lan-radvd-chk"><input type="checkbox" id="q-lan-radvd"><label for="q-lan-radvd">Enable IPv6 Router Advertisements (SLAAC via <code>radvd</code>)</label></div>' +
      '      </div>' +
      '      <p class="q-field-hint" style="margin-top:10px;">Selecting the current WAN port automatically swaps LAN &amp; WAN roles. AdGuardHome DNS/DHCP, Dropbear SSH, and nftables sync atomically (60s auto-rollback).</p>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-lan-save-btn">Stage LAN Settings</button>' +
      '  </div>' +
      '</div>' +

      // Configure WAN Modal (Orthogonal Protocol + 802.1Q VLAN + Static IP / DHCP / PPPoE + Custom DNS)
      '<div class="ui small modal" id="q-wan-modal" role="dialog" aria-labelledby="q-wan-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-wan-title"><i data-lucide="globe" class="q-icon q-text-accent"></i><span>Configure WAN Uplink</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-wan-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field"><label>WAN Protocol</label>' +
      '          <div class="ui fluid selection dropdown" id="q-wan-proto-dd" data-q-manual-init>' +
      '            <input type="hidden" id="q-wan-proto" value="dhcp"><i class="dropdown icon"></i><div class="text">DHCP Client (IPoE)</div>' +
      '            <div class="menu">' +
      '              <div class="item" data-value="dhcp">DHCP Client (Automatic IP / IPoE)</div>' +
      '              <div class="item" data-value="static">Static IPv4 Address</div>' +
      '              <div class="item" data-value="pppoe">PPPoE Session (DSL / Fiber ONT)</div>' +
      '            </div>' +
      '          </div>' +
      '        </div>' +
      '        <div class="field required"><label>Physical WAN Port</label>' +
      '          <div class="ui fluid search selection dropdown" id="q-wan-dev-dd" data-q-manual-init><input type="hidden" id="q-wan-dev" value="eth1"><i class="dropdown icon"></i><div class="text">eth1</div><div class="menu"></div></div>' +
      '        </div>' +
      '      </div>' +

      '      <div class="two fields" style="align-items:center;">' +
      '        <div class="field" style="margin-bottom:0;"><div class="ui toggle checkbox" id="q-wan-vlan-chk"><input type="checkbox" id="q-wan-vlan-en"><label for="q-wan-vlan-en">Enable 802.1Q VLAN Tagging</label></div></div>' +
      '        <div class="field required" id="q-wan-vlan-wrap" hidden><label for="q-wan-vlan">802.1Q VLAN ID (e.g. 35)</label><input id="q-wan-vlan" type="number" class="q-mono" min="1" max="4094" value="35"><span class="q-field-error" id="q-wan-vlan-err" hidden>Enter a VLAN tag between 1 and 4094.</span></div>' +
      '      </div>' +

      '      <div id="q-wan-static-wrap" hidden style="margin-bottom:var(--q-space-3);">' +
      '        <div class="three fields">' +
      '          <div class="field required" id="q-wan-stip-field"><label for="q-wan-stip">WAN IPv4 Address</label><input id="q-wan-stip" type="text" class="q-mono" placeholder="203.0.113.10"><span class="q-field-error" id="q-wan-stip-err" hidden>Invalid IPv4.</span></div>' +
      '          <div class="field required" id="q-wan-stmask-field"><label for="q-wan-stmask">Subnet Mask</label><input id="q-wan-stmask" type="text" class="q-mono" value="255.255.255.0"><span class="q-field-error" id="q-wan-stmask-err" hidden>Invalid mask.</span></div>' +
      '          <div class="field required" id="q-wan-stgw-field"><label for="q-wan-stgw">Default Gateway</label><input id="q-wan-stgw" type="text" class="q-mono" placeholder="203.0.113.1"><span class="q-field-error" id="q-wan-stgw-err" hidden>Invalid gateway.</span></div>' +
      '        </div>' +
      '      </div>' +

      '      <div id="q-wan-pppoe-wrap" hidden style="margin-bottom:var(--q-space-3);">' +
      '        <div class="two fields">' +
      '          <div class="field required" id="q-wan-user-field"><label for="q-wan-user">PPPoE Username</label><input id="q-wan-user" type="text" class="q-mono" placeholder="user@isp"><span class="q-field-error" id="q-wan-user-err" hidden>PPPoE username is required.</span></div>' +
      '          <div class="field" id="q-wan-pass-field"><label for="q-wan-pass">PPPoE Password</label><input id="q-wan-pass" type="password" autocomplete="new-password" placeholder="Leave blank to keep stored password"><span class="q-field-error" id="q-wan-pass-err" hidden>PPPoE password is required for initial PPPoE setup.</span></div>' +
      '        </div>' +
      '      </div>' +

      '      <div class="two fields">' +
      '        <div class="field required" id="q-wan-mtu-field"><label for="q-wan-mtu">MTU (576 – 1508)</label><input id="q-wan-mtu" type="number" class="q-mono" min="576" max="1508" value="1500"><span class="q-field-error" id="q-wan-mtu-err" hidden>MTU must be between 576 and 1508.</span></div>' +
      '        <div class="field" id="q-wan-mac-field"><label for="q-wan-mac">MAC Address Clone (Optional)</label><input id="q-wan-mac" type="text" class="q-mono" placeholder="AA:BB:CC:DD:EE:FF"><span class="q-field-error" id="q-wan-mac-err" hidden>Enter a valid MAC (AA:BB:CC:DD:EE:FF) or leave blank.</span></div>' +
      '      </div>' +

      '      <div class="field">' +
      '        <div class="ui toggle checkbox" id="q-wan-peerdns-chk"><input type="checkbox" id="q-wan-peerdns" checked><label for="q-wan-peerdns">Use DNS servers advertised by ISP peer (<code>peerdns</code>)</label></div>' +
      '      </div>' +
      '      <div class="field" id="q-wan-dns-wrap" hidden>' +
      '        <label for="q-wan-dns">Custom WAN DNS Servers (comma-separated IPv4/IPv6)</label>' +
      '        <input id="q-wan-dns" type="text" class="q-mono" placeholder="1.1.1.1, 1.0.0.1">' +
      '        <span class="q-field-error" id="q-wan-dns-err" hidden>Enter at least one valid DNS IP when peerdns is disabled.</span>' +
      '      </div>' +

      '      <div class="two fields" style="margin-bottom:0;">' +
      '        <div class="field"><div class="ui toggle checkbox" id="q-wan-pinmac-chk"><input type="checkbox" id="q-wan-pinmac"><label for="q-wan-pinmac">Pin WAN port to MAC (<span class="q-mono" id="q-wan-pinmac-lbl">auto</span>)</label></div></div>' +
      '        <div class="field"><div class="ui toggle checkbox" id="q-wan-v6pd-chk"><input type="checkbox" id="q-wan-v6pd"><label for="q-wan-v6pd">Enable DHCPv6-PD to LAN</label></div></div>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-wan-save-btn">Stage WAN Settings</button>' +
      '  </div>' +
      '</div>' +

      // Swap LAN <-> WAN Confirmation Modal
      '<div class="ui tiny modal" id="q-swap-modal" role="dialog" aria-labelledby="q-swap-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-swap-title"><i data-lucide="arrow-left-right" class="q-icon q-text-accent"></i><span>Swap LAN &amp; WAN Physical Ports</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <p style="margin-top:0;">This atomically exchanges the physical ports assigned to <strong>LAN</strong> and <strong>WAN</strong> (for example, promoting a 2.5GbE USB/PCIe NIC to LAN and moving WAN to built-in <code>eth0</code>):</p>' +
      '    <div class="q-kv-list" id="q-swap-preview" style="margin:12px 0;"></div>' +
      '    <p class="q-field-hint" style="margin-bottom:0;">Protected by the 60-second auto-rollback timer: move your LAN cable to the new LAN port and click <strong>Keep Changes</strong> in the banner within 60 seconds.</p>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-swap-confirm-btn">Swap Roles Now</button>' +
      '  </div>' +
      '</div>' +

      // Custom Interface Label Modal
      '<div class="ui tiny modal" id="q-label-modal" role="dialog" aria-labelledby="q-label-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-label-title"><i data-lucide="tag" class="q-icon q-text-accent"></i><span>Interface Label (<span class="q-mono" id="q-label-dev-lbl"></span>)</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-label-form" novalidate>' +
      '      <div class="field" style="margin-bottom:0;">' +
      '        <label for="q-label-input">Custom Description / Label</label>' +
      '        <input id="q-label-input" type="text" maxlength="48" placeholder="e.g. TurkNet Fiber ONT, 2.5G Switch...">' +
      '        <span class="q-field-hint">Leave blank to restore the default role label.</span>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-label-save-btn">Save Label</button>' +
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
      '    <span class="q-modal-header-title" id="q-ifping-title"><i data-lucide="terminal" class="q-icon q-text-accent"></i><span>Live ICMP Ping Probe <span class="q-mono" id="q-ifping-dev-lbl"></span></span></span>' +
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

    var lanSummary = state.lanConfig
      ? (state.lanConfig.ip + ' / ' + state.lanConfig.netmask + ' · MTU ' + (state.lanConfig.mtu || 1500))
      : '192.168.10.1 / 255.255.255.0';
    var wanHasVlan = state.wanConfig && (state.wanConfig.vlanEnabled || state.wanConfig.mode === 'ont_vlan');
    var wanProtoLbl = state.wanConfig
      ? ((state.wanConfig.mode === 'ont_vlan' ? 'PPPOE' : state.wanConfig.mode.toUpperCase()) + (wanHasVlan ? ' · VLAN ' + state.wanConfig.vlanId : '') + ' · MTU ' + state.wanConfig.mtu)
      : 'DHCP · MTU 1500';
    state.$root.find('#q-if-lan-summary').text(lanIf + ' · ' + lanSummary);
    state.$root.find('#q-if-wan-summary').text(wanIf + ' · ' + wanProtoLbl);

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
          var isSpare = it.zone === 'unassigned' && isPhys;
          var canToggleLink = it.device !== lanIf;
          var drvMeta = it.driver ? (' · ' + it.driver) : '';
          return (
            '<div class="q-card" data-dev="' + esc(it.device) + '">' +
            '  <div class="q-iface-card-top">' +
            '    <div style="display:flex;align-items:center;gap:8px;"><span class="q-status-dot ' + (isUp ? 'is-success' : 'is-danger') + '"></span><strong class="q-mono" style="font-size:15px;">' + esc(it.device) + '</strong> <span class="ui label ' + fmt.zoneBadgeClass(it.zone) + ' q-badge-square q-mono">' + esc(fmt.zoneLabel(it.zone)) + '</span></div>' +
            '    <span class="ui label ' + (isUp ? 'q-status-success' : 'q-status-danger') + '">' + (isUp ? 'UP' : 'DOWN') + '</span>' +
            '  </div>' +
            '  <div class="q-kv-list" style="margin:12px 0;">' +
            '    <div class="q-kv-row"><span class="q-kv-label">Label / Driver</span><span class="q-kv-value">' + esc(it.label + drvMeta) + '</span></div>' +
            '    <div class="q-kv-row"><span class="q-kv-label">Mode</span><span class="q-kv-value q-mono">' + esc(it.mode) + '</span></div>' +
            '    <div class="q-kv-row"><span class="q-kv-label">IPv4</span><span class="q-kv-value q-mono">' + esc(it.ipv4) + '</span></div>' +
            '    <div class="q-kv-row"><span class="q-kv-label">Link / MTU</span><span class="q-kv-value q-mono">' + esc(it.speed) + ' · ' + it.mtu + '</span></div>' +
            '    <div class="q-kv-row"><span class="q-kv-label">Live Rate</span><span class="q-kv-value q-mono" data-if-rate>↓ ' + fmt.mbps(it.rxMbps) + ' · ↑ ' + fmt.mbps(it.txMbps) + '</span></div>' +
            '  </div>' +
            '  <div style="display:flex;gap:6px;flex-wrap:wrap;">' +
            (it.device === lanIf ? '<button type="button" class="ui mini primary button q-open-lan-btn">Edit LAN</button>' : '') +
            (it.device === wanIf || it.device === 'ppp0' ? '<button type="button" class="ui mini primary button q-open-wan-btn">Edit WAN</button>' : '') +
            (isSpare ? '<button type="button" class="ui mini primary button q-assign-wan-btn" data-dev="' + esc(it.device) + '">Use as WAN</button><button type="button" class="ui mini secondary button q-assign-lan-btn" data-dev="' + esc(it.device) + '">Use as LAN</button>' : '') +
            (it.type === 'wireguard' ? '<a href="#/security/vpn" class="ui mini secondary button">Configure VPN</a>' : '') +
            (isPhys ? '<button type="button" class="ui mini secondary button q-open-eth-btn" data-dev="' + esc(it.device) + '">Ethtool</button>' : '') +
            '<button type="button" class="ui mini secondary button q-open-label-btn" data-dev="' + esc(it.device) + '" data-lbl="' + esc(it.customLabel || '') + '">Label</button>' +
            (canToggleLink ? '<button type="button" class="ui mini secondary button q-toggle-link-btn" data-dev="' + esc(it.device) + '" data-up="' + (it.adminUp !== false ? '1' : '0') + '">' + (it.adminUp !== false ? 'Bring Down' : 'Bring Up') + '</button>' : '') +
            '<button type="button" class="ui mini secondary button q-open-ping-btn" data-dev="' + esc(it.device) + '">Ping</button>' +
            '  </div>' +
            '</div>'
          );
        })
        .join('');
      $host.html('<div class="q-iface-card-grid">' + cards + '</div>');
      if (Hive.icons) Hive.icons.render($host[0]);
      return;
    }

    var rows = items
      .map(function (it) {
        var isUp = it.status === 'up';
        var isPhys = it.type === 'physical';
        var isSpare = it.zone === 'unassigned' && isPhys;
        var canToggleLink = it.device !== lanIf;
        var subMeta = esc(it.label) + (it.driver ? ' · <span class="q-mono">' + esc(it.driver) + '</span>' : '') + ' · ' + esc(it.mac);
        return (
          '<tr data-dev="' + esc(it.device) + '">' +
          '  <td><div style="display:flex;align-items:center;gap:8px;"><span class="q-status-dot ' + (isUp ? 'is-success' : 'is-danger') + '"></span><div><strong class="q-mono">' + esc(it.device) + '</strong><span class="q-rule-desc">' + subMeta + '</span></div></div></td>' +
          '  <td><span class="ui label ' + fmt.zoneBadgeClass(it.zone) + ' q-badge-square q-mono">' + esc(fmt.zoneLabel(it.zone)) + '</span></td>' +
          '  <td class="q-mono">' + esc(it.mode) + '</td>' +
          '  <td class="q-mono"><strong>' + esc(it.ipv4) + '</strong><span class="q-rule-desc">' + esc(it.ipv6 !== '—' ? it.ipv6 : (it.gateway !== '—' ? 'GW ' + it.gateway : '')) + '</span></td>' +
          '  <td class="q-mono">' + esc(it.speed) + '<span class="q-rule-desc">MTU ' + it.mtu + '</span></td>' +
          '  <td class="q-mono" data-if-rate>↓ ' + fmt.mbps(it.rxMbps) + ' / ↑ ' + fmt.mbps(it.txMbps) + '<span class="q-rule-desc">Total ↓' + fmt.bytesGb(it.rxTotalGb) + ' · ↑' + fmt.bytesGb(it.txTotalGb) + '</span></td>' +
          '  <td><span class="ui label ' + (isUp ? 'q-status-success' : 'q-status-danger') + '">' + (isUp ? 'UP' : 'DOWN') + '</span></td>' +
          '  <td><div class="q-row-actions">' +
          (it.device === lanIf ? '<button type="button" class="ui mini icon button q-btn-ghost q-open-lan-btn" title="Configure LAN" aria-label="Configure LAN (' + esc(it.device) + ')"><i data-lucide="sliders-horizontal" class="q-icon q-icon-sm"></i></button>' : '') +
          (it.device === wanIf || it.device === 'ppp0' ? '<button type="button" class="ui mini icon button q-btn-ghost q-open-wan-btn" title="Configure WAN" aria-label="Configure WAN (' + esc(it.device) + ')"><i data-lucide="globe" class="q-icon q-icon-sm"></i></button>' : '') +
          (isSpare ? '<button type="button" class="ui mini icon button q-btn-ghost q-assign-wan-btn" data-dev="' + esc(it.device) + '" title="Assign as WAN" aria-label="Assign ' + esc(it.device) + ' as WAN"><i data-lucide="globe" class="q-icon q-icon-sm"></i></button><button type="button" class="ui mini icon button q-btn-ghost q-assign-lan-btn" data-dev="' + esc(it.device) + '" title="Assign as LAN" aria-label="Assign ' + esc(it.device) + ' as LAN"><i data-lucide="network" class="q-icon q-icon-sm"></i></button>' : '') +
          (it.type === 'wireguard' ? '<a href="#/security/vpn" class="ui mini icon button q-btn-ghost" title="Configure WireGuard" aria-label="Configure WireGuard (' + esc(it.device) + ')"><i data-lucide="lock-keyhole" class="q-icon q-icon-sm"></i></a>' : '') +
          (isPhys ? '<button type="button" class="ui mini icon button q-btn-ghost q-open-eth-btn" data-dev="' + esc(it.device) + '" title="Hardware & Offloads (ethtool)" aria-label="Hardware and offloads for ' + esc(it.device) + '"><i data-lucide="cpu" class="q-icon q-icon-sm"></i></button>' : '') +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-open-label-btn" data-dev="' + esc(it.device) + '" data-lbl="' + esc(it.customLabel || '') + '" title="Set custom label" aria-label="Set custom label for ' + esc(it.device) + '"><i data-lucide="tag" class="q-icon q-icon-sm"></i></button>' +
          (canToggleLink ? '<button type="button" class="ui mini icon button q-btn-ghost q-toggle-link-btn" data-dev="' + esc(it.device) + '" data-up="' + (it.adminUp !== false ? '1' : '0') + '" title="' + (it.adminUp !== false ? 'Bring interface down' : 'Bring interface up') + '" aria-label="' + (it.adminUp !== false ? 'Bring down ' : 'Bring up ') + esc(it.device) + '"><i data-lucide="power" class="q-icon q-icon-sm"></i></button>' : '') +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-open-ping-btn" data-dev="' + esc(it.device) + '" title="Ping probe" aria-label="Ping probe from ' + esc(it.device) + '"><i data-lucide="terminal" class="q-icon q-icon-sm"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');

    $host.html(
      '<div class="q-table-wrap">' +
      '  <table class="ui selectable striped table">' +
      '    <thead><tr><th>Interface</th><th>Zone</th><th>Mode</th><th>IPv4 / IPv6</th><th>Link &amp; MTU</th><th>Throughput</th><th>State</th><th style="width:168px;">Actions</th></tr></thead>' +
      '    <tbody>' + rows + '</tbody>' +
      '  </table>' +
      '</div>'
    );
    if (Hive.icons) Hive.icons.render($host[0]);
  }

  function updateLiveRatesInPlace() {
    if (!state.$root || !Hive.store) return;
    var fmt = Hive.format;
    var liveIfs = Hive.store.getState().interfaces || [];
    state.interfaces = liveIfs.slice();
    var $host = state.$root.find('#q-if-view-host');
    liveIfs.forEach(function (it) {
      var $row = $host.find('[data-dev="' + it.device + '"]');
      if (!$row.length) return;
      var $rate = $row.find('[data-if-rate]');
      if (!$rate.length) return;
      if (state.viewMode === 'cards') {
        $rate.text('↓ ' + fmt.mbps(it.rxMbps) + ' · ↑ ' + fmt.mbps(it.txMbps));
      } else {
        $rate.html('↓ ' + fmt.mbps(it.rxMbps) + ' / ↑ ' + fmt.mbps(it.txMbps) + '<span class="q-rule-desc">Total ↓' + fmt.bytesGb(it.rxTotalGb) + ' · ↑' + fmt.bytesGb(it.txTotalGb) + '</span>');
      }
    });
  }

  function updateLanPinMacHint(dev) {
    var mac = findDeviceMac(dev);
    $('#q-lan-pinmac-lbl').text(mac || 'live MAC');
  }

  function updateWanPinMacHint(dev) {
    var mac = findDeviceMac(dev);
    $('#q-wan-pinmac-lbl').text(mac || 'live MAC');
  }

  function openLanModal(overrideDev) {
    var lan = state.lanConfig || { interface: 'eth0', ip: '192.168.10.1', netmask: '255.255.255.0', mtu: 1500, pinMac: '' };
    var wanIf = (state.wanConfig && state.wanConfig.interface) || 'eth1';
    var v6 = state.ipv6Config || { radvdEnabled: false };
    var selectedDev = typeof overrideDev === 'string' && overrideDev ? overrideDev : (lan.interface || 'eth0');

    var $dd = $('#q-lan-dev-dd');
    $dd.find('.menu').html(buildPhysicalDropdownMenuHtml(wanIf, 'WAN'));
    $dd.dropdown({ onChange: updateLanPinMacHint }).dropdown('refresh').dropdown('set selected', selectedDev);

    $('#q-lan-ip').val(lan.ip);
    $('#q-lan-mask').val(lan.netmask);
    $('#q-lan-mtu').val(lan.mtu || 1500);
    updateLanPinMacHint(selectedDev);
    $('#q-lan-pinmac-chk').checkbox(lan.pinMac ? 'set checked' : 'set unchecked');
    $('#q-lan-radvd-chk').checkbox(v6.radvdEnabled ? 'set checked' : 'set unchecked');
    $('#q-lan-form .field.error').removeClass('error');
    $('#q-lan-form .q-field-error').attr('hidden', true);
    Hive.ui.openModal('#q-lan-modal');
  }

  function saveLanModal() {
    var dev = $.trim($('#q-lan-dev').val()) || 'eth0';
    var ip = $.trim($('#q-lan-ip').val());
    var mask = $.trim($('#q-lan-mask').val());
    var mtu = Number($('#q-lan-mtu').val() || 1500);
    var pinChecked = $('#q-lan-pinmac').is(':checked');
    var radvd = $('#q-lan-radvd').is(':checked');

    var ok = true;
    $('#q-lan-form .field.error').removeClass('error');
    $('#q-lan-form .q-field-error').attr('hidden', true);

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
    if (!Number.isInteger(mtu) || mtu < 576 || mtu > 9000) {
      $('#q-lan-mtu-field').addClass('error');
      $('#q-lan-mtu-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    var pinMac = '';
    if (pinChecked) {
      pinMac = findDeviceMac(dev) || (state.lanConfig && state.lanConfig.pinMac) || '';
    }

    Promise.all([
      Hive.services.interfaces.stageLan({ interface: dev, ip: ip, netmask: mask, mtu: mtu, pinMac: pinMac }),
      Hive.services.interfaces.stageIpv6({ radvdEnabled: radvd, ipv6Pd: state.ipv6Config ? state.ipv6Config.ipv6Pd : false })
    ]).then(function () {
      $('#q-lan-modal').modal('hide');
      Hive.ui.notify({ title: 'LAN Settings Staged', message: 'Click Apply in the bottom dock to commit LAN changes.', type: 'info' });
    });
  }

  function syncWanProtoAndVlanFields() {
    var proto = $('#q-wan-proto').val() || 'dhcp';
    var vlanEn = $('#q-wan-vlan-en').is(':checked');
    var peerDns = $('#q-wan-peerdns').is(':checked');

    if (vlanEn) $('#q-wan-vlan-wrap').removeAttr('hidden');
    else $('#q-wan-vlan-wrap').attr('hidden', true);

    if (proto === 'static') $('#q-wan-static-wrap').removeAttr('hidden');
    else $('#q-wan-static-wrap').attr('hidden', true);

    if (proto === 'pppoe') $('#q-wan-pppoe-wrap').removeAttr('hidden');
    else $('#q-wan-pppoe-wrap').attr('hidden', true);

    if (!peerDns) $('#q-wan-dns-wrap').removeAttr('hidden');
    else $('#q-wan-dns-wrap').attr('hidden', true);

    var curMtu = Number($('#q-wan-mtu').val());
    if (proto === 'pppoe' && curMtu === 1500) $('#q-wan-mtu').val(1492);
    if (proto !== 'pppoe' && curMtu === 1492) $('#q-wan-mtu').val(1500);
  }

  function openWanModal(overrideDev) {
    var wan = state.wanConfig || {
      mode: 'dhcp', interface: 'eth1', vlanEnabled: false, vlanId: 35,
      staticIp: '', staticNetmask: '255.255.255.0', staticGateway: '',
      pppoeUser: '', peerDns: true, dnsServers: [], macClone: '', pinMac: '', mtu: 1500, ipv6Pd: false
    };
    var lanIf = (state.lanConfig && state.lanConfig.interface) || 'eth0';
    var selectedDev = typeof overrideDev === 'string' && overrideDev ? overrideDev : (wan.interface || 'eth1');
    var proto = wan.mode === 'ont_vlan' ? 'pppoe' : (wan.mode || 'dhcp');
    var vlanEn = Boolean(wan.vlanEnabled || wan.mode === 'ont_vlan');
    var peerDns = wan.peerDns !== false;

    var $devDd = $('#q-wan-dev-dd');
    $devDd.find('.menu').html(buildPhysicalDropdownMenuHtml(lanIf, 'LAN'));
    $devDd.dropdown({ allowAdditions: true, onChange: updateWanPinMacHint }).dropdown('refresh').dropdown('set selected', selectedDev);

    $('#q-wan-proto-dd').dropdown({ onChange: syncWanProtoAndVlanFields }).dropdown('set selected', proto);
    $('#q-wan-vlan-chk').checkbox(vlanEn ? 'set checked' : 'set unchecked');
    $('#q-wan-vlan').val(wan.vlanId || 35);
    $('#q-wan-stip').val(wan.staticIp || '');
    $('#q-wan-stmask').val(wan.staticNetmask || '255.255.255.0');
    $('#q-wan-stgw').val(wan.staticGateway || '');
    $('#q-wan-user').val(wan.pppoeUser || '');
    $('#q-wan-pass').val('');
    $('#q-wan-mtu').val(wan.mtu || (proto === 'pppoe' ? 1492 : 1500));
    $('#q-wan-mac').val(wan.macClone || '');
    $('#q-wan-peerdns-chk').checkbox(peerDns ? 'set checked' : 'set unchecked');
    $('#q-wan-dns').val(Array.isArray(wan.dnsServers) ? wan.dnsServers.join(', ') : '');
    updateWanPinMacHint(selectedDev);
    $('#q-wan-pinmac-chk').checkbox(wan.pinMac ? 'set checked' : 'set unchecked');
    $('#q-wan-v6pd-chk').checkbox(wan.ipv6Pd ? 'set checked' : 'set unchecked');

    syncWanProtoAndVlanFields();
    $('#q-wan-form .field.error').removeClass('error');
    $('#q-wan-form .q-field-error').attr('hidden', true);
    Hive.ui.openModal('#q-wan-modal');
  }

  function saveWanModal() {
    var proto = $('#q-wan-proto').val() || 'dhcp';
    var dev = $.trim($('#q-wan-dev').val()) || 'eth1';
    var vlanEn = $('#q-wan-vlan-en').is(':checked');
    var vlanId = Number($('#q-wan-vlan').val() || 35);
    var stIp = $.trim($('#q-wan-stip').val());
    var stMask = $.trim($('#q-wan-stmask').val());
    var stGw = $.trim($('#q-wan-stgw').val());
    var pppUser = $.trim($('#q-wan-user').val());
    var pppPass = $('#q-wan-pass').val();
    var mtu = Number($('#q-wan-mtu').val() || 1500);
    var mac = $.trim($('#q-wan-mac').val()).toUpperCase();
    var peerDns = $('#q-wan-peerdns').is(':checked');
    var dnsRaw = $.trim($('#q-wan-dns').val());
    var pinChecked = $('#q-wan-pinmac').is(':checked');
    var v6pd = $('#q-wan-v6pd').is(':checked');

    $('#q-wan-form .field.error').removeClass('error');
    $('#q-wan-form .q-field-error').attr('hidden', true);
    var ok = true;

    if (vlanEn && (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094)) {
      $('#q-wan-vlan-wrap').addClass('error');
      $('#q-wan-vlan-err').removeAttr('hidden');
      ok = false;
    }
    if (proto === 'static') {
      if (!Hive.validators.isIPv4(stIp)) {
        $('#q-wan-stip-field').addClass('error');
        $('#q-wan-stip-err').removeAttr('hidden');
        ok = false;
      }
      if (!Hive.validators.isIPv4(stMask)) {
        $('#q-wan-stmask-field').addClass('error');
        $('#q-wan-stmask-err').removeAttr('hidden');
        ok = false;
      }
      if (!Hive.validators.isIPv4(stGw)) {
        $('#q-wan-stgw-field').addClass('error');
        $('#q-wan-stgw-err').removeAttr('hidden');
        ok = false;
      }
    }
    if (proto === 'pppoe') {
      if (!pppUser) {
        $('#q-wan-user-field').addClass('error');
        $('#q-wan-user-err').removeAttr('hidden');
        ok = false;
      }
      var committedWan = (Hive.store && Hive.store.getCommittedState().wanConfig) || {};
      var hasStoredPass =
        Boolean(state.wanConfig && state.wanConfig.pppoePassword) ||
        Boolean(committedWan.pppoeUser && (committedWan.mode === 'pppoe' || committedWan.mode === 'ont_vlan'));
      if (!pppPass && !hasStoredPass) {
        $('#q-wan-pass-field').addClass('error');
        $('#q-wan-pass-err').removeAttr('hidden');
        ok = false;
      }
    }
    if (!Number.isInteger(mtu) || mtu < 576 || mtu > 1508) {
      $('#q-wan-mtu-field').addClass('error');
      $('#q-wan-mtu-err').removeAttr('hidden');
      ok = false;
    }
    if (mac && !Hive.validators.isMAC(mac)) {
      $('#q-wan-mac-field').addClass('error');
      $('#q-wan-mac-err').removeAttr('hidden');
      ok = false;
    }

    var dnsList = dnsRaw
      ? dnsRaw.split(',').map(function (s) { return $.trim(s); }).filter(Boolean)
      : [];
    if (!peerDns) {
      var badDns = !dnsList.length || dnsList.some(function (ip) { return !Hive.validators.isIP(ip); });
      if (badDns) {
        $('#q-wan-dns-wrap').addClass('error');
        $('#q-wan-dns-err').removeAttr('hidden');
        ok = false;
      }
    }
    if (!ok) return;

    var mode = proto === 'pppoe' && vlanEn ? 'ont_vlan' : proto;
    var pinMac = '';
    if (pinChecked) {
      pinMac = findDeviceMac(dev) || (state.wanConfig && state.wanConfig.pinMac) || '';
    }

    var patch = {
      mode: mode,
      interface: dev,
      vlanEnabled: vlanEn,
      vlanId: vlanId,
      staticIp: stIp,
      staticNetmask: stMask,
      staticGateway: stGw,
      pppoeUser: pppUser,
      peerDns: peerDns,
      dnsServers: dnsList,
      macClone: mac,
      pinMac: pinMac,
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

  function openSwapModal() {
    var esc = Hive.format.escapeHtml;
    var lanIf = (state.lanConfig && state.lanConfig.interface) || 'eth0';
    var wanIf = (state.wanConfig && state.wanConfig.interface) || 'eth1';
    $('#q-swap-preview').html(
      '<div class="q-kv-row"><span class="q-kv-label">New LAN Interface</span><span class="q-kv-value q-mono">' + esc(wanIf) + ' (' + esc((state.lanConfig && state.lanConfig.ip) || '192.168.10.1') + ')</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">New WAN Interface</span><span class="q-kv-value q-mono">' + esc(lanIf) + ' (' + esc(((state.wanConfig && state.wanConfig.mode) || 'dhcp').toUpperCase()) + ')</span></div>'
    );
    Hive.ui.openModal('#q-swap-modal');
  }

  function confirmSwapRoles() {
    var $btn = $('#q-swap-confirm-btn').addClass('loading disabled');
    Hive.services.interfaces
      .swapRoles()
      .then(function () {
        $('#q-swap-modal').modal('hide');
        Hive.ui.notify({
          title: 'LAN & WAN Swapped',
          message: 'Confirm within 60 seconds in the rollback banner to keep the new port assignment.',
          type: 'warning'
        });
        loadAndRender();
      })
      .catch(function (err) {
        Hive.ui.notify({ title: 'Role Swap Failed', message: err.message, type: 'error' });
      })
      .then(function () {
        $btn.removeClass('loading disabled');
      });
  }

  function openLabelModal(dev, currentLbl) {
    state.labelIface = dev;
    $('#q-label-dev-lbl').text(dev);
    $('#q-label-input').val(currentLbl || '');
    Hive.ui.openModal('#q-label-modal');
  }

  function saveLabelModal() {
    var lbl = $.trim($('#q-label-input').val());
    var $btn = $('#q-label-save-btn').addClass('loading disabled');
    Hive.services.interfaces
      .setLabel(state.labelIface, lbl)
      .then(function () {
        $('#q-label-modal').modal('hide');
        Hive.ui.notify({ title: 'Label Updated', message: 'Saved interface label for ' + state.labelIface + '.', type: 'success' });
        loadAndRender();
      })
      .catch(function (err) {
        Hive.ui.notify({ title: 'Label Error', message: err.message, type: 'error' });
      })
      .then(function () {
        $btn.removeClass('loading disabled');
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
        '    <p class="q-page-subtitle">Dynamic LAN/WAN port assignment, role swap, 802.1Q VLAN tagging, DHCP / Static / PPPoE WAN, IPv6, and NIC offloads.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <button type="button" class="ui secondary button" id="q-wan-reconnect-btn"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Reconnect WAN</span></button>' +
        '    <button type="button" class="ui secondary button" id="q-swap-roles-btn"><i data-lucide="arrow-left-right" class="q-icon q-icon-sm"></i><span>Swap LAN ↔ WAN</span></button>' +
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
        '    <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-if-search" placeholder="Search device, driver, IP, MAC..."></div>' +
        '    <div class="ui selection dropdown" id="q-if-zone-filter" data-q-manual-init style="min-width:150px;"><input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Zones</div><div class="menu"><div class="item" data-value="all">All Zones</div><div class="item" data-value="lan">LAN</div><div class="item" data-value="wan">WAN</div><div class="item" data-value="vpn">WireGuard VPN</div><div class="item" data-value="unassigned">Spare / Unassigned</div></div></div>' +
        '  </div>' +
        '  <div class="q-toolbar-right">' +
        '    <span class="ui label q-mono" id="q-if-count"></span>' +
        '    <div class="ui mini icon buttons" id="q-if-view-btns">' +
        '      <button type="button" class="ui button active" data-view="table" title="Table view" aria-label="Table view"><i data-lucide="list" class="q-icon q-icon-sm"></i></button>' +
        '      <button type="button" class="ui button" data-view="cards" title="Card view" aria-label="Card view"><i data-lucide="layout-grid" class="q-icon q-icon-sm"></i></button>' +
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

    $container.on('click.qIfaces', '.q-open-lan-btn', function () { openLanModal(''); });
    $container.on('click.qIfaces', '.q-open-wan-btn', function () { openWanModal(''); });
    $container.on('click.qIfaces', '.q-assign-lan-btn', function () { openLanModal($(this).attr('data-dev')); });
    $container.on('click.qIfaces', '.q-assign-wan-btn', function () { openWanModal($(this).attr('data-dev')); });
    $container.on('click.qIfaces', '#q-swap-roles-btn', openSwapModal);

    $container.on('click.qIfaces', '.q-open-eth-btn', function () {
      openEthtoolModal($(this).attr('data-dev'));
    });

    $container.on('click.qIfaces', '.q-open-label-btn', function () {
      openLabelModal($(this).attr('data-dev'), $(this).attr('data-lbl'));
    });

    $container.on('click.qIfaces', '.q-toggle-link-btn', function () {
      var $btn = $(this).addClass('loading disabled');
      var dev = $btn.attr('data-dev');
      var curUp = $btn.attr('data-up') === '1';
      Hive.services.interfaces
        .setLinkState(dev, !curUp)
        .then(function () {
          Hive.ui.notify({
            title: 'Interface ' + (!curUp ? 'Brought Up' : 'Brought Down'),
            message: dev + ' administrative state set to ' + (!curUp ? 'UP' : 'DOWN') + '.',
            type: 'info'
          });
          loadAndRender();
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Link State Error', message: err.message, type: 'error' });
        })
        .then(function () {
          $btn.removeClass('loading disabled');
        });
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
      var dev = $(this).attr('data-dev') || '';
      var ifaceObj = (state.interfaces || []).find(function (i) { return i.device === dev; });
      $('#q-ifping-dev-lbl').text(dev ? '(' + dev + ')' : '');
      if (ifaceObj && ifaceObj.gateway && ifaceObj.gateway !== '—') {
        $('#q-ifping-host').val(ifaceObj.gateway);
      } else if (!$('#q-ifping-host').val()) {
        $('#q-ifping-host').val('1.1.1.1');
      }
      $('#q-ifping-out').text('Ready to run ICMP ping.');
      $('#q-ifping-st').text('ready');
      Hive.ui.openModal('#q-iface-ping-modal');
    });

    $(document).on('change.qIfacesModal', '#q-eth-autoneg', function () {
      if (this.checked) $('#q-eth-manual-wrap').attr('hidden', true);
      else $('#q-eth-manual-wrap').removeAttr('hidden');
    });
    $(document).on('change.qIfacesModal', '#q-wan-vlan-en, #q-wan-peerdns', syncWanProtoAndVlanFields);

    $(document).on('click.qIfacesModal', '#q-lan-save-btn', saveLanModal);
    $(document).on('submit.qIfacesModal', '#q-lan-form', function (e) { e.preventDefault(); saveLanModal(); });
    $(document).on('click.qIfacesModal', '#q-wan-save-btn', saveWanModal);
    $(document).on('submit.qIfacesModal', '#q-wan-form', function (e) { e.preventDefault(); saveWanModal(); });
    $(document).on('click.qIfacesModal', '#q-swap-confirm-btn', confirmSwapRoles);
    $(document).on('click.qIfacesModal', '#q-label-save-btn', saveLabelModal);
    $(document).on('submit.qIfacesModal', '#q-label-form', function (e) { e.preventDefault(); saveLabelModal(); });
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
      if (reason === 'telemetry') {
        updateLiveRatesInPlace();
        return;
      }
      if (Hive.store.isRuntimeOnlyReason(reason)) return;
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
