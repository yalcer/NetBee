/* ==========================================================================
   Hive — Security Module: WireGuard VPN (#/security/vpn)
   NetBee OS WireGuard (wg0) Server Configuration, Live Keygen & Peer Profiles
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    vpn: null,
    editingPeerId: null,
    exportPeerName: 'peer',
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-wg-srv-modal, #q-wg-peer-modal, #q-wg-export-modal').modal('hide').remove();
  }

  function renderModalsHtml() {
    return (
      // WireGuard Server Settings Modal
      '<div class="ui small modal" id="q-wg-srv-modal" role="dialog" aria-labelledby="q-wg-srv-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-wg-srv-title"><i data-lucide="settings" class="q-icon q-text-accent"></i><span>WireGuard Server Configuration (wg0)</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-wg-srv-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-wgs-sub-field">' +
      '          <label for="q-wgs-subnet">Tunnel Interface CIDR</label>' +
      '          <input id="q-wgs-subnet" type="text" class="q-mono" placeholder="10.66.66.1/24">' +
      '          <span class="q-field-error" id="q-wgs-sub-err" hidden>Enter a subnet CIDR (e.g. 10.66.66.1/24, not /32).</span>' +
      '        </div>' +
      '        <div class="field required" id="q-wgs-port-field">' +
      '          <label for="q-wgs-port">UDP Listen Port</label>' +
      '          <input id="q-wgs-port" type="number" class="q-mono" min="1" max="65535" placeholder="51820">' +
      '          <span class="q-field-error" id="q-wgs-port-err" hidden>Enter a valid port 1–65535.</span>' +
      '        </div>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field" id="q-wgs-ep-field">' +
      '          <label for="q-wgs-endpoint">Public Endpoint Host / IP (For Client Profiles)</label>' +
      '          <input id="q-wgs-endpoint" type="text" class="q-mono" placeholder="vpn.example.com or 203.0.113.10">' +
      '          <span class="q-field-error" id="q-wgs-ep-err" hidden>Enter a valid hostname or public IP.</span>' +
      '        </div>' +
      '        <div class="field" id="q-wgs-dns-field">' +
      '          <label for="q-wgs-dns">Client DNS Server(s)</label>' +
      '          <input id="q-wgs-dns" type="text" class="q-mono" placeholder="192.168.10.1">' +
      '          <span class="q-field-error" id="q-wgs-dns-err" hidden>Enter valid IPv4/IPv6 DNS server address(es).</span>' +
      '        </div>' +
      '      </div>' +
      '      <div class="two fields" style="margin-bottom:0;">' +
      '        <div class="field"><div class="ui toggle checkbox" id="q-wgs-enabled-chk"><input type="checkbox" id="q-wgs-enabled"><label for="q-wgs-enabled">Enable WireGuard Interface (wg0)</label></div></div>' +
      '        <div class="field"><div class="ui toggle checkbox" id="q-wgs-fw-chk"><input type="checkbox" id="q-wgs-fw"><label for="q-wgs-fw">Open UDP port on WAN Firewall</label></div></div>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-wgs-save-btn">Stage Server Settings</button>' +
      '  </div>' +
      '</div>' +

      // Add / Edit WireGuard Peer Modal
      '<div class="ui small modal" id="q-wg-peer-modal" role="dialog" aria-labelledby="q-wg-peer-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-wg-peer-title"><i data-lucide="lock-keyhole" class="q-icon q-text-accent"></i><span id="q-wg-peer-heading">Add WireGuard Peer</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-wg-peer-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-wg-name-field">' +
      '          <label for="q-wg-name">Peer Name</label>' +
      '          <input id="q-wg-name" type="text" class="q-mono" placeholder="phone-admin">' +
      '          <span class="q-field-error" id="q-wg-name-err" hidden>Enter a valid peer name (letters, digits, hyphens).</span>' +
      '        </div>' +
      '        <div class="field required" id="q-wg-ips-field">' +
      '          <label for="q-wg-ips">Tunnel Allowed IP / CIDR</label>' +
      '          <input id="q-wg-ips" type="text" class="q-mono" value="10.66.66.2/32">' +
      '          <span class="q-field-error" id="q-wg-ips-err" hidden>Enter a valid client tunnel IP/CIDR inside the wg0 subnet.</span>' +
      '        </div>' +
      '      </div>' +
      '      <div class="field" id="q-wg-pub-field">' +
      '        <label for="q-wg-pub">Client Public Key <span class="q-text-muted">(Leave blank to auto-generate Curve25519 keypair on router)</span></label>' +
      '        <input id="q-wg-pub" type="text" class="q-mono" placeholder="Auto-generate Curve25519 keypair and export .conf">' +
      '        <span class="q-field-error" id="q-wg-pub-err" hidden>Enter a valid 44-char Base64 WireGuard public key, or leave blank.</span>' +
      '      </div>' +
      '      <div class="two fields" style="margin-bottom:0;">' +
      '        <div class="field" id="q-wg-psk-wrap"><div class="ui toggle checkbox" id="q-wg-psk-chk"><input type="checkbox" id="q-wg-psk" checked><label for="q-wg-psk">Generate PresharedKey (Post-Quantum PSK)</label></div></div>' +
      '        <div class="field" id="q-wg-enabled-wrap"><div class="ui toggle checkbox" id="q-wg-enabled-chk"><input type="checkbox" id="q-wg-enabled" checked><label for="q-wg-enabled">Peer enabled</label></div></div>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-wg-save-btn">Create Peer</button>' +
      '  </div>' +
      '</div>' +

      // Export WireGuard .conf Modal
      '<div class="ui small modal" id="q-wg-export-modal" role="dialog" aria-labelledby="q-wg-exp-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-wg-exp-title"><i data-lucide="download" class="q-icon q-text-accent"></i><span>Client Profile: <span class="q-mono" id="q-wg-exp-name"></span>.conf</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <p id="q-wg-exp-notice" class="q-text-secondary" style="margin-bottom:var(--q-space-3);"></p>' +
      '    <pre class="q-code-block" id="q-wg-exp-code"></pre>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui basic cancel button">Close</button>' +
      '    <button type="button" class="ui secondary button" id="q-wg-exp-copy"><i data-lucide="copy" class="q-icon q-icon-sm"></i><span>Copy</span></button>' +
      '    <button type="button" class="ui primary button" id="q-wg-exp-download"><i data-lucide="download" class="q-icon q-icon-sm"></i><span>Download .conf</span></button>' +
      '  </div>' +
      '</div>'
    );
  }

  function renderContent() {
    if (!state.$root || !state.vpn) return;
    var wg = state.vpn.wireguard;
    var fwCfg = state.vpn.firewallConfig || {};
    var fmt = Hive.format;
    var esc = fmt.escapeHtml;

    var peers = wg.peers || [];
    var connectedCount = peers.filter(function (p) { return p.enabled && p.status === 'connected'; }).length;

    var statusPill = wg.active
      ? '<span class="ui label q-status-success q-mono">Active</span>'
      : wg.enabled
      ? '<span class="ui label q-status-warning q-mono">Staged / Starting</span>'
      : '<span class="ui label q-badge-square q-mono">Disabled</span>';

    var fwNote = fwCfg.exposeWireguard ? '<span class="q-text-success">WAN UDP/' + wg.listenPort + ' Open</span>' : '<span class="q-text-warning">WAN Port Closed</span>';
    var pubKeyDisplay = wg.publicKey || 'Generated automatically when WireGuard is enabled';

    state.$root.find('#q-wg-hero').html(
      '<div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Tunnel Interface</span>' + statusPill + '</div><div class="q-kpi-value">' + esc(wg.iface || 'wg0') + '</div><div class="q-kpi-sub"><span class="q-mono">' + esc(wg.tunnelSubnet) + '</span><span>UDP/' + wg.listenPort + '</span></div></div>' +
      '<div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Connected Peers</span><span class="q-kpi-icon"><i data-lucide="lock-keyhole" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-wg-active-count">' + connectedCount + '/' + peers.length + '</div><div class="q-kpi-sub"><span>Recent handshakes (&lt;3m)</span>' + fwNote + '</div></div>' +
      '<div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Public Endpoint</span></div><div class="q-kpi-value" style="font-size:15px;">' + esc(wg.endpointHost || 'Not set (edit server)') + '</div><div class="q-kpi-sub"><span>Client DNS: <span class="q-mono">' + esc(wg.dns) + '</span></span></div></div>' +
      '<div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Server Public Key</span>' + (wg.publicKey ? '<button type="button" class="ui mini icon button q-btn-ghost" data-q-copy="' + esc(wg.publicKey) + '" data-q-copy-label="Server public key" title="Copy public key"><i data-lucide="copy" class="q-icon q-icon-sm"></i></button>' : '') + '</div><div class="q-mono" style="font-size:12px;word-break:break-all;color:var(--q-text-secondary);">' + esc(pubKeyDisplay) + '</div></div>'
    );

    if (!peers.length) {
      state.$root.find('#q-wg-peers-tbody').html('<tr><td colspan="7" style="text-align:center;padding:28px;color:var(--q-text-muted);">No WireGuard peers configured. Click <strong>Add WireGuard Peer</strong> to generate a client profile.</td></tr>');
      if (Hive.icons) Hive.icons.render();
      return;
    }

    var peerRows = peers
      .map(function (p) {
        var dotCls = p.status === 'connected' ? 'is-success' : p.status === 'idle' ? 'is-info' : 'is-danger';
        var stCls = p.status === 'connected' ? 'q-status-success' : p.status === 'idle' ? 'q-status-info' : '';
        var pskBadge = p.hasPsk ? ' <span class="ui mini label q-badge-square q-mono" title="PresharedKey configured">PSK</span>' : '';
        return (
          '<tr class="' + (p.enabled ? '' : 'q-rule-disabled') + '">' +
          '  <td><strong class="q-mono">' + esc(p.name) + '</strong>' + pskBadge + '<span class="q-rule-desc q-mono">' + esc(p.endpoint || 'Roaming') + '</span></td>' +
          '  <td><div class="q-key-copy-row"><span class="q-key-trunc" title="' + esc(p.publicKey) + '">' + esc(p.publicKey) + '</span><button type="button" class="ui mini icon button q-btn-ghost" data-q-copy="' + esc(p.publicKey) + '" data-q-copy-label="Peer public key" aria-label="Copy peer key"><i data-lucide="copy" class="q-icon q-icon-sm"></i></button></div></td>' +
          '  <td class="q-mono">' + esc(p.allowedIps) + '</td>' +
          '  <td class="q-mono q-text-secondary">' + esc(p.lastHandshake) + '<span class="q-rule-desc">↓ ' + fmt.bytesGb(p.rxGb) + ' · ↑ ' + fmt.bytesGb(p.txGb) + '</span></td>' +
          '  <td><span class="ui label ' + stCls + '"><span class="q-status-dot ' + dotCls + '"></span>' + esc(p.status) + '</span></td>' +
          '  <td><div class="ui fitted toggle checkbox q-wg-toggle" data-id="' + esc(p.id) + '"><input type="checkbox"' + (p.enabled ? ' checked' : '') + ' aria-label="Toggle peer ' + esc(p.name) + '"><label></label></div></td>' +
          '  <td><div class="q-row-actions">' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-wg-export-btn" data-id="' + esc(p.id) + '" title="View client .conf template"><i data-lucide="download" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-wg-edit-btn" data-id="' + esc(p.id) + '" title="Edit peer"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-wg-del-btn" data-id="' + esc(p.id) + '" title="Delete peer"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-wg-peers-tbody').html(peerRows);

    if (Hive.icons) Hive.icons.render();
    state.$root.find('#q-wg-peers-tbody .ui.checkbox').checkbox();
  }

  function nextUniquePeerIp() {
    var wg = (state.vpn && state.vpn.wireguard) || {};
    var subnet = wg.tunnelSubnet || '10.66.66.1/24';
    var baseIp = subnet.split('/')[0] || '10.66.66.1';
    var octets = baseIp.split('.');
    var prefix3 = octets.length === 4 ? (octets[0] + '.' + octets[1] + '.' + octets[2] + '.') : '10.66.66.';
    var srvHost = Number(octets[3] || 1);
    var peers = wg.peers || [];
    for (var host = 2; host < 254; host++) {
      if (host === srvHost) continue;
      var candidate = prefix3 + host;
      var taken = peers.some(function (p) {
        return String(p.allowedIps || '').indexOf(candidate + '/') !== -1 || String(p.allowedIps || '') === candidate;
      });
      if (!taken) return candidate + '/32';
    }
    return prefix3 + '250/32';
  }

  function openServerModal() {
    var wg = state.vpn.wireguard;
    var fw = state.vpn.firewallConfig || {};
    $('#q-wgs-subnet').val(wg.tunnelSubnet || '10.66.66.1/24');
    $('#q-wgs-port').val(wg.listenPort || 51820);
    $('#q-wgs-endpoint').val(wg.endpointHost || '');
    $('#q-wgs-dns').val(wg.dns || '192.168.10.1');
    $('#q-wgs-enabled-chk').checkbox(wg.enabled ? 'set checked' : 'set unchecked');
    $('#q-wgs-fw-chk').checkbox(fw.exposeWireguard ? 'set checked' : 'set unchecked');
    $('#q-wgs-sub-field, #q-wgs-port-field, #q-wgs-ep-field, #q-wgs-dns-field').removeClass('error');
    $('#q-wgs-sub-err, #q-wgs-port-err, #q-wgs-ep-err, #q-wgs-dns-err').attr('hidden', true);
    Hive.ui.openModal('#q-wg-srv-modal');
  }

  function saveServerModal() {
    var v = Hive.validators;
    var subnet = $.trim($('#q-wgs-subnet').val());
    var port = Number($('#q-wgs-port').val() || 51820);
    var endpoint = $.trim($('#q-wgs-endpoint').val());
    var dns = $.trim($('#q-wgs-dns').val());
    var enabled = $('#q-wgs-enabled').is(':checked');
    var exposeFw = $('#q-wgs-fw').is(':checked');

    var ok = true;
    $('#q-wgs-sub-field, #q-wgs-port-field, #q-wgs-ep-field, #q-wgs-dns-field').removeClass('error');
    $('#q-wgs-sub-err, #q-wgs-port-err, #q-wgs-ep-err, #q-wgs-dns-err').attr('hidden', true);

    if (!v.isCIDR(subnet) || Number(subnet.split('/')[1]) >= 32) {
      $('#q-wgs-sub-field').addClass('error');
      $('#q-wgs-sub-err').removeAttr('hidden');
      ok = false;
    }
    if (!v.isPortNumber(port)) {
      $('#q-wgs-port-field').addClass('error');
      $('#q-wgs-port-err').removeAttr('hidden');
      ok = false;
    }
    if (endpoint && !v.isHostname(endpoint) && !v.isIPv4(endpoint) && !v.isIPv6(endpoint)) {
      $('#q-wgs-ep-field').addClass('error');
      $('#q-wgs-ep-err').removeAttr('hidden');
      ok = false;
    }
    var dnsParts = dns ? dns.split(',').map(function (s) { return s.trim(); }).filter(Boolean) : [];
    if (!dnsParts.length || !dnsParts.every(function (ip) { return v.isIPv4(ip) || v.isIPv6(ip); })) {
      $('#q-wgs-dns-field').addClass('error');
      $('#q-wgs-dns-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    Hive.services.vpn
      .stageServer({
        enabled: enabled,
        tunnelSubnet: subnet,
        listenPort: port,
        endpointHost: endpoint,
        dns: dnsParts.join(', '),
        exposeWireguard: exposeFw
      })
      .then(function () {
        $('#q-wg-srv-modal').modal('hide');
        Hive.ui.notify({
          title: 'WireGuard Server Staged',
          message: 'Server configuration queued in pending changes.',
          type: 'success'
        });
      });
  }

  function openWgPeerModal(id) {
    state.editingPeerId = id || null;
    var p = id ? (state.vpn.wireguard.peers || []).find(function (x) { return x.id === id; }) : null;
    var isEdit = Boolean(p);
    $('#q-wg-peer-heading').text(isEdit ? 'Edit WireGuard Peer (' + p.name + ')' : 'Add WireGuard Peer');
    $('#q-wg-name').val(isEdit ? p.name : '');
    $('#q-wg-ips').val(isEdit ? p.allowedIps : nextUniquePeerIp());
    $('#q-wg-pub').val(isEdit ? p.publicKey : '').prop('readonly', isEdit);
    $('#q-wg-psk-wrap').toggle(!isEdit);
    $('#q-wg-psk-chk').checkbox('set checked');
    $('#q-wg-enabled-wrap').toggle(isEdit);
    $('#q-wg-enabled-chk').checkbox(!p || p.enabled ? 'set checked' : 'set unchecked');
    $('#q-wg-save-btn').text(isEdit ? 'Stage Peer Update' : 'Generate & Add Peer');

    $('#q-wg-name-field, #q-wg-pub-field, #q-wg-ips-field').removeClass('error');
    $('#q-wg-name-err, #q-wg-pub-err, #q-wg-ips-err').attr('hidden', true);
    Hive.ui.openModal('#q-wg-peer-modal');
  }

  function showConfigModal(peerName, configText, isOneTimeKey) {
    state.exportPeerName = peerName || 'wg-client';
    $('#q-wg-exp-name').text(state.exportPeerName);
    $('#q-wg-exp-notice').html(
      isOneTimeKey
        ? '<strong class="q-text-warning">Save or download this profile now:</strong> NetBee OS generated the client <code>PrivateKey</code> in memory and never stores it on disk.'
        : 'Client profile template. Because client private keys are never stored on the router, insert your client <code>PrivateKey</code> on the device.'
    );
    $('#q-wg-exp-code').text(configText);
    Hive.ui.openModal('#q-wg-export-modal');
  }

  function saveWgPeerModal() {
    var v = Hive.validators;
    var name = $.trim($('#q-wg-name').val());
    var allowedIps = $.trim($('#q-wg-ips').val());
    var publicKey = $.trim($('#q-wg-pub').val());
    var usePsk = $('#q-wg-psk').is(':checked');
    var enabled = $('#q-wg-enabled').is(':checked');

    var ok = true;
    $('#q-wg-name-field, #q-wg-pub-field, #q-wg-ips-field').removeClass('error');
    $('#q-wg-name-err, #q-wg-pub-err, #q-wg-ips-err').attr('hidden', true);

    if (!name || !/^[A-Za-z0-9._-]{1,48}$/.test(name)) {
      $('#q-wg-name-field').addClass('error');
      $('#q-wg-name-err').removeAttr('hidden');
      ok = false;
    }
    if (!v.isIPv4OrCIDR(allowedIps) && !v.isIPv6(allowedIps)) {
      $('#q-wg-ips-field').addClass('error');
      $('#q-wg-ips-err').removeAttr('hidden');
      ok = false;
    }
    if (!state.editingPeerId && publicKey !== '' && !v.isWireGuardKey(publicKey)) {
      $('#q-wg-pub-field').addClass('error');
      $('#q-wg-pub-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    if (state.editingPeerId) {
      Hive.services.vpn
        .saveWgPeer({ id: state.editingPeerId, name: name, allowedIps: allowedIps, enabled: enabled })
        .then(function () {
          $('#q-wg-peer-modal').modal('hide');
          Hive.ui.notify({ title: 'Peer Update Staged', message: 'Changes for ' + name + ' added to pending diff.', type: 'success' });
        });
      return;
    }

    var $btn = $('#q-wg-save-btn');
    if ($btn.hasClass('loading')) return;
    $btn.addClass('loading disabled');

    Hive.services.vpn
      .createPeerLive({ name: name, allowedIps: allowedIps, publicKey: publicKey, usePsk: usePsk })
      .then(function (res) {
        $('#q-wg-peer-modal').modal('hide');
        Hive.ui.notify({ title: 'WireGuard Peer Created', message: 'Peer ' + name + ' created on netbeed.', type: 'success' });
        if (res && res.clientConfig) {
          window.setTimeout(function () {
            showConfigModal(name, res.clientConfig, publicKey === '');
          }, 220);
        }
      })
      .catch(function (err) {
        Hive.ui.notify({ title: 'Failed to Create Peer', message: err.message || 'Check tunnel IP against wg0 subnet.', type: 'error', displayTime: 4500 });
      })
      .finally(function () {
        $btn.removeClass('loading disabled');
      });
  }

  function openExportModal(id) {
    var p = (state.vpn.wireguard.peers || []).find(function (x) { return x.id === id; });
    if (!p) return;
    showConfigModal(p.name, Hive.services.vpn.buildWgClientConfig(id), false);
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.vpn.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.vpn = data;
      renderContent();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    cleanupDetachedModals();

    Hive.services.vpn.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.vpn = data;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">WireGuard VPN</h1>' +
        '    <p class="q-page-subtitle">Kernel-space <code>wg0</code> encrypted remote access server, Curve25519 key generation, and client profile export.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <button type="button" class="ui secondary button" id="q-wg-srv-btn"><i data-lucide="settings" class="q-icon q-icon-sm"></i><span>Server Settings</span></button>' +
        '    <button type="button" class="ui primary button" id="q-add-wg-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add WireGuard Peer</span></button>' +
        '  </div>' +
        '</div>' +

        '<div class="q-wg-hero" id="q-wg-hero"></div>' +

        '<div class="q-card">' +
        '  <div class="q-card-header">' +
        '    <div>' +
        '      <h2 class="q-card-title">Authorized WireGuard Peers</h2>' +
        '      <p class="q-card-subtitle">Live handshake telemetry and transfer counters read directly from <code>wg show wg0 dump</code>.</p>' +
        '    </div>' +
        '    <button type="button" class="ui mini basic button" id="q-wg-refresh-btn"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Refresh Handshakes</span></button>' +
        '  </div>' +
        '  <div class="q-table-wrap">' +
        '    <table class="ui selectable striped table">' +
        '      <thead><tr><th>Peer &amp; Endpoint</th><th>Public Key</th><th>Allowed IPs</th><th>Handshake / Transfer</th><th>Status</th><th>State</th><th style="width:116px;">Actions</th></tr></thead>' +
        '      <tbody id="q-wg-peers-tbody"></tbody>' +
        '    </table>' +
        '  </div>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);
      renderContent();
    });

    $container.on('click.qVpn', '#q-wg-srv-btn', openServerModal);
    $container.on('click.qVpn', '#q-add-wg-btn', function () { openWgPeerModal(null); });
    $container.on('click.qVpn', '#q-wg-refresh-btn', loadAndRender);
    $container.on('click.qVpn', '.q-wg-edit-btn', function () { openWgPeerModal($(this).attr('data-id')); });
    $container.on('click.qVpn', '.q-wg-export-btn', function () { openExportModal($(this).attr('data-id')); });

    $container.on('change.qVpn', '.q-wg-toggle input', function () {
      var $toggle = $(this).closest('.q-wg-toggle');
      var id = $toggle.attr('data-id');
      var enabled = this.checked;
      $toggle.closest('tr').toggleClass('q-rule-disabled', !enabled);
      Hive.services.vpn.toggleWgPeer(id, enabled);
    });

    $container.on('click.qVpn', '.q-wg-del-btn', function () {
      Hive.services.vpn.deleteWgPeer($(this).attr('data-id')).then(function () {
        Hive.ui.notify({ title: 'Peer Removal Staged', message: 'WireGuard peer queued for removal.', type: 'warning' });
      });
    });

    $(document).on('click.qVpnModal', '#q-wgs-save-btn', saveServerModal);
    $(document).on('submit.qVpnModal', '#q-wg-srv-form', function (e) { e.preventDefault(); saveServerModal(); });
    $(document).on('click.qVpnModal', '#q-wg-save-btn', saveWgPeerModal);
    $(document).on('submit.qVpnModal', '#q-wg-peer-form', function (e) { e.preventDefault(); saveWgPeerModal(); });

    $(document).on('click.qVpnModal', '#q-wg-exp-copy', function () {
      var text = $('#q-wg-exp-code').text();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(function () {});
      }
      Hive.ui.notify({ title: 'Config Copied', message: state.exportPeerName + '.conf copied to clipboard.', type: 'success' });
    });

    $(document).on('click.qVpnModal', '#q-wg-exp-download', function () {
      var text = $('#q-wg-exp-code').text();
      var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = state.exportPeerName + '.conf';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      Hive.ui.notify({ title: 'Profile Exported', message: 'Downloaded ' + state.exportPeerName + '.conf.', type: 'info' });
    });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (reason === 'telemetry' || reason === 'inline-toggle' || reason === 'flows-tick' || reason === 'audit') return;
      loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    $(document).off('.qVpnModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qVpn');
      state.$root = null;
    }
  }

  Hive.router.register('/security/vpn', {
    title: 'WireGuard VPN',
    group: 'Security',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
