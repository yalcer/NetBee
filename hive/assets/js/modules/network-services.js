/* ==========================================================================
   Hive — DHCP & DNS Services (#/network/services)
   AdGuardHome Single-LAN DHCP Pool, Static Leases, Upstreams, Cache & Rewrites.
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    dhcp: null,
    dns: null,
    interfaces: [],
    leaseSearch: '',
    editingScopeId: null,
    editingResId: null,
    editingDnsId: null,
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-scope-modal, #q-res-modal, #q-dns-ov-modal').modal('hide').remove();
  }

  function validUpstreamResolver(val) {
    var s = String(val || '').trim();
    if (!s) return false;
    if (Hive.validators.isIPv4(s) || Hive.validators.isIPv6(s)) return true;
    return /^(tls|https|quic|sdns):\/\/\S+$/i.test(s);
  }

  function renderModalsHtml() {
    return (
      '<div class="ui small modal" id="q-scope-modal" role="dialog" aria-labelledby="q-scope-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-scope-title"><i data-lucide="sliders-horizontal" class="q-icon q-text-accent"></i><span>Edit LAN DHCP Pool <span class="q-mono" id="q-sc-dev"></span></span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-scope-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-sc-start-field"><label for="q-sc-start">Pool Start IP</label><input id="q-sc-start" type="text" class="q-mono"><span class="q-field-error" id="q-sc-start-err" hidden>Enter a valid IPv4 address.</span></div>' +
      '        <div class="field required" id="q-sc-end-field"><label for="q-sc-end">Pool End IP</label><input id="q-sc-end" type="text" class="q-mono"><span class="q-field-error" id="q-sc-end-err" hidden>Enter a valid IPv4 address.</span></div>' +
      '      </div>' +
      '      <div class="field"><label for="q-sc-lease">Lease Duration (Hours)</label><input id="q-sc-lease" type="number" class="q-mono" min="1" max="720" value="24"></div>' +
      '      <div class="field" style="margin-bottom:0;"><div class="ui toggle checkbox" id="q-sc-enabled-chk"><input type="checkbox" id="q-sc-enabled"><label for="q-sc-enabled">Enable AdGuardHome DHCPv4 Server on LAN</label></div></div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-sc-save-btn">Stage DHCP Pool</button>' +
      '  </div>' +
      '</div>' +

      '<div class="ui small modal" id="q-res-modal" role="dialog" aria-labelledby="q-res-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-res-title"><i data-lucide="pin" class="q-icon q-text-accent"></i><span id="q-res-heading">Add Static DHCP Lease</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-res-form" novalidate>' +
      '      <div class="field required" id="q-res-host-field"><label for="q-res-host">Client Hostname</label><input id="q-res-host" type="text" class="q-mono" placeholder="nas-01"><span class="q-field-error" id="q-res-host-err" hidden>Enter a valid hostname.</span></div>' +
      '      <div class="two fields" style="margin-bottom:0;">' +
      '        <div class="field required" id="q-res-mac-field"><label for="q-res-mac">MAC Address</label><input id="q-res-mac" type="text" class="q-mono" placeholder="00:11:32:AB:44:20"><span class="q-field-error" id="q-res-mac-err" hidden>Enter a valid MAC (AA:BB:CC:DD:EE:FF).</span></div>' +
      '        <div class="field required" id="q-res-ip-field"><label for="q-res-ip">Pinned IPv4 Address</label><input id="q-res-ip" type="text" class="q-mono" placeholder="192.168.10.20"><span class="q-field-error" id="q-res-ip-err" hidden>Enter a valid IPv4 address.</span></div>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-res-save-btn">Stage Static Lease</button>' +
      '  </div>' +
      '</div>' +

      '<div class="ui small modal" id="q-dns-ov-modal" role="dialog" aria-labelledby="q-dns-ov-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-dns-ov-title"><i data-lucide="globe" class="q-icon q-text-accent"></i><span id="q-dns-ov-heading">Add DNS Rewrite</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-dns-ov-form" novalidate>' +
      '      <div class="field required" id="q-dns-host-field"><label for="q-dns-host">Domain / FQDN</label><input id="q-dns-host" type="text" class="q-mono" placeholder="homeassistant.lan"><span class="q-field-error" id="q-dns-host-err" hidden>Enter a valid hostname or domain.</span></div>' +
      '      <div class="field required" id="q-dns-val-field" style="margin-bottom:0;"><label for="q-dns-val">Answer (IPv4, IPv6, or CNAME Target)</label><input id="q-dns-val" type="text" class="q-mono" placeholder="192.168.10.25"><span class="q-field-error" id="q-dns-val-err" hidden>Enter a valid IP address or target domain.</span></div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-dns-ov-save-btn">Stage Rewrite</button>' +
      '  </div>' +
      '</div>'
    );
  }

  function renderActiveTab() {
    if (!state.$root || !state.dhcp || !state.dns) return;
    var fmt = Hive.format;
    var esc = fmt.escapeHtml;

    state.$root.find('[data-svc-count="leases"]').text(state.dhcp.leases.length);
    state.$root.find('[data-svc-count="reservations"]').text(state.dhcp.reservations.length);
    state.$root.find('[data-svc-count="dns"]').text(state.dns.overrides.length);

    var scopesHtml = state.dhcp.scopes
      .map(function (sc) {
        var used = state.dhcp.leases.length;
        var pct = Math.max(2, Math.round((used / Math.max(1, sc.poolSize)) * 100));
        return (
          '<div class="q-card">' +
          '  <div class="q-iface-card-top">' +
          '    <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;"><span class="q-iface-dev q-mono">' + esc(sc.iface) + '</span> <span class="ui label q-net-lan q-badge-square q-mono">LAN</span> <span class="ui label ' + (sc.enabled ? 'q-status-success' : '') + '">' + (sc.enabled ? 'DHCP Active' : 'Disabled') + '</span></div>' +
          '    <button type="button" class="ui mini secondary button q-sc-edit-btn" data-id="' + esc(sc.id) + '"><i data-lucide="pencil" class="q-icon q-icon-sm"></i><span>Edit Pool</span></button>' +
          '  </div>' +
          '  <div class="q-kv-list" style="margin-bottom:10px;">' +
          '    <div class="q-kv-row"><span class="q-kv-label">Pool Range</span><span class="q-kv-value q-mono">' + esc(sc.rangeStart + ' – ' + sc.rangeEnd) + '</span></div>' +
          '    <div class="q-kv-row"><span class="q-kv-label">Gateway / DNS</span><span class="q-kv-value q-mono">' + esc(sc.gatewayIp || sc.dnsServer) + ' · Lease ' + sc.leaseHours + 'h</span></div>' +
          '    <div class="q-kv-row"><span class="q-kv-label">Active Leases</span><span class="q-kv-value q-mono">' + used + ' / ' + sc.poolSize + '</span></div>' +
          '  </div>' +
          '  <div class="ui tiny ' + (sc.enabled ? 'success' : '') + ' progress" data-percent="' + pct + '"><div class="bar" style="width:' + pct + '%;"></div></div>' +
          '</div>'
        );
      })
      .join('');
    state.$root.find('#q-dhcp-scopes').html(scopesHtml);

    var q = state.leaseSearch.toLowerCase();
    var filteredLeases = state.dhcp.leases.filter(function (l) {
      if (!q) return true;
      return (l.ip + ' ' + l.mac + ' ' + l.hostname).toLowerCase().indexOf(q) !== -1;
    });

    var leaseRows = filteredLeases.length
      ? filteredLeases
          .map(function (l) {
            var pinned = state.dhcp.reservations.some(function (r) { return r.mac.toLowerCase() === l.mac.toLowerCase(); });
            return (
              '<tr>' +
              '  <td class="q-mono"><strong>' + esc(l.ip) + '</strong></td>' +
              '  <td class="q-mono q-text-secondary">' + esc(l.mac) + '</td>' +
              '  <td>' + esc(l.hostname) + '</td>' +
              '  <td><span class="ui label q-net-lan q-badge-square q-mono">' + esc(l.iface) + '</span></td>' +
              '  <td class="q-mono q-text-muted">' + esc(l.expires || 'Active') + '</td>' +
              '  <td>' +
              (pinned
                ? '<span class="ui label q-status-success">Pinned</span>'
                : '<button type="button" class="ui mini secondary button q-promote-lease-btn" data-id="' + esc(l.id) + '"><i data-lucide="pin" class="q-icon q-icon-sm"></i><span>Pin Static</span></button>') +
              '  </td>' +
              '</tr>'
            );
          })
          .join('')
      : '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--q-text-muted);">No active dynamic DHCP leases.</td></tr>';
    state.$root.find('#q-dhcp-leases-tbody').html(leaseRows);

    var resRows = state.dhcp.reservations
      .map(function (r) {
        return (
          '<tr>' +
          '  <td class="q-mono"><strong>' + esc(r.hostname) + '</strong></td>' +
          '  <td class="q-mono">' + esc(r.ip) + '</td>' +
          '  <td class="q-mono q-text-secondary">' + esc(r.mac) + '</td>' +
          '  <td><span class="ui label q-badge-square q-mono">' + esc(r.iface) + '</span></td>' +
          '  <td><div class="q-row-actions">' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-res-edit-btn" data-id="' + esc(r.id) + '"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-res-del-btn" data-id="' + esc(r.id) + '"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-dhcp-res-tbody').html(resRows || '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--q-text-muted);">No static MAC reservations configured.</td></tr>');

    state.$root.find('#q-dns-upstreams').val((state.dns.resolvers || []).join('\n'));
    state.$root.find('#q-dns-cache').val(state.dns.cacheSize !== undefined ? state.dns.cacheSize : 4194304);
    state.$root.find('#q-dns-sec-chk').checkbox(state.dns.dnssecEnabled ? 'set checked' : 'set unchecked');

    var ovRows = state.dns.overrides
      .map(function (ov) {
        return (
          '<tr>' +
          '  <td class="q-mono"><strong>' + esc(ov.hostname) + '</strong></td>' +
          '  <td><span class="ui label q-net-lan q-badge-square q-mono">' + esc(ov.type) + '</span></td>' +
          '  <td class="q-mono">' + esc(ov.value) + '</td>' +
          '  <td><div class="q-row-actions">' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-dns-edit-btn" data-id="' + esc(ov.id) + '"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-dns-del-btn" data-id="' + esc(ov.id) + '"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-dns-ov-tbody').html(ovRows || '<tr><td colspan="4" style="text-align:center;padding:24px;color:var(--q-text-muted);">No local DNS rewrites configured.</td></tr>');

    if (Hive.icons) Hive.icons.render();
  }

  function openScopeModal(id) {
    var sc = state.dhcp.scopes[0];
    if (!sc) return;
    state.editingScopeId = id;
    $('#q-sc-dev').text(sc.iface);
    $('#q-sc-start').val(sc.rangeStart);
    $('#q-sc-end').val(sc.rangeEnd);
    $('#q-sc-lease').val(sc.leaseHours);
    $('#q-sc-enabled-chk').checkbox(sc.enabled ? 'set checked' : 'set unchecked');
    $('#q-sc-start-field, #q-sc-end-field').removeClass('error');
    $('#q-sc-start-err, #q-sc-end-err').attr('hidden', true);
    Hive.ui.openModal('#q-scope-modal');
  }

  function saveScopeModal() {
    var v = Hive.validators;
    var rangeStart = $.trim($('#q-sc-start').val());
    var rangeEnd = $.trim($('#q-sc-end').val());
    var leaseHours = Math.max(1, Math.min(720, Math.round(Number($('#q-sc-lease').val()) || 24)));
    var enabled = $('#q-sc-enabled').is(':checked');

    var ok = true;
    $('#q-sc-start-field, #q-sc-end-field').removeClass('error');
    $('#q-sc-start-err, #q-sc-end-err').attr('hidden', true);

    if (!v.isIPv4(rangeStart)) { $('#q-sc-start-field').addClass('error'); $('#q-sc-start-err').removeAttr('hidden'); ok = false; }
    if (!v.isIPv4(rangeEnd)) { $('#q-sc-end-field').addClass('error'); $('#q-sc-end-err').removeAttr('hidden'); ok = false; }
    if (ok && v.ipv4ToInt(rangeStart) > v.ipv4ToInt(rangeEnd)) {
      $('#q-sc-end-field').addClass('error');
      $('#q-sc-end-err').text('End IP must be >= Start IP.').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    Hive.services.dhcpDns.updateScope(state.editingScopeId, { rangeStart: rangeStart, rangeEnd: rangeEnd, leaseHours: leaseHours, enabled: enabled }).then(function () {
      $('#q-scope-modal').modal('hide');
      Hive.ui.notify({ title: 'DHCP Pool Staged', message: 'Click Apply to commit AdGuardHome DHCP settings.', type: 'info' });
    });
  }

  function openResModal(id) {
    state.editingResId = id || null;
    var r = id ? state.dhcp.reservations.find(function (x) { return x.id === id; }) : null;
    $('#q-res-heading').text(r ? 'Edit Static DHCP Lease' : 'Add Static DHCP Lease');
    $('#q-res-host').val(r ? r.hostname : '');
    $('#q-res-mac').val(r ? r.mac : '');
    $('#q-res-ip').val(r ? r.ip : '');
    $('#q-res-host-field, #q-res-mac-field, #q-res-ip-field').removeClass('error');
    $('#q-res-host-err, #q-res-mac-err, #q-res-ip-err').attr('hidden', true);
    Hive.ui.openModal('#q-res-modal');
  }

  function saveResModal() {
    var v = Hive.validators;
    var hostname = $.trim($('#q-res-host').val());
    var mac = $.trim($('#q-res-mac').val()).toUpperCase();
    var ip = $.trim($('#q-res-ip').val());

    var ok = true;
    $('#q-res-host-field, #q-res-mac-field, #q-res-ip-field').removeClass('error');
    $('#q-res-host-err, #q-res-mac-err, #q-res-ip-err').attr('hidden', true);
    if (!v.isHostname(hostname)) { $('#q-res-host-field').addClass('error'); $('#q-res-host-err').removeAttr('hidden'); ok = false; }
    if (!v.isMAC(mac)) { $('#q-res-mac-field').addClass('error'); $('#q-res-mac-err').removeAttr('hidden'); ok = false; }
    if (!v.isIPv4(ip)) { $('#q-res-ip-field').addClass('error'); $('#q-res-ip-err').removeAttr('hidden'); ok = false; }
    if (!ok) return;

    Hive.services.dhcpDns.saveReservation({ id: state.editingResId, hostname: hostname, mac: mac, ip: ip }).then(function () {
      $('#q-res-modal').modal('hide');
      $('#q-svc-tabs-ctx .ui.menu .item[data-tab="reservations"]').tab('change tab', 'reservations');
      Hive.ui.notify({ title: 'Static Lease Staged', message: hostname + ' (' + ip + ') queued.', type: 'success' });
    });
  }

  function openDnsOvModal(id) {
    state.editingDnsId = id || null;
    var ov = id ? state.dns.overrides.find(function (x) { return x.id === id; }) : null;
    $('#q-dns-ov-heading').text(ov ? 'Edit DNS Rewrite' : 'Add DNS Rewrite');
    $('#q-dns-host').val(ov ? ov.hostname : '');
    $('#q-dns-val').val(ov ? ov.value : '');
    $('#q-dns-host-field, #q-dns-val-field').removeClass('error');
    $('#q-dns-host-err, #q-dns-val-err').attr('hidden', true);
    Hive.ui.openModal('#q-dns-ov-modal');
  }

  function saveDnsOvModal() {
    var v = Hive.validators;
    var hostname = $.trim($('#q-dns-host').val());
    var value = $.trim($('#q-dns-val').val());

    var ok = true;
    $('#q-dns-host-field, #q-dns-val-field').removeClass('error');
    $('#q-dns-host-err, #q-dns-val-err').attr('hidden', true);
    if (!hostname) { $('#q-dns-host-field').addClass('error'); $('#q-dns-host-err').removeAttr('hidden'); ok = false; }
    if (!v.isIPv4(value) && !v.isIPv6(value) && !v.isHostname(value)) {
      $('#q-dns-val-field').addClass('error');
      $('#q-dns-val-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    Hive.services.dhcpDns.saveDnsOverride({ id: state.editingDnsId, hostname: hostname, value: value }).then(function () {
      $('#q-dns-ov-modal').modal('hide');
      $('#q-svc-tabs-ctx .ui.menu .item[data-tab="dns"]').tab('change tab', 'dns');
      Hive.ui.notify({ title: 'DNS Rewrite Staged', message: hostname + ' -> ' + value, type: 'success' });
    });
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.dhcpDns.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.dhcp = data.dhcp;
      state.dns = data.dns;
      state.interfaces = data.interfaces;
      renderActiveTab();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.leaseSearch = '';
    cleanupDetachedModals();

    Hive.services.dhcpDns.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.dhcp = data.dhcp;
      state.dns = data.dns;
      state.interfaces = data.interfaces;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">DHCP &amp; DNS Services</h1>' +
        '    <p class="q-page-subtitle">AdGuardHome unified LAN DHCPv4 server (<code>:67</code>) and DNS resolver (<code>:53</code>) with rewrites and cache control.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <button type="button" class="ui secondary button" id="q-clear-dns-cache-btn"><i data-lucide="eraser" class="q-icon q-icon-sm"></i><span>Clear DNS Cache</span></button>' +
        '    <button type="button" class="ui secondary button" id="q-add-dns-btn"><i data-lucide="globe" class="q-icon q-icon-sm"></i><span>Add DNS Rewrite</span></button>' +
        '    <button type="button" class="ui primary button" id="q-add-res-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add Static Lease</span></button>' +
        '  </div>' +
        '</div>' +

        '<div id="q-svc-tabs-ctx">' +
        '  <div class="q-zone-tabs-bar">' +
        '    <div class="ui secondary pointing menu" data-tab-context="#q-svc-tabs-ctx">' +
        '      <a class="item active" data-tab="leases">LAN DHCP Pool &amp; Leases <span class="ui label q-mono" data-svc-count="leases">0</span></a>' +
        '      <a class="item" data-tab="reservations">Static Leases <span class="ui label q-mono" data-svc-count="reservations">0</span></a>' +
        '      <a class="item" data-tab="dns">Upstream DNS &amp; Rewrites <span class="ui label q-mono" data-svc-count="dns">0</span></a>' +
        '    </div>' +
        '  </div>' +

        '  <div class="ui tab active q-tab-plain" data-tab="leases">' +
        '    <div style="margin-bottom:var(--q-space-4);" id="q-dhcp-scopes"></div>' +
        '    <div class="q-card">' +
        '      <div class="q-toolbar">' +
        '        <div class="q-toolbar-left">' +
        '          <h2 class="q-card-title" style="margin-right:12px;">Active DHCP Leases</h2>' +
        '          <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-lease-search" placeholder="Filter IP, MAC, hostname..."></div>' +
        '        </div>' +
        '      </div>' +
        '      <div class="q-table-wrap">' +
        '        <table class="ui selectable striped table">' +
        '          <thead><tr><th>IPv4 Address</th><th>MAC Address</th><th>Hostname</th><th>Interface</th><th>Expires</th><th style="width:128px;">Static</th></tr></thead>' +
        '          <tbody id="q-dhcp-leases-tbody"></tbody>' +
        '        </table>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +

        '  <div class="ui tab q-tab-plain" data-tab="reservations">' +
        '    <div class="q-card">' +
        '      <div class="q-card-header">' +
        '        <div><h2 class="q-card-title">Static MAC Reservations</h2><p class="q-card-subtitle">Deterministic IPv4 assignments managed by AdGuardHome DHCP.</p></div>' +
        '      </div>' +
        '      <div class="q-table-wrap">' +
        '        <table class="ui selectable striped table">' +
        '          <thead><tr><th>Hostname</th><th>Pinned IPv4</th><th>MAC Address</th><th>Interface</th><th style="width:86px;">Edit</th></tr></thead>' +
        '          <tbody id="q-dhcp-res-tbody"></tbody>' +
        '        </table>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +

        '  <div class="ui tab q-tab-plain" data-tab="dns">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-5);">' +
        '      <div class="q-card-header">' +
        '        <div><h2 class="q-card-title">Upstream DNS Resolvers</h2><p class="q-card-subtitle">One resolver per line — supports plain IP, DoT (<code>tls://1.1.1.1</code>), DoH (<code>https://dns.quad9.net/dns-query</code>), and DoQ.</p></div>' +
        '      </div>' +
        '      <form class="ui form" id="q-dns-settings-form" novalidate>' +
        '        <div class="two fields">' +
        '          <div class="field"><label for="q-dns-upstreams">Upstream Servers (1 per line)</label><textarea id="q-dns-upstreams" rows="4" class="q-mono" placeholder="tls://1.1.1.1\nhttps://dns.quad9.net/dns-query"></textarea></div>' +
        '          <div class="field">' +
        '            <label for="q-dns-cache">DNS Cache Size (Bytes)</label>' +
        '            <input id="q-dns-cache" type="number" class="q-mono" min="0" max="67108864">' +
        '            <div class="ui toggle checkbox" id="q-dns-sec-chk" style="margin-top:16px;"><input type="checkbox" id="q-dns-sec"><label for="q-dns-sec">Enable DNSSEC Validation</label></div>' +
        '          </div>' +
        '        </div>' +
        '        <div style="display:flex;justify-content:flex-end;">' +
        '          <button type="submit" class="ui primary small button">Stage Resolver Settings</button>' +
        '        </div>' +
        '      </form>' +
        '    </div>' +

        '    <div class="q-card">' +
        '      <div class="q-card-header">' +
        '        <div><h2 class="q-card-title">Local DNS Rewrites</h2><p class="q-card-subtitle">Split-horizon domain answers served authoritatively on LAN &amp; WireGuard.</p></div>' +
        '      </div>' +
        '      <div class="q-table-wrap">' +
        '        <table class="ui selectable striped table">' +
        '          <thead><tr><th>Domain / FQDN</th><th>Type</th><th>Answer</th><th style="width:86px;">Edit</th></tr></thead>' +
        '          <tbody id="q-dns-ov-tbody"></tbody>' +
        '        </table>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);
      renderActiveTab();
    });

    $container.on('input.qDhcpDns', '#q-lease-search', function () {
      state.leaseSearch = $.trim($(this).val());
      renderActiveTab();
    });

    $container.on('click.qDhcpDns', '#q-clear-dns-cache-btn', function () {
      var $btn = $(this).addClass('loading disabled');
      Hive.services.dhcpDns
        .clearCache()
        .then(function () {
          Hive.ui.notify({ title: 'DNS Cache Cleared', message: 'Flushed AdGuardHome resolver cache.', type: 'success' });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Clear Failed', message: err.message, type: 'error' });
        })
        .then(function () {
          $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qDhcpDns', '.q-sc-edit-btn', function () { openScopeModal($(this).attr('data-id')); });
    $container.on('click.qDhcpDns', '#q-add-res-btn', function () { openResModal(null); });
    $container.on('click.qDhcpDns', '.q-res-edit-btn', function () { openResModal($(this).attr('data-id')); });
    $container.on('click.qDhcpDns', '#q-add-dns-btn', function () { openDnsOvModal(null); });
    $container.on('click.qDhcpDns', '.q-dns-edit-btn', function () { openDnsOvModal($(this).attr('data-id')); });

    $container.on('click.qDhcpDns', '.q-promote-lease-btn', function () {
      Hive.services.dhcpDns.promoteLease($(this).attr('data-id')).then(function (res) {
        if (res.ok) Hive.ui.notify({ title: 'Static Lease Staged', message: res.hostname + ' (' + res.ip + ') pinned.', type: 'success' });
        else Hive.ui.notify({ title: 'Notice', message: res.reason, type: 'warning' });
      });
    });

    $container.on('click.qDhcpDns', '.q-res-del-btn', function () {
      Hive.services.dhcpDns.deleteReservation($(this).attr('data-id')).then(function () {
        Hive.ui.notify({ title: 'Static Lease Removed', message: 'Queued for deletion.', type: 'warning' });
      });
    });

    $container.on('click.qDhcpDns', '.q-dns-del-btn', function () {
      Hive.services.dhcpDns.deleteDnsOverride($(this).attr('data-id')).then(function () {
        Hive.ui.notify({ title: 'DNS Rewrite Removed', message: 'Queued for deletion.', type: 'warning' });
      });
    });

    $container.on('submit.qDhcpDns', '#q-dns-settings-form', function (e) {
      e.preventDefault();
      var lines = String($('#q-dns-upstreams').val() || '')
        .split('\n')
        .map(function (s) { return $.trim(s); })
        .filter(Boolean);
      if (!lines.length || !lines.every(validUpstreamResolver)) {
        Hive.ui.notify({ title: 'Invalid Upstream', message: 'Provide valid IPv4/IPv6 or tls:///https:// upstream resolvers.', type: 'error' });
        return;
      }
      var cacheSize = Math.max(0, Math.min(67108864, Math.round(Number($('#q-dns-cache').val()) || 4194304)));
      Hive.services.dhcpDns
        .updateDnsSettings({
          resolvers: lines,
          dnssecEnabled: $('#q-dns-sec').is(':checked'),
          cacheSize: cacheSize
        })
        .then(function () {
          Hive.ui.notify({ title: 'DNS Settings Staged', message: 'Upstream resolvers queued for commit.', type: 'success' });
        });
    });

    $(document).on('click.qDhcpDnsModal', '#q-sc-save-btn', saveScopeModal);
    $(document).on('click.qDhcpDnsModal', '#q-res-save-btn', saveResModal);
    $(document).on('click.qDhcpDnsModal', '#q-dns-ov-save-btn', saveDnsOvModal);
    $(document).on('submit.qDhcpDnsModal', '#q-scope-form', function (e) { e.preventDefault(); saveScopeModal(); });
    $(document).on('submit.qDhcpDnsModal', '#q-res-form', function (e) { e.preventDefault(); saveResModal(); });
    $(document).on('submit.qDhcpDnsModal', '#q-dns-ov-form', function (e) { e.preventDefault(); saveDnsOvModal(); });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (reason !== 'telemetry' && reason !== 'audit') loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    $(document).off('.qDhcpDnsModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qDhcpDns');
      state.$root = null;
    }
  }

  Hive.router.register('/network/services', {
    title: 'DHCP & DNS',
    group: 'Network',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
