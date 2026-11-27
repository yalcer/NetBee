/* ==========================================================================
   Hive — Routing & Gateways (#/network/routing)
   WAN Upstream Gateway, Persisted Static Routes, LPM Lookup & ARP/NDP Table.
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    gateways: [],
    staticRoutes: [],
    connectedRoutes: [],
    neighbors: [],
    interfaces: [],
    search: '',
    neighSearch: '',
    matchedRouteId: null,
    editingRouteId: null,
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-rt-modal').modal('hide').remove();
  }

  function renderModalsHtml() {
    var esc = Hive.format.escapeHtml;
    var ifaceOptions = state.interfaces
      .map(function (i) {
        return '<div class="item" data-value="' + esc(i.device) + '"><span class="q-mono">' + esc(i.device) + '</span> — ' + esc(i.label) + '</div>';
      })
      .join('');

    return (
      '<div class="ui small modal" id="q-rt-modal" role="dialog" aria-labelledby="q-rt-modal-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-rt-modal-title"><i data-lucide="git-fork" class="q-icon q-text-accent"></i><span id="q-rt-modal-heading">Add Static Route</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-rt-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-rt-dst-field"><label for="q-rt-dst">Destination Network (CIDR)</label><input id="q-rt-dst" type="text" class="q-mono" placeholder="10.80.0.0/16"><span class="q-field-error" id="q-rt-dst-err" hidden>Enter a valid IPv4/IPv6 CIDR (e.g. 10.80.0.0/16).</span></div>' +
      '        <div class="field" id="q-rt-gw-field"><label for="q-rt-gw">Next-Hop Gateway</label><input id="q-rt-gw" type="text" class="q-mono" placeholder="192.168.10.2"><span class="q-field-error" id="q-rt-gw-err" hidden>Enter a valid gateway IP or select an egress interface.</span></div>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field"><label>Egress Interface</label>' +
      '          <div class="ui fluid selection dropdown" id="q-rt-iface-dd"><input type="hidden" id="q-rt-iface" value="eth0"><i class="dropdown icon"></i><div class="text">eth0</div><div class="menu">' + ifaceOptions + '</div></div>' +
      '        </div>' +
      '        <div class="field required" id="q-rt-metric-field"><label for="q-rt-metric">Metric (0 – 65535)</label><input id="q-rt-metric" type="number" class="q-mono" value="100" min="0" max="65535"><span class="q-field-error" id="q-rt-metric-err" hidden>Enter an integer metric between 0 and 65535.</span></div>' +
      '      </div>' +
      '      <div class="field"><label for="q-rt-desc">Description</label><input id="q-rt-desc" type="text" placeholder="Remote subnet via LAN router or VPN"></div>' +
      '      <div class="field" style="margin-bottom:0;"><div class="ui toggle checkbox" id="q-rt-enabled-chk"><input type="checkbox" id="q-rt-enabled" checked><label for="q-rt-enabled">Route enabled</label></div></div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-rt-save-btn">Stage Route</button>' +
      '  </div>' +
      '</div>'
    );
  }

  function renderContent() {
    if (!state.$root) return;
    var esc = Hive.format.escapeHtml;

    var gwHtml = state.gateways
      .map(function (gw) {
        var online = gw.status === 'online';
        return (
          '<div class="q-card">' +
          '  <div class="q-gateway-top" style="margin-bottom:8px;">' +
          '    <span class="q-gateway-name"><span class="q-status-dot ' + (online ? 'is-success' : 'is-warning') + '"></span><span class="q-mono">' + esc(gw.name) + '</span></span>' +
          '    <span class="ui label ' + (online ? 'q-status-success' : 'q-status-warning') + '">' + (online ? 'Active Default Route' : 'Awaiting Uplink') + '</span>' +
          '  </div>' +
          '  <div class="q-gateway-metrics">' +
          '    <div><span class="q-gateway-metric-label">Next Hop</span><span class="q-gateway-metric-val q-mono">' + esc(gw.address) + '</span></div>' +
          '    <div><span class="q-gateway-metric-label">WAN Device</span><span class="q-gateway-metric-val q-mono">' + esc(gw.iface) + '</span></div>' +
          '    <div><span class="q-gateway-metric-label">Role</span><span class="q-gateway-metric-val">' + esc(gw.role) + '</span></div>' +
          '  </div>' +
          '</div>'
        );
      })
      .join('');
    state.$root.find('#q-rt-gateways').html(gwHtml);

    var q = state.search.toLowerCase();
    var filteredStatic = state.staticRoutes.filter(function (r) {
      if (!q) return true;
      return (r.destination + ' ' + r.gateway + ' ' + r.iface + ' ' + r.description).toLowerCase().indexOf(q) !== -1;
    });

    var staticRows = filteredStatic.length
      ? filteredStatic
          .map(function (r) {
            var cls = [];
            if (!r.enabled) cls.push('q-rule-disabled');
            if (state.matchedRouteId === r.id) cls.push('q-rule-matched');
            return (
              '<tr class="' + cls.join(' ') + '">' +
              '  <td class="q-mono"><strong>' + esc(r.destination) + '</strong><span class="q-rule-desc">' + esc(r.description) + '</span></td>' +
              '  <td class="q-mono">' + esc(r.gateway || 'Direct') + '</td>' +
              '  <td><span class="ui label q-badge-square q-mono">' + esc(r.iface || 'auto') + '</span></td>' +
              '  <td class="q-mono">' + r.metric + '</td>' +
              '  <td><span class="ui label ' + (r.enabled ? 'q-status-success' : '') + '">' + (r.enabled ? 'Active' : 'Disabled') + '</span></td>' +
              '  <td><div class="ui fitted toggle checkbox q-rt-toggle" data-id="' + esc(r.id) + '"><input type="checkbox"' + (r.enabled ? ' checked' : '') + '><label></label></div></td>' +
              '  <td><div class="q-row-actions">' +
              '    <button type="button" class="ui mini icon button q-btn-ghost q-rt-edit-btn" data-id="' + esc(r.id) + '" aria-label="Edit route"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
              '    <button type="button" class="ui mini icon button q-btn-ghost q-rt-del-btn" data-id="' + esc(r.id) + '" aria-label="Delete route"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
              '  </div></td>' +
              '</tr>'
            );
          })
          .join('')
      : '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--q-text-muted);">No persisted static routes configured.</td></tr>';
    state.$root.find('#q-rt-static-tbody').html(staticRows);

    var connRows = state.connectedRoutes.length
      ? state.connectedRoutes
          .map(function (c) {
            var cls = state.matchedRouteId === c.id ? 'q-rule-matched' : '';
            return (
              '<tr class="' + cls + '">' +
              '  <td class="q-mono"><strong>' + esc(c.destination) + '</strong></td>' +
              '  <td class="q-text-secondary">' + esc(c.gateway) + '</td>' +
              '  <td><span class="ui label q-badge-square q-mono">' + esc(c.iface) + '</span></td>' +
              '  <td class="q-mono">' + c.metric + '</td>' +
              '  <td class="q-text-muted">' + esc(c.description) + '</td>' +
              '</tr>'
            );
          })
          .join('')
      : '<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--q-text-muted);">No connected kernel routes reported.</td></tr>';
    state.$root.find('#q-rt-conn-tbody').html(connRows);

    // ARP / IPv6 NDP Neighbors Table
    var nq = state.neighSearch.toLowerCase();
    var neighFiltered = state.neighbors.filter(function (n) {
      if (!nq) return true;
      return (n.ip + ' ' + n.mac + ' ' + n.iface + ' ' + n.state).toLowerCase().indexOf(nq) !== -1;
    });
    state.$root.find('#q-nb-count').text(neighFiltered.length + ' neighbors');
    var neighRows = neighFiltered.length
      ? neighFiltered
          .map(function (n) {
            var reach = n.state.indexOf('REACHABLE') !== -1 || n.state.indexOf('PERMANENT') !== -1;
            return (
              '<tr>' +
              '  <td class="q-mono"><strong>' + esc(n.ip) + '</strong></td>' +
              '  <td class="q-mono q-text-secondary">' + esc(n.mac) + '</td>' +
              '  <td><span class="ui label q-badge-square q-mono">' + esc(n.iface) + '</span></td>' +
              '  <td><span class="ui label ' + (reach ? 'q-status-success' : '') + ' q-mono">' + esc(n.state) + '</span></td>' +
              '</tr>'
            );
          })
          .join('')
      : '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--q-text-muted);">No ARP / NDP neighbor entries found.</td></tr>';
    state.$root.find('#q-nb-tbody').html(neighRows);

    if (Hive.icons) Hive.icons.render();
    state.$root.find('#q-rt-static-tbody .ui.checkbox').checkbox();
  }

  function openRouteModal(id) {
    state.editingRouteId = id || null;
    var r = id ? state.staticRoutes.find(function (x) { return x.id === id; }) : null;
    var esc = Hive.format.escapeHtml;
    var ifaceOptions = state.interfaces
      .map(function (i) {
        return '<div class="item" data-value="' + esc(i.device) + '"><span class="q-mono">' + esc(i.device) + '</span> — ' + esc(i.label) + '</div>';
      })
      .join('');
    var $dd = $('#q-rt-iface-dd');
    $dd.find('.menu').html(ifaceOptions);
    $dd.dropdown('refresh').dropdown('set selected', r ? r.iface : 'eth0');

    $('#q-rt-modal-heading').text(r ? 'Edit Static Route' : 'Add Static Route');
    $('#q-rt-dst').val(r ? r.destination : '');
    $('#q-rt-gw').val(r ? r.gateway : '');
    $('#q-rt-metric').val(r ? r.metric : 100);
    $('#q-rt-desc').val(r ? r.description : '');
    $('#q-rt-enabled-chk').checkbox(!r || r.enabled ? 'set checked' : 'set unchecked');
    $('#q-rt-dst-field, #q-rt-gw-field, #q-rt-metric-field').removeClass('error');
    $('#q-rt-dst-err, #q-rt-gw-err, #q-rt-metric-err').attr('hidden', true);
    Hive.ui.openModal('#q-rt-modal');
  }

  function saveRouteModal() {
    var v = Hive.validators;
    var destination = $.trim($('#q-rt-dst').val());
    var gateway = $.trim($('#q-rt-gw').val());
    var iface = $('#q-rt-iface').val() || '';
    var metric = Number($('#q-rt-metric').val() || 0);
    var description = $.trim($('#q-rt-desc').val()) || ('Static route ' + destination);
    var enabled = $('#q-rt-enabled').is(':checked');

    var ok = true;
    $('#q-rt-dst-field, #q-rt-gw-field, #q-rt-metric-field').removeClass('error');
    $('#q-rt-dst-err, #q-rt-gw-err, #q-rt-metric-err').attr('hidden', true);

    var validDst = v.isCIDR(destination) || v.isIPv4(destination) || v.isIPv6(destination);
    if (!validDst) {
      $('#q-rt-dst-field').addClass('error');
      $('#q-rt-dst-err').removeAttr('hidden');
      ok = false;
    }
    if (!gateway && !iface) {
      $('#q-rt-gw-field').addClass('error');
      $('#q-rt-gw-err').removeAttr('hidden');
      ok = false;
    } else if (gateway && !v.isIPv4(gateway) && !v.isIPv6(gateway)) {
      $('#q-rt-gw-field').addClass('error');
      $('#q-rt-gw-err').removeAttr('hidden');
      ok = false;
    }
    if (!Number.isInteger(metric) || metric < 0 || metric > 65535) {
      $('#q-rt-metric-field').addClass('error');
      $('#q-rt-metric-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    Hive.services.routing
      .saveRoute({ id: state.editingRouteId, destination: destination, gateway: gateway, iface: iface, metric: metric, description: description, enabled: enabled })
      .then(function () {
        $('#q-rt-modal').modal('hide');
        Hive.ui.notify({ title: 'Route Staged', message: destination + ' queued for commit.', type: 'success' });
      });
  }

  function runLpmLookup() {
    var ip = $.trim($('#q-lpm-ip').val());
    if (!Hive.validators.isIP(ip)) {
      Hive.ui.notify({ title: 'Invalid IP Address', message: 'Enter a valid IPv4 or IPv6 address (e.g. 192.168.10.42, 1.1.1.1, or 2001:db8::1).', type: 'error' });
      return;
    }
    Hive.services.routing.lookupRoute(ip).then(function (match) {
      var esc = Hive.format.escapeHtml;
      var $res = $('#q-lpm-result');
      if (!match) {
        state.matchedRouteId = null;
        renderContent();
        $res.html('<span class="ui label q-status-danger">No Route</span> <span>No active route matched <strong class="q-mono">' + esc(ip) + '</strong>.</span>').removeAttr('hidden');
        return;
      }
      var r = match.route;
      state.matchedRouteId = r.id;
      renderContent();
      $res
        .html(
          '<div><span class="ui primary label q-badge-square q-mono">/' + match.prefixLength + ' LPM</span> ' +
          '<strong class="q-mono" style="margin-left:6px;">' + esc(ip) + '</strong> → ' +
          '<span class="q-mono">' + esc(r.destination) + '</span> via <strong class="q-mono">' + esc(r.gateway || 'Direct') + '</strong> ' +
          'on <span class="ui label q-badge-square q-mono">' + esc(r.iface) + '</span> ' +
          '<span class="q-text-muted">(' + esc(r.sourceType) + ')</span></div>' +
          '<button type="button" class="ui mini button q-btn-ghost" id="q-lpm-clear">Clear</button>'
        )
        .removeAttr('hidden');
    });
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.routing.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.gateways = data.gateways;
      state.staticRoutes = data.staticRoutes;
      state.connectedRoutes = data.connectedRoutes;
      state.neighbors = data.neighbors || [];
      state.interfaces = data.interfaces;
      renderContent();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.search = '';
    state.neighSearch = '';
    state.matchedRouteId = null;
    cleanupDetachedModals();

    Hive.services.routing.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.gateways = data.gateways;
      state.staticRoutes = data.staticRoutes;
      state.connectedRoutes = data.connectedRoutes;
      state.neighbors = data.neighbors || [];
      state.interfaces = data.interfaces;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Routing &amp; Neighbors</h1>' +
        '    <p class="q-page-subtitle">WAN upstream gateway status, persisted static IPv4/IPv6 routes, LPM lookup, and live ARP/NDP neighbors.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <button type="button" class="ui secondary button" id="q-rt-wan-recon-btn"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Reconnect WAN</span></button>' +
        '    <button type="button" class="ui primary button" id="q-rt-add-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add Static Route</span></button>' +
        '  </div>' +
        '</div>' +

        '<div style="margin-bottom:var(--q-space-5);" id="q-rt-gateways"></div>' +

        '<div class="q-card" style="margin-bottom: var(--q-space-5);">' +
        '  <div class="q-card-header" style="margin-bottom:var(--q-space-3);padding-bottom:var(--q-space-2);">' +
        '    <div>' +
        '      <h2 class="q-card-title" style="font-size:var(--q-text-base);"><i data-lucide="radar" class="q-icon q-text-accent"></i><span>Route Lookup (Longest Prefix Match)</span></h2>' +
        '      <p class="q-card-subtitle">Evaluate egress interface and next hop across kernel connected subnets, static routes, and default gateway.</p>' +
        '    </div>' +
        '  </div>' +
        '  <form class="ui form q-lpm-bar" id="q-lpm-form" novalidate>' +
        '    <div class="field" style="margin:0;"><label for="q-lpm-ip">Destination IP Address</label><input id="q-lpm-ip" type="text" class="q-mono" value="1.1.1.1" placeholder="e.g. 192.168.10.42, 1.1.1.1, or 2001:db8::1"></div>' +
        '    <button type="submit" class="ui primary button" style="height:38px;">Resolve Route</button>' +
        '  </form>' +
        '  <div class="q-sim-result" id="q-lpm-result" hidden></div>' +
        '</div>' +

        '<div class="q-card" style="margin-bottom: var(--q-space-5);">' +
        '  <div class="q-toolbar">' +
        '    <div class="q-toolbar-left">' +
        '      <h2 class="q-card-title" style="margin-right:12px;"><i data-lucide="git-fork" class="q-icon q-text-accent"></i><span>Persisted Static Routes</span></h2>' +
        '      <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-rt-search" placeholder="Filter CIDR, gateway, interface..."></div>' +
        '    </div>' +
        '  </div>' +
        '  <div class="q-table-wrap">' +
        '    <table class="ui selectable striped table">' +
        '      <thead><tr><th>Destination &amp; Description</th><th>Next Hop</th><th>Interface</th><th>Metric</th><th>Status</th><th>State</th><th style="width:86px;">Edit</th></tr></thead>' +
        '      <tbody id="q-rt-static-tbody"></tbody>' +
        '    </table>' +
        '  </div>' +
        '</div>' +

        '<div class="q-card" style="margin-bottom: var(--q-space-5);">' +
        '  <div class="q-card-header">' +
        '    <div>' +
        '      <h2 class="q-card-title"><i data-lucide="link" class="q-icon q-text-accent"></i><span>Kernel Connected Subnets</span></h2>' +
        '      <p class="q-card-subtitle">Live direct routes reported by <code>ip route show</code>.</p>' +
        '    </div>' +
        '  </div>' +
        '  <div class="q-table-wrap">' +
        '    <table class="ui striped table">' +
        '      <thead><tr><th>Connected CIDR</th><th>Origin</th><th>Interface</th><th>Metric</th><th>Protocol</th></tr></thead>' +
        '      <tbody id="q-rt-conn-tbody"></tbody>' +
        '    </table>' +
        '  </div>' +
        '</div>' +

        '<div class="q-card">' +
        '  <div class="q-toolbar">' +
        '    <div class="q-toolbar-left">' +
        '      <h2 class="q-card-title" style="margin-right:12px;"><i data-lucide="users" class="q-icon q-text-accent"></i><span>ARP &amp; IPv6 NDP Neighbor Table</span></h2>' +
        '      <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-nb-search" placeholder="Filter IP, MAC, interface..."></div>' +
        '    </div>' +
        '    <div class="q-toolbar-right"><span class="ui label q-mono" id="q-nb-count"></span></div>' +
        '  </div>' +
        '  <div class="q-table-wrap">' +
        '    <table class="ui selectable striped table">' +
        '      <thead><tr><th>Neighbor IP</th><th>Hardware MAC (LLAddr)</th><th>Interface</th><th>NUD State</th></tr></thead>' +
        '      <tbody id="q-nb-tbody"></tbody>' +
        '    </table>' +
        '  </div>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);
      renderContent();
    });

    $container.on('input.qRouting', '#q-rt-search', function () {
      state.search = $.trim($(this).val());
      renderContent();
    });

    $container.on('input.qRouting', '#q-nb-search', function () {
      state.neighSearch = $.trim($(this).val());
      renderContent();
    });

    $container.on('submit.qRouting', '#q-lpm-form', function (e) {
      e.preventDefault();
      runLpmLookup();
    });

    $container.on('click.qRouting', '#q-lpm-clear', function () {
      state.matchedRouteId = null;
      $('#q-lpm-result').attr('hidden', true);
      renderContent();
    });

    $container.on('click.qRouting', '#q-rt-add-btn', function () { openRouteModal(null); });
    $container.on('click.qRouting', '.q-rt-edit-btn', function () { openRouteModal($(this).attr('data-id')); });

    $container.on('click.qRouting', '#q-rt-wan-recon-btn', function () {
      var $btn = $(this).addClass('loading disabled');
      Hive.services.interfaces
        .reconnectWan()
        .then(function () {
          Hive.ui.notify({ title: 'WAN Reconnected', message: 'Renewed WAN uplink session.', type: 'success' });
          loadAndRender();
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Reconnect Failed', message: err.message, type: 'error' });
        })
        .then(function () {
          $btn.removeClass('loading disabled');
        });
    });

    $container.on('change.qRouting', '.q-rt-toggle input', function () {
      var $toggle = $(this).closest('.q-rt-toggle');
      var id = $toggle.attr('data-id');
      var enabled = this.checked;
      var $row = $toggle.closest('tr');
      $row.toggleClass('q-rule-disabled', !enabled);
      $row.find('td').eq(4).html('<span class="ui label ' + (enabled ? 'q-status-success' : '') + '">' + (enabled ? 'Active' : 'Disabled') + '</span>');
      Hive.services.routing.toggleRoute(id, enabled);
    });

    $container.on('click.qRouting', '.q-rt-del-btn', function () {
      Hive.services.routing.deleteRoute($(this).attr('data-id')).then(function () {
        Hive.ui.notify({ title: 'Route Removal Staged', message: 'Static route queued for deletion.', type: 'warning' });
      });
    });

    $(document).on('click.qRoutingModal', '#q-rt-save-btn', saveRouteModal);
    $(document).on('submit.qRoutingModal', '#q-rt-form', function (e) { e.preventDefault(); saveRouteModal(); });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (Hive.store.isRuntimeOnlyReason(reason)) return;
      if (reason === 'inline-toggle') {
        state.staticRoutes = JSON.parse(JSON.stringify(Hive.store.getState().staticRoutes || []));
        return;
      }
      loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    $(document).off('.qRoutingModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qRouting');
      state.$root = null;
    }
  }

  Hive.router.register('/network/routing', {
    title: 'Routing & Gateways',
    group: 'Network',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
