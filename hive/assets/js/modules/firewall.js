/* ==========================================================================
   Hive — Security Module: Firewall Rules (#/security/firewall)
   NetBee OS nftables Input/Forward chains, Global Toggles, Raw .nft & Simulator
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    rules: [],
    config: {
      transparentDns: true,
      exposeWireguard: false,
      wireguardPort: 51820,
      flowOffload: true,
      offloadActive: false
    },
    aliases: {},
    interfaces: [],
    activeChain: 'all',
    actionFilter: 'all',
    search: '',
    simOpen: false,
    matchedRuleId: null,
    editingId: null,
    editingAliasName: null,
    dragSourceId: null,
    dragTargetId: null,
    dragPosition: null,
    lastMouseDownTarget: null,
    lastReorderedId: null,
    refocusHandleId: null,
    reorderFlashTimer: null,
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-fw-rule-modal, #q-fw-aliases-modal, #q-fw-raw-modal').modal('hide').remove();
  }

  function clearDragVisuals() {
    state.dragSourceId = null;
    state.dragTargetId = null;
    state.dragPosition = null;
    if (state.$root) {
      state.$root.find('#q-fw-tbody tr').removeClass('is-dragging q-drop-before q-drop-after');
    }
  }

  function scheduleReorderFlash(ruleId) {
    state.lastReorderedId = ruleId;
    if (state.reorderFlashTimer) window.clearTimeout(state.reorderFlashTimer);
    state.reorderFlashTimer = window.setTimeout(function () {
      state.lastReorderedId = null;
      state.reorderFlashTimer = null;
      if (state.$root) state.$root.find('#q-fw-tbody tr.q-rule-reordered').removeClass('q-rule-reordered');
    }, 700);
  }

  function getFilteredRules() {
    var q = state.search.toLowerCase();
    return state.rules.filter(function (r) {
      var chain = r.chain || 'input';
      if (state.activeChain !== 'all' && chain !== state.activeChain) return false;
      if (state.actionFilter !== 'all' && r.action !== state.actionFilter) return false;
      if (q) {
        var hay = (
          r.id + ' ' + chain + ' ' + (r.inIface || 'any') + ' ' + (r.outIface || '') + ' ' +
          r.action + ' ' + r.protocol + ' ' + r.source + ' ' + r.destination + ' ' + r.port + ' ' + r.description
        ).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
  }

  function isSingleOrRangePort(val, aliases) {
    var s = String(val || '').trim();
    if (!s || s.toLowerCase() === 'any') return true;
    if (aliases && aliases[s] && Array.isArray(aliases[s].members) && aliases[s].members.length) {
      s = String(aliases[s].members[0] || '').trim();
    }
    if (s.indexOf(',') !== -1) return false;
    return Hive.validators.isPortSpec(s);
  }

  function resolveSingleAddr(val, aliases) {
    var s = String(val || '').trim();
    if (!s || s.toLowerCase() === 'any') return '';
    if (aliases && aliases[s] && Array.isArray(aliases[s].members) && aliases[s].members.length) {
      return String(aliases[s].members[0] || '').trim();
    }
    return s;
  }

  function formatEndpoint(value) {
    var esc = Hive.format.escapeHtml;
    var v = value || 'any';
    var alias = state.aliases[v];
    if (alias) {
      var title = alias.description + ' (' + (alias.members || []).join(', ') + ')';
      return '<span class="q-alias-chip" data-q-popup data-content="' + esc(title) + '" data-position="top center">' + esc(v) + '</span>';
    }
    return '<span class="q-mono">' + esc(v) + '</span>';
  }

  function buildInterfaceItems(includeAny) {
    var esc = Hive.format.escapeHtml;
    var seen = {};
    var items = [];
    if (includeAny) {
      items.push('<div class="item" data-value="">Any Interface</div>');
    }
    var defaults = [
      { dev: 'eth0', label: 'LAN' },
      { dev: 'eth1', label: 'WAN' },
      { dev: 'ppp0', label: 'PPPoE WAN' },
      { dev: 'wg0', label: 'WireGuard VPN' }
    ];
    defaults.forEach(function (d) {
      seen[d.dev] = true;
      items.push('<div class="item" data-value="' + esc(d.dev) + '"><span class="q-mono">' + esc(d.dev) + '</span> — ' + esc(d.label) + '</div>');
    });
    (state.interfaces || []).forEach(function (iface) {
      if (iface.device && !seen[iface.device]) {
        seen[iface.device] = true;
        items.push('<div class="item" data-value="' + esc(iface.device) + '"><span class="q-mono">' + esc(iface.device) + '</span> — ' + esc(iface.label || iface.device) + '</div>');
      }
    });
    return items.join('');
  }

  function renderAliasesTable() {
    var $tbody = $('#q-fw-aliases-tbody');
    if (!$tbody.length) return;
    var esc = Hive.format.escapeHtml;
    var names = Object.keys(state.aliases || {});
    if (!names.length) {
      $tbody.html('<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--q-text-muted);">No local helper aliases defined.</td></tr>');
      return;
    }
    var html = names
      .map(function (name) {
        var a = state.aliases[name];
        return (
          '<tr>' +
          '  <td><span class="q-alias-chip">' + esc(name) + '</span></td>' +
          '  <td><span class="ui label q-badge-square q-mono">' + esc(a.type) + '</span></td>' +
          '  <td class="q-mono">' + esc((a.members || []).join(', ')) + '</td>' +
          '  <td class="q-text-secondary">' + esc(a.description) + '</td>' +
          '  <td><div class="q-row-actions">' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-al-edit-btn" data-name="' + esc(name) + '" aria-label="Edit alias ' + esc(name) + '"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-al-del-btn" data-name="' + esc(name) + '" aria-label="Delete alias ' + esc(name) + '"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');
    $tbody.html(html);
    if (Hive.icons) Hive.icons.render();
  }

  function resetAliasForm() {
    state.editingAliasName = null;
    $('#q-al-form-title').text('Add Local Helper Alias');
    $('#q-al-name').val('');
    $('#q-al-type-dd').dropdown('set selected', 'network');
    $('#q-al-members').val('');
    $('#q-al-desc').val('');
    $('#q-al-save-btn').text('Save Alias');
    $('#q-al-cancel-edit').attr('hidden', true);
    $('#q-al-name-field, #q-al-mem-field').removeClass('error');
    $('#q-al-name-err, #q-al-mem-err').attr('hidden', true);
  }

  function saveAliasForm() {
    var v = Hive.validators;
    var name = $.trim($('#q-al-name').val()).toUpperCase();
    var type = $('#q-al-type').val() || 'network';
    var rawMembers = $.trim($('#q-al-members').val());
    var description = $.trim($('#q-al-desc').val()) || 'Local helper alias';
    var members = rawMembers.split(',').map(function (s) { return s.trim(); }).filter(Boolean);

    var ok = true;
    $('#q-al-name-field, #q-al-mem-field').removeClass('error');
    $('#q-al-name-err, #q-al-mem-err').attr('hidden', true);

    if (!v.isAliasName(name)) {
      $('#q-al-name-field').addClass('error');
      $('#q-al-name-err').text('Use 2–32 letters, digits, or underscores starting with a letter.').removeAttr('hidden');
      ok = false;
    } else if (name !== state.editingAliasName && state.aliases[name]) {
      $('#q-al-name-field').addClass('error');
      $('#q-al-name-err').text('An alias with this name already exists.').removeAttr('hidden');
      ok = false;
    }

    var membersValid = members.length === 1 && members.every(function (m) {
      if (type === 'port') return m.toLowerCase() !== 'any' && isSingleOrRangePort(m);
      return v.isIPv4OrCIDR(m) || v.isIPv6(m);
    });
    if (!membersValid) {
      $('#q-al-mem-field').addClass('error');
      $('#q-al-mem-err').text(type === 'port' ? 'Enter a single port or range (e.g. 443 or 8000-8080).' : 'Enter a valid IP or CIDR target (e.g. 192.168.10.0/24).').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    Hive.services.firewall
      .saveAlias({ originalName: state.editingAliasName, name: name, type: type, members: members, description: description })
      .then(function () {
        resetAliasForm();
        Hive.ui.notify({ title: 'Alias Saved', message: 'Alias ' + name + ' saved locally.', type: 'success' });
      });
  }

  function renderModalsHtml() {
    var ifaceMenu = buildInterfaceItems(true);
    return (
      // Add / Edit Firewall Rule Modal
      '<div class="ui small modal" id="q-fw-rule-modal" role="dialog" aria-labelledby="q-fw-modal-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-fw-modal-title"><i data-lucide="shield" class="q-icon q-text-accent"></i><span id="q-fw-modal-heading">Add Firewall Rule</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-fw-rule-form" novalidate>' +
      '      <div class="three fields">' +
      '        <div class="field"><label>nftables Chain</label>' +
      '          <div class="ui fluid selection dropdown" id="q-fw-chain-dd" data-q-manual-init>' +
      '            <input type="hidden" id="q-fw-chain" value="input"><i class="dropdown icon"></i><div class="text">Input (Router)</div>' +
      '            <div class="menu">' +
      '              <div class="item" data-value="input">Input (Router Self)</div>' +
      '              <div class="item" data-value="forward">Forward (LAN / WG ↔ WAN)</div>' +
      '            </div>' +
      '          </div>' +
      '        </div>' +
      '        <div class="field"><label>Action</label>' +
      '          <div class="ui fluid selection dropdown" id="q-fw-action-dd">' +
      '            <input type="hidden" id="q-fw-action" value="block"><i class="dropdown icon"></i><div class="text">Block</div>' +
      '            <div class="menu">' +
      '              <div class="item" data-value="pass">Pass (Accept)</div>' +
      '              <div class="item" data-value="block">Block (Drop)</div>' +
      '              <div class="item" data-value="reject">Reject</div>' +
      '            </div>' +
      '          </div>' +
      '        </div>' +
      '        <div class="field"><label>Protocol</label>' +
      '          <div class="ui fluid selection dropdown" id="q-fw-proto-dd" data-q-manual-init>' +
      '            <input type="hidden" id="q-fw-proto" value="TCP"><i class="dropdown icon"></i><div class="text">TCP</div>' +
      '            <div class="menu">' +
      '              <div class="item" data-value="TCP">TCP</div>' +
      '              <div class="item" data-value="UDP">UDP</div>' +
      '              <div class="item" data-value="ICMP">ICMP</div>' +
      '              <div class="item" data-value="ICMPV6">ICMPv6</div>' +
      '              <div class="item" data-value="ANY">ANY</div>' +
      '            </div>' +
      '          </div>' +
      '        </div>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field"><label>Inbound Interface (iifname)</label>' +
      '          <div class="ui fluid selection dropdown" id="q-fw-inif-dd">' +
      '            <input type="hidden" id="q-fw-inif" value="eth1"><i class="dropdown icon"></i><div class="text">eth1</div>' +
      '            <div class="menu">' + ifaceMenu + '</div>' +
      '          </div>' +
      '        </div>' +
      '        <div class="field" id="q-fw-outif-wrap"><label>Outbound Interface (Forward only)</label>' +
      '          <div class="ui fluid selection dropdown" id="q-fw-outif-dd">' +
      '            <input type="hidden" id="q-fw-outif" value=""><i class="dropdown icon"></i><div class="text">Any Interface</div>' +
      '            <div class="menu">' + ifaceMenu + '</div>' +
      '          </div>' +
      '        </div>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-fw-src-field"><label for="q-fw-src">Source IP / CIDR / Alias</label><input id="q-fw-src" type="text" class="q-mono" value="any" placeholder="any, 192.168.10.50, LAN_NET"><span class="q-field-error" id="q-fw-src-err" hidden>Enter any, a valid IP/CIDR, or a defined alias.</span></div>' +
      '        <div class="field required" id="q-fw-dst-field"><label for="q-fw-dst">Destination IP / CIDR / Alias</label><input id="q-fw-dst" type="text" class="q-mono" value="any" placeholder="any, 1.1.1.1, 2001:db8::/32"><span class="q-field-error" id="q-fw-dst-err" hidden>Enter any, a valid IP/CIDR, or a defined alias.</span></div>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field" id="q-fw-port-field"><label for="q-fw-port">Destination Port or Range</label><input id="q-fw-port" type="text" class="q-mono" value="443" placeholder="any, 443, 8000-8080"><span class="q-field-error" id="q-fw-port-err" hidden>Enter any, a port (1-65535), or a range (8000-8080).</span></div>' +
      '        <div class="field"><label for="q-fw-desc">Rule Name / Description</label><input id="q-fw-desc" type="text" placeholder="Block IoT camera WAN egress"></div>' +
      '      </div>' +
      '      <div class="two fields" style="margin-bottom:0;">' +
      '        <div class="field"><div class="ui toggle checkbox" id="q-fw-log-chk"><input type="checkbox" id="q-fw-log"><label for="q-fw-log">Log matched packets (rate-limited)</label></div></div>' +
      '        <div class="field"><div class="ui toggle checkbox" id="q-fw-enabled-chk"><input type="checkbox" id="q-fw-enabled" checked><label for="q-fw-enabled">Rule enabled</label></div></div>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-fw-save-btn">Stage Rule</button>' +
      '  </div>' +
      '</div>' +

      // Local Helper Aliases Modal
      '<div class="ui modal" id="q-fw-aliases-modal" role="dialog" aria-labelledby="q-fw-aliases-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-fw-aliases-title"><i data-lucide="tag" class="q-icon q-text-accent"></i><span>Local Helper Aliases</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <p class="q-text-secondary" style="margin-bottom:var(--q-space-3);">Named shortcuts resolved automatically to IP/CIDR or port targets when rules are committed to <code>10-ui-rules.nft</code>.</p>' +
      '    <div class="q-table-wrap" style="margin-bottom:var(--q-space-4);"><table class="ui compact striped table"><thead><tr><th>Alias</th><th>Type</th><th>Target</th><th>Purpose</th><th style="width:78px;">Edit</th></tr></thead><tbody id="q-fw-aliases-tbody"></tbody></table></div>' +
      '    <form class="ui form" id="q-al-form" novalidate style="padding-top:var(--q-space-3);border-top:1px solid var(--q-border-subtle);">' +
      '      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--q-space-3);">' +
      '        <strong id="q-al-form-title" style="color:var(--q-text);">Add Local Helper Alias</strong>' +
      '        <button type="button" class="ui mini button q-btn-ghost" id="q-al-cancel-edit" hidden>Cancel Edit</button>' +
      '      </div>' +
      '      <div class="three fields">' +
      '        <div class="field required" id="q-al-name-field"><label for="q-al-name">Alias Name</label><input id="q-al-name" type="text" class="q-mono" placeholder="NAS_HOST"><span class="q-field-error" id="q-al-name-err" hidden>Use 2–32 letters, digits, or underscores.</span></div>' +
      '        <div class="field"><label>Type</label><div class="ui fluid selection dropdown" id="q-al-type-dd"><input type="hidden" id="q-al-type" value="network"><i class="dropdown icon"></i><div class="text">network</div><div class="menu"><div class="item" data-value="network">network (CIDR)</div><div class="item" data-value="host">host (IP)</div><div class="item" data-value="port">port (Port / Range)</div></div></div></div>' +
      '        <div class="field required" id="q-al-mem-field"><label for="q-al-members">Target Value</label><input id="q-al-members" type="text" class="q-mono" placeholder="192.168.10.20 or 8000-8080"><span class="q-field-error" id="q-al-mem-err" hidden>Enter a valid IP/CIDR or port/range.</span></div>' +
      '      </div>' +
      '      <div style="display:flex;align-items:end;gap:12px;flex-wrap:wrap;">' +
      '        <div class="field" style="flex:1;min-width:220px;margin:0;"><label for="q-al-desc">Description</label><input id="q-al-desc" type="text" placeholder="Home NAS server"></div>' +
      '        <button type="submit" class="ui primary small button" id="q-al-save-btn" style="height:38px;">Save Alias</button>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions"><button type="button" class="ui secondary cancel button">Close</button></div>' +
      '</div>' +

      // Raw Custom .nft & Live Ruleset Inspector Modal
      '<div class="ui modal" id="q-fw-raw-modal" role="dialog" aria-labelledby="q-fw-raw-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-fw-raw-title"><i data-lucide="file-code" class="q-icon q-text-accent"></i><span>Advanced nftables Drop-In &amp; Live Ruleset</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content" id="q-fw-raw-tabs-ctx">' +
      '    <div class="ui secondary pointing menu" data-tab-context="#q-fw-raw-tabs-ctx" style="margin-bottom:var(--q-space-3);">' +
      '      <a class="item active" data-tab="dropin">Custom Drop-In (<code>00-custom.nft</code>)</a>' +
      '      <a class="item" data-tab="ruleset" id="q-fw-load-ruleset-tab">Live Kernel Ruleset (<code>nft -j</code>)</a>' +
      '    </div>' +
      '    <div class="ui tab active q-tab-plain" data-tab="dropin">' +
      '      <p class="q-text-secondary" style="margin-bottom:var(--q-space-3);">Validated with <code>nft -c -f /etc/nftables.conf</code> before activation and protected by the 60-second anti-lockout rollback timer.</p>' +
      '      <div class="ui form"><div class="field"><textarea id="q-fw-raw-editor" rows="12" class="q-mono" placeholder="# Optional custom nftables statements included inside /etc/nftables.d/00-custom.nft"></textarea></div></div>' +
      '      <div style="display:flex;justify-content:flex-end;margin-top:var(--q-space-3);">' +
      '        <button type="button" class="ui primary small button" id="q-fw-raw-save-btn"><i data-lucide="check" class="q-icon q-icon-sm"></i><span>Validate &amp; Apply Drop-In</span></button>' +
      '      </div>' +
      '    </div>' +
      '    <div class="ui tab q-tab-plain" data-tab="ruleset">' +
      '      <pre class="q-code-block" id="q-fw-ruleset-pre" style="max-height:380px;">Loading active kernel ruleset...</pre>' +
      '    </div>' +
      '  </div>' +
      '  <div class="actions"><button type="button" class="ui secondary cancel button">Close</button></div>' +
      '</div>'
    );
  }

  function renderTogglesCard() {
    if (!state.$root) return;
    var cfg = state.config || {};
    $('#q-fw-offload-chk').checkbox(cfg.flowOffload ? 'set checked' : 'set unchecked');
    $('#q-fw-tdns-chk').checkbox(cfg.transparentDns ? 'set checked' : 'set unchecked');
    $('#q-fw-wgexp-chk').checkbox(cfg.exposeWireguard ? 'set checked' : 'set unchecked');
    $('#q-fw-wgport').val(cfg.wireguardPort || 51820);

    var $badge = state.$root.find('#q-fw-offload-badge');
    if (cfg.offloadActive) {
      $badge.attr('class', 'ui label q-status-success q-mono').text('Fastpath Active');
    } else if (cfg.flowOffload) {
      $badge.attr('class', 'ui label q-status-warning q-mono').text('Configured (SQM / Pending)');
    } else {
      $badge.attr('class', 'ui label q-badge-square q-mono').text('Offload Disabled');
    }
  }

  function renderTable() {
    if (!state.$root) return;
    var rows = getFilteredRules();
    var fmt = Hive.format;
    var esc = fmt.escapeHtml;

    var $policy = state.$root.find('#q-fw-zone-policy');
    if (state.activeChain === 'all') {
      $policy.html('Showing both chains · <strong class="q-mono">' + rows.length + ' custom rules</strong>');
    } else if (state.activeChain === 'input') {
      $policy.html('Chain <code>custom_input</code> · WAN Default: <span class="ui label q-status-danger q-badge-square q-mono">DROP</span> · LAN: <span class="ui label q-status-success q-badge-square q-mono">ALLOW</span>');
    } else {
      $policy.html('Chain <code>custom_forward</code> · Evaluated before default LAN/WG → WAN accept');
    }

    var counts = { all: state.rules.length, input: 0, forward: 0 };
    state.rules.forEach(function (r) {
      var ch = r.chain === 'forward' ? 'forward' : 'input';
      counts[ch] += 1;
    });
    Object.keys(counts).forEach(function (k) {
      state.$root.find('[data-chain-count="' + k + '"]').text(counts[k]);
    });

    var isFiltered = Boolean(state.search) || state.actionFilter !== 'all';
    var $hint = state.$root.find('#q-fw-dnd-hint');
    if (isFiltered) {
      $hint.addClass('is-locked').html('<i data-lucide="lock" class="q-icon" style="width:12px;height:12px;"></i><span>Clear filters to drag &amp; reorder</span>');
    } else {
      $hint.removeClass('is-locked').html('<i data-lucide="grip-vertical" class="q-icon" style="width:12px;height:12px;"></i><span>Drag rows to reorder priority</span>');
    }

    var $tbody = state.$root.find('#q-fw-tbody');
    $tbody.find('[data-q-popup]').popup('destroy');

    if (!rows.length) {
      $tbody.html('<tr><td colspan="9" style="text-align:center;padding:28px;color:var(--q-text-muted);">No custom firewall rules configured in this view. Base hardened nftables policy remains active.</td></tr>');
      if (Hive.icons) Hive.icons.render();
      return;
    }

    var canDrag = !isFiltered && rows.length > 1;
    var html = rows
      .map(function (r, idx) {
        var rowClasses = [];
        if (canDrag) rowClasses.push('q-fw-draggable');
        if (!r.enabled) rowClasses.push('q-rule-disabled');
        if (state.matchedRuleId === r.id) rowClasses.push('q-rule-matched');
        if (state.lastReorderedId === r.id) rowClasses.push('q-rule-reordered');

        var handleAttrs = canDrag
          ? 'tabindex="0" role="button" title="Drag to reorder (or press Arrow Up / Down)" aria-label="Reorder rule ' + esc(r.id) + '"'
          : 'tabindex="-1" aria-disabled="true"';

        var chLabel = (r.chain || 'input').toUpperCase();
        var chCls = r.chain === 'forward' ? 'q-net-vpn' : 'q-net-wan';
        var ifSummary = r.inIface ? esc(r.inIface) : 'any';
        if (r.chain === 'forward' && r.outIface) {
          ifSummary += ' → ' + esc(r.outIface);
        }

        return (
          '<tr class="' + rowClasses.join(' ') + '" data-rule-id="' + esc(r.id) + '"' + (canDrag ? ' draggable="true"' : ' draggable="false"') + '>' +
          '  <td>' +
          '    <div class="q-order-cell">' +
          '      <span class="q-drag-handle' + (canDrag ? '' : ' is-disabled') + '" data-id="' + esc(r.id) + '" ' + handleAttrs + '>' +
          '        <i data-lucide="grip-vertical" class="q-icon q-icon-sm"></i>' +
          '      </span>' +
          '      <span class="q-order-badge">#' + (idx + 1) + '</span>' +
          '    </div>' +
          '  </td>' +
          '  <td><span class="ui label ' + fmt.actionBadgeClass(r.action) + ' q-badge-square q-mono">' + esc(r.action.toUpperCase()) + '</span></td>' +
          '  <td><span class="ui label ' + chCls + ' q-badge-square q-mono">' + chLabel + '</span><span class="q-rule-desc q-mono">' + ifSummary + '</span></td>' +
          '  <td class="q-mono">' + esc(r.protocol) + '</td>' +
          '  <td>' + formatEndpoint(r.source) + '</td>' +
          '  <td>' + formatEndpoint(r.destination) + (r.port && r.port !== 'any' ? ' <span class="q-text-muted">:</span> ' + formatEndpoint(r.port) : '') + '<span class="q-rule-desc">' + esc(r.description) + '</span></td>' +
          '  <td class="q-mono q-text-secondary">' + (r.log ? '<span class="ui mini label q-badge-square q-status-warning">LOG</span>' : '<span class="q-text-muted">—</span>') + '</td>' +
          '  <td><div class="ui fitted toggle checkbox q-fw-toggle" data-id="' + esc(r.id) + '"><input type="checkbox"' + (r.enabled ? ' checked' : '') + ' aria-label="Toggle rule ' + esc(r.id) + '"><label></label></div></td>' +
          '  <td>' +
          '    <div class="q-row-actions">' +
          '      <button type="button" class="ui mini icon button q-btn-ghost q-fw-edit-btn" data-id="' + esc(r.id) + '" title="Edit rule" aria-label="Edit rule ' + esc(r.id) + '"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
          '      <button type="button" class="ui mini icon button q-btn-ghost q-fw-del-btn" data-id="' + esc(r.id) + '" title="Delete rule" aria-label="Delete rule ' + esc(r.id) + '"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '    </div>' +
          '  </td>' +
          '</tr>'
        );
      })
      .join('');

    $tbody.html(html);
    if (Hive.icons) Hive.icons.render();
    if (Hive.ui) Hive.ui.init($tbody);

    if (state.refocusHandleId) {
      var targetId = state.refocusHandleId;
      state.refocusHandleId = null;
      $tbody.find('tr[data-rule-id="' + targetId + '"] .q-drag-handle').trigger('focus');
    }
  }

  function syncRuleProtoAndChain(proto, chain) {
    var p = String(proto !== undefined ? proto : ($('#q-fw-proto').val() || 'TCP')).toUpperCase();
    var c = String(chain !== undefined ? chain : ($('#q-fw-chain').val() || 'input')).toLowerCase();
    var hasPort = p === 'TCP' || p === 'UDP';
    var $port = $('#q-fw-port');
    $port.prop('disabled', !hasPort);
    if (!hasPort) $port.val('any');

    var $outDd = $('#q-fw-outif-dd');
    if (c === 'forward') {
      $outDd.removeClass('disabled');
    } else {
      $outDd.dropdown('set exactly', '').addClass('disabled');
    }
  }

  function openRuleModal(id) {
    state.editingId = id || null;
    var r = id ? state.rules.find(function (x) { return x.id === id; }) : null;
    var chain = r ? (r.chain || 'input') : (state.activeChain === 'forward' ? 'forward' : 'input');
    var proto = r ? r.protocol : 'TCP';

    $('#q-fw-modal-heading').text(r ? 'Edit Firewall Rule (' + r.id + ')' : 'Add Firewall Rule');
    $('#q-fw-chain-dd')
      .dropdown({ onChange: function (val) { syncRuleProtoAndChain(undefined, val); } })
      .dropdown('set selected', chain);
    $('#q-fw-action-dd').dropdown('set selected', r ? r.action : 'block');
    $('#q-fw-proto-dd')
      .dropdown({ onChange: function (val) { syncRuleProtoAndChain(val, undefined); } })
      .dropdown('set selected', proto);

    $('#q-fw-inif-dd').dropdown('set selected', r ? (r.inIface || '') : (chain === 'input' ? 'eth1' : 'eth0'));
    $('#q-fw-outif-dd').dropdown('set selected', r && chain === 'forward' ? (r.outIface || '') : '');

    $('#q-fw-src').val(r ? r.source : 'any');
    $('#q-fw-dst').val(r ? r.destination : 'any');
    $('#q-fw-port').val(r ? r.port : '443');
    syncRuleProtoAndChain(proto, chain);

    $('#q-fw-desc').val(r ? r.description : '');
    $('#q-fw-log-chk').checkbox(r && r.log ? 'set checked' : 'set unchecked');
    $('#q-fw-enabled-chk').checkbox(!r || r.enabled ? 'set checked' : 'set unchecked');

    $('#q-fw-src-field, #q-fw-dst-field, #q-fw-port-field').removeClass('error');
    $('#q-fw-src-err, #q-fw-dst-err, #q-fw-port-err').attr('hidden', true);

    Hive.ui.openModal('#q-fw-rule-modal');
  }

  function saveRuleModal() {
    var v = Hive.validators;
    var chain = $('#q-fw-chain').val() || 'input';
    var action = $('#q-fw-action').val() || 'block';
    var protocol = ($('#q-fw-proto').val() || 'TCP').toUpperCase();
    var inIface = $('#q-fw-inif').val() || '';
    var outIface = chain === 'forward' ? ($('#q-fw-outif').val() || '') : '';
    var source = $.trim($('#q-fw-src').val()) || 'any';
    var destination = $.trim($('#q-fw-dst').val()) || 'any';
    var hasPort = protocol === 'TCP' || protocol === 'UDP';
    var port = hasPort ? ($.trim($('#q-fw-port').val()) || 'any') : 'any';
    var description = $.trim($('#q-fw-desc').val()) || (action.toUpperCase() + ' ' + protocol + ' rule');
    var log = $('#q-fw-log').is(':checked');
    var enabled = $('#q-fw-enabled').is(':checked');

    var ok = true;
    $('#q-fw-src-field, #q-fw-dst-field, #q-fw-port-field').removeClass('error');
    $('#q-fw-src-err, #q-fw-dst-err, #q-fw-port-err').attr('hidden', true);

    if (!v.isAddressSpec(source, state.aliases)) {
      $('#q-fw-src-field').addClass('error');
      $('#q-fw-src-err').text('Enter any, a valid IP/CIDR, or a defined alias.').removeAttr('hidden');
      ok = false;
    }
    if (!v.isAddressSpec(destination, state.aliases)) {
      $('#q-fw-dst-field').addClass('error');
      $('#q-fw-dst-err').text('Enter any, a valid IP/CIDR, or a defined alias.').removeAttr('hidden');
      ok = false;
    }

    var resSrc = resolveSingleAddr(source, state.aliases);
    var resDst = resolveSingleAddr(destination, state.aliases);
    if (ok && resSrc && resDst && v.isIPv6(resSrc) !== v.isIPv6(resDst)) {
      $('#q-fw-dst-field').addClass('error');
      $('#q-fw-dst-err').text('Source and destination must use the same IP family (IPv4 or IPv6).').removeAttr('hidden');
      ok = false;
    }
    if (ok && protocol === 'ICMPV6' && ((resSrc && !v.isIPv6(resSrc)) || (resDst && !v.isIPv6(resDst)))) {
      $('#q-fw-src-field').addClass('error');
      $('#q-fw-src-err').text('ICMPv6 cannot be combined with IPv4 addresses.').removeAttr('hidden');
      ok = false;
    }
    if (hasPort && !isSingleOrRangePort(port, state.aliases)) {
      $('#q-fw-port-field').addClass('error');
      $('#q-fw-port-err').text('Enter any, a single port (443), or a range (8000-8080).').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    var zone = inIface === 'eth0' ? 'lan' : inIface === 'wg0' ? 'vpn' : 'wan';

    Hive.services.firewall
      .saveRule({
        id: state.editingId,
        chain: chain,
        inIface: inIface,
        outIface: outIface,
        zone: zone,
        action: action,
        protocol: protocol,
        source: source,
        destination: destination,
        port: port,
        log: log,
        enabled: enabled,
        description: description
      })
      .then(function () {
        $('#q-fw-rule-modal').modal('hide');
        Hive.ui.notify({
          title: 'Firewall Rule Staged',
          message: 'Rule queued in pending changes (validated via nft -c on Apply).',
          type: 'success'
        });
      });
  }

  function openRawModal() {
    $('#q-fw-raw-editor').val('Loading /etc/nftables.d/00-custom.nft...');
    $('#q-fw-ruleset-pre').text('Click tab to load live nft -j ruleset...');
    Hive.ui.openModal('#q-fw-raw-modal');
    Hive.services.firewall
      .getRaw()
      .then(function (res) {
        $('#q-fw-raw-editor').val((res && res.content) || '');
      })
      .catch(function (err) {
        $('#q-fw-raw-editor').val('# Error reading custom drop-in: ' + (err.message || err));
      });
  }

  function runPacketSimulator() {
    var chain = $('#q-sim-chain').val() || 'input';
    var inIface = $('#q-sim-inif').val() || 'eth1';
    var protocol = $('#q-sim-proto').val() || 'TCP';
    var source = $.trim($('#q-sim-src').val());
    var destination = $.trim($('#q-sim-dst').val());
    var port = $.trim($('#q-sim-port').val());

    if (!Hive.validators.isIPv4(source) || !Hive.validators.isIPv4(destination)) {
      Hive.ui.notify({
        title: 'Invalid Test Packet',
        message: 'Provide valid IPv4 addresses for both Source IP and Destination IP.',
        type: 'error'
      });
      return;
    }
    if ((protocol === 'TCP' || protocol === 'UDP') && !Hive.validators.isPortNumber(port)) {
      Hive.ui.notify({
        title: 'Invalid Destination Port',
        message: 'Enter a valid TCP/UDP destination port between 1 and 65535.',
        type: 'error'
      });
      return;
    }

    Hive.services.firewall
      .simulatePacket({ chain: chain, inIface: inIface, protocol: protocol, source: source, destination: destination, port: port })
      .then(function (res) {
        var fmt = Hive.format;
        var esc = fmt.escapeHtml;
        state.matchedRuleId = res.matched ? res.rule.id : null;

        if (state.search || state.actionFilter !== 'all') {
          state.search = '';
          state.actionFilter = 'all';
          $('#q-fw-search').val('');
          $('#q-fw-action-filter').dropdown('set selected', 'all');
        }
        if (state.activeChain !== chain) {
          state.activeChain = chain;
          state.$root.find('#q-fw-chain-tabs .item').removeClass('active').filter('[data-chain="' + chain + '"]').addClass('active');
        }
        renderTable();

        var badge = '<span class="ui label ' + fmt.actionBadgeClass(res.action) + ' q-badge-square q-mono">' + esc(res.action.toUpperCase()) + '</span>';
        var detail = res.matched
          ? 'Matched custom rule <strong class="q-mono">' + esc(res.rule.id) + '</strong> (#' + res.ruleIndex + ' in <code>' + esc(chain) + '</code>): ' + esc(res.rule.description)
          : 'No custom rule matched in <code>' + esc(chain) + '</code> — fell through to base policy (<strong class="q-mono">' + esc(res.defaultPolicy) + '</strong>).';

        state.$root
          .find('#q-sim-result')
          .html('<div>' + badge + ' <span style="margin-left:8px;">' + detail + '</span></div><button type="button" class="ui mini button q-btn-ghost" id="q-sim-clear-btn">Clear highlight</button>')
          .removeAttr('hidden');
      });
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.firewall.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.rules = data.rules || [];
      state.config = data.config || state.config;
      state.aliases = data.aliases || {};
      state.interfaces = data.interfaces || [];
      renderTogglesCard();
      renderTable();
      renderAliasesTable();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.activeChain = 'all';
    state.actionFilter = 'all';
    state.search = '';
    state.simOpen = false;
    state.matchedRuleId = null;
    state.lastReorderedId = null;
    clearDragVisuals();
    cleanupDetachedModals();

    Hive.services.firewall.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.rules = data.rules || [];
      state.config = data.config || state.config;
      state.aliases = data.aliases || {};
      state.interfaces = data.interfaces || [];

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Firewall Rules</h1>' +
        '    <p class="q-page-subtitle">Stateful <code>nftables</code> packet filtering, hardware/software flowtable offload, and custom drop-in validation.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <button type="button" class="ui basic button" id="q-fw-aliases-btn"><i data-lucide="tag" class="q-icon q-icon-sm"></i><span>Aliases</span></button>' +
        '    <button type="button" class="ui basic button" id="q-fw-raw-btn"><i data-lucide="file-code" class="q-icon q-icon-sm"></i><span>Custom .nft</span></button>' +
        '    <button type="button" class="ui basic button" id="q-fw-reload-btn"><i data-lucide="rotate-cw" class="q-icon q-icon-sm"></i><span>Reload</span></button>' +
        '    <button type="button" class="ui secondary button" id="q-fw-sim-toggle"><i data-lucide="radar" class="q-icon q-icon-sm"></i><span>Simulator</span></button>' +
        '    <button type="button" class="ui primary button" id="q-fw-add-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add Rule</span></button>' +
        '  </div>' +
        '</div>' +

        // Global Firewall Posture & Fastpath Card
        '<div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '  <div class="q-card-header" style="margin-bottom:var(--q-space-3);">' +
        '    <div>' +
        '      <h2 class="q-card-title"><i data-lucide="zap" class="q-icon q-text-accent"></i><span>Global Firewall &amp; Fastpath Toggles</span></h2>' +
        '      <p class="q-card-subtitle">Managed in <code>/etc/nftables.d/10-ui-rules.nft</code> and <code>S42nft-offload</code>.</p>' +
        '    </div>' +
        '    <span class="ui label q-mono" id="q-fw-offload-badge">—</span>' +
        '  </div>' +
        '  <form class="ui form" id="q-fw-toggles-form" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;">' +
        '    <div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap;">' +
        '      <div class="ui toggle checkbox" id="q-fw-offload-chk"><input type="checkbox" id="q-fw-offload"><label for="q-fw-offload">Gigabit Flowtable Offload</label></div>' +
        '      <div class="ui toggle checkbox" id="q-fw-tdns-chk"><input type="checkbox" id="q-fw-tdns"><label for="q-fw-tdns">Transparent LAN DNS (:53 Redirect)</label></div>' +
        '      <div class="ui toggle checkbox" id="q-fw-wgexp-chk"><input type="checkbox" id="q-fw-wgexp"><label for="q-fw-wgexp">Allow WireGuard on WAN</label></div>' +
        '      <div style="display:flex;align-items:center;gap:8px;">' +
        '        <label for="q-fw-wgport" class="q-text-secondary" style="font-size:12px;margin:0;">WG UDP Port</label>' +
        '        <input type="number" id="q-fw-wgport" class="q-mono" min="1" max="65535" style="width:92px;padding:6px 8px;" value="51820">' +
        '      </div>' +
        '    </div>' +
        '    <button type="submit" class="ui secondary small button">Stage Toggles</button>' +
        '  </form>' +
        '</div>' +

        // Collapsible Packet Match Simulator
        '<div class="q-sim-panel" id="q-fw-sim-panel"' + (state.simOpen ? '' : ' hidden') + '>' +
        '  <div class="q-card-header" style="margin-bottom:var(--q-space-3);padding-bottom:var(--q-space-2);">' +
        '    <div>' +
        '      <h2 class="q-card-title" style="font-size:var(--q-text-base);"><i data-lucide="radar" class="q-icon q-text-accent"></i><span>Packet Match Simulator</span></h2>' +
        '      <p class="q-card-subtitle">Evaluate a synthetic IPv4 packet against custom <code>input</code> or <code>forward</code> rules.</p>' +
        '    </div>' +
        '  </div>' +
        '  <form class="ui form q-sim-grid" id="q-sim-form" novalidate>' +
        '    <div class="field" style="margin:0;"><label>Chain</label>' +
        '      <div class="ui fluid selection dropdown" id="q-sim-chain-dd"><input type="hidden" id="q-sim-chain" value="input"><i class="dropdown icon"></i><div class="text">input</div>' +
        '        <div class="menu"><div class="item" data-value="input">input</div><div class="item" data-value="forward">forward</div></div>' +
        '      </div>' +
        '    </div>' +
        '    <div class="field" style="margin:0;"><label>In Interface</label>' +
        '      <div class="ui fluid selection dropdown" id="q-sim-inif-dd"><input type="hidden" id="q-sim-inif" value="eth1"><i class="dropdown icon"></i><div class="text">eth1</div>' +
        '        <div class="menu"><div class="item" data-value="eth1">eth1 (WAN)</div><div class="item" data-value="eth0">eth0 (LAN)</div><div class="item" data-value="ppp0">ppp0 (PPPoE)</div><div class="item" data-value="wg0">wg0 (VPN)</div></div>' +
        '      </div>' +
        '    </div>' +
        '    <div class="field" style="margin:0;"><label>Protocol</label>' +
        '      <div class="ui fluid selection dropdown" id="q-sim-proto-dd" data-q-manual-init><input type="hidden" id="q-sim-proto" value="TCP"><i class="dropdown icon"></i><div class="text">TCP</div>' +
        '        <div class="menu"><div class="item" data-value="TCP">TCP</div><div class="item" data-value="UDP">UDP</div><div class="item" data-value="ICMP">ICMP</div></div>' +
        '      </div>' +
        '    </div>' +
        '    <div class="field" style="margin:0;"><label for="q-sim-src">Source IP</label><input id="q-sim-src" type="text" class="q-mono" value="198.51.100.25"></div>' +
        '    <div class="field" style="margin:0;"><label for="q-sim-dst">Destination IP</label><input id="q-sim-dst" type="text" class="q-mono" value="192.168.10.1"></div>' +
        '    <div class="field" style="margin:0;"><label for="q-sim-port">Dest Port</label><input id="q-sim-port" type="number" class="q-mono" value="443"></div>' +
        '    <button type="submit" class="ui primary button" id="q-sim-run-btn" style="height:38px;">Evaluate</button>' +
        '  </form>' +
        '  <div class="q-sim-result" id="q-sim-result" hidden></div>' +
        '</div>' +

        // Chain Tabs Bar
        '<div class="q-zone-tabs-bar">' +
        '  <div class="ui secondary pointing menu" id="q-fw-chain-tabs">' +
        '    <a class="item active" data-chain="all">All Custom Rules <span class="ui label q-mono" data-chain-count="all" style="padding:1px 6px;">0</span></a>' +
        '    <a class="item" data-chain="input">Input Chain (Router) <span class="ui label q-mono" data-chain-count="input" style="padding:1px 6px;">0</span></a>' +
        '    <a class="item" data-chain="forward">Forward Chain (Transit) <span class="ui label q-mono" data-chain-count="forward" style="padding:1px 6px;">0</span></a>' +
        '  </div>' +
        '  <div class="q-zone-policy-pill" id="q-fw-zone-policy"></div>' +
        '</div>' +

        // Toolbar
        '<div class="q-toolbar">' +
        '  <div class="q-toolbar-left">' +
        '    <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-fw-search" placeholder="Search IP, interface, port, alias, description..."></div>' +
        '    <div class="ui selection dropdown" id="q-fw-action-filter" data-q-manual-init style="min-width:140px;">' +
        '      <input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Actions</div>' +
        '      <div class="menu">' +
        '        <div class="item" data-value="all">All Actions</div>' +
        '        <div class="item" data-value="pass">Pass</div>' +
        '        <div class="item" data-value="block">Block</div>' +
        '        <div class="item" data-value="reject">Reject</div>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +
        '  <div class="q-toolbar-right">' +
        '    <span class="q-dnd-hint" id="q-fw-dnd-hint"></span>' +
        '  </div>' +
        '</div>' +

        // Rules Table
        '<div class="q-table-wrap">' +
        '  <table class="ui selectable striped table">' +
        '    <thead><tr><th style="width:86px;">Order</th><th style="width:92px;">Action</th><th style="width:128px;">Chain / Iface</th><th style="width:76px;">Proto</th><th>Source</th><th>Destination &amp; Description</th><th style="width:76px;">Log</th><th style="width:66px;">State</th><th style="width:82px;">Edit</th></tr></thead>' +
        '    <tbody id="q-fw-tbody"></tbody>' +
        '  </table>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);

      $('#q-fw-action-filter').dropdown({
        onChange: function (val) {
          state.actionFilter = val || 'all';
          renderTable();
        }
      });

      $('#q-sim-proto-dd').dropdown({
        onChange: function (val) {
          var isIcmp = String(val || '').toUpperCase() === 'ICMP';
          var $port = $('#q-sim-port');
          $port.prop('disabled', isIcmp);
          if (isIcmp) $port.val('');
          else if (!$.trim($port.val())) $port.val('443');
        }
      });

      renderTogglesCard();
      renderTable();
    });

    // Global Toggles Submit
    $container.on('submit.qFirewall', '#q-fw-toggles-form', function (e) {
      e.preventDefault();
      var wgPort = Number($('#q-fw-wgport').val() || 51820);
      if (!Hive.validators.isPortNumber(wgPort)) {
        Hive.ui.notify({ title: 'Invalid WireGuard Port', message: 'Enter a UDP port between 1 and 65535.', type: 'error' });
        return;
      }
      Hive.services.firewall
        .stageToggles({
          flowOffload: $('#q-fw-offload').is(':checked'),
          transparentDns: $('#q-fw-tdns').is(':checked'),
          exposeWireguard: $('#q-fw-wgexp').is(':checked'),
          wireguardPort: wgPort
        })
        .then(function () {
          Hive.ui.notify({ title: 'Firewall Toggles Staged', message: 'Global fastpath & port toggles added to pending changes.', type: 'success' });
        });
    });

    // Drag-and-Drop Priority Reordering Events
    $container.on('mousedown.qFirewall', '#q-fw-tbody tr.q-fw-draggable', function (e) {
      state.lastMouseDownTarget = e.target;
    });

    $container.on('dragstart.qFirewall', '#q-fw-tbody tr.q-fw-draggable', function (e) {
      if (state.lastMouseDownTarget && $(state.lastMouseDownTarget).closest('button, input, a, .ui.checkbox, .q-alias-chip').length) {
        e.preventDefault();
        return;
      }
      var $row = $(this);
      var ruleId = $row.attr('data-rule-id');
      state.dragSourceId = ruleId;
      state.dragTargetId = null;
      state.dragPosition = null;

      var dt = e.originalEvent && e.originalEvent.dataTransfer;
      if (dt) {
        dt.effectAllowed = 'move';
        dt.setData('text/plain', ruleId);
      }

      window.requestAnimationFrame(function () {
        if (state.dragSourceId === ruleId) $row.addClass('is-dragging');
      });
    });

    $container.on('dragover.qFirewall', '#q-fw-tbody tr.q-fw-draggable', function (e) {
      if (!state.dragSourceId) return;
      e.preventDefault();
      var dt = e.originalEvent && e.originalEvent.dataTransfer;
      if (dt) dt.dropEffect = 'move';

      var $target = $(this);
      var targetId = $target.attr('data-rule-id');
      if (targetId === state.dragSourceId) {
        if (state.dragTargetId) {
          state.$root.find('#q-fw-tbody tr').removeClass('q-drop-before q-drop-after');
          state.dragTargetId = null;
          state.dragPosition = null;
        }
        return;
      }

      var rect = this.getBoundingClientRect();
      var clientY = e.originalEvent ? e.originalEvent.clientY : rect.top;
      var pos = clientY < rect.top + rect.height / 2 ? 'before' : 'after';

      if (state.dragTargetId !== targetId || state.dragPosition !== pos) {
        state.dragTargetId = targetId;
        state.dragPosition = pos;
        state.$root.find('#q-fw-tbody tr').removeClass('q-drop-before q-drop-after');
        $target.addClass(pos === 'before' ? 'q-drop-before' : 'q-drop-after');
      }
    });

    $container.on('dragleave.qFirewall', '#q-fw-tbody', function (e) {
      var related = e.originalEvent && e.originalEvent.relatedTarget;
      if (!related || !this.contains(related)) {
        state.$root.find('#q-fw-tbody tr').removeClass('q-drop-before q-drop-after');
        state.dragTargetId = null;
        state.dragPosition = null;
      }
    });

    $container.on('drop.qFirewall', '#q-fw-tbody tr.q-fw-draggable, #q-fw-tbody', function (e) {
      if (!state.dragSourceId) return;
      e.preventDefault();
      e.stopPropagation();

      var srcId = state.dragSourceId;
      var $row = $(this).closest('tr[data-rule-id]');
      var tgtId = ($row.length ? $row.attr('data-rule-id') : null) || state.dragTargetId;
      var pos = state.dragPosition || 'before';
      clearDragVisuals();

      if (!tgtId || srcId === tgtId) return;

      Hive.services.firewall.moveRule(srcId, tgtId, pos, state.activeChain).then(function (res) {
        if (res && res.moved) {
          scheduleReorderFlash(srcId);
          renderTable();
          Hive.ui.notify({
            title: 'Rule Priority Updated',
            message: 'Moved ' + srcId + ' from #' + res.fromIndex + ' to #' + res.toIndex + ' (staged).',
            type: 'info',
            displayTime: 2200
          });
        }
      });
    });

    $container.on('dragend.qFirewall', '#q-fw-tbody tr.q-fw-draggable', function () {
      clearDragVisuals();
      state.lastMouseDownTarget = null;
    });

    $container.on('keydown.qFirewall', '.q-drag-handle:not(.is-disabled)', function (e) {
      if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
      e.preventDefault();
      var id = $(this).attr('data-id');
      var dir = e.key === 'ArrowUp' ? 'up' : 'down';
      Hive.services.firewall.reorderRule(id, dir, state.activeChain).then(function (res) {
        if (res && res.moved) {
          state.refocusHandleId = id;
          scheduleReorderFlash(id);
          renderTable();
        }
      });
    });

    $container.on('click.qFirewall', '#q-fw-chain-tabs .item', function () {
      state.activeChain = $(this).attr('data-chain') || 'all';
      $(this).addClass('active').siblings().removeClass('active');
      renderTable();
    });

    $container.on('input.qFirewall', '#q-fw-search', function () {
      state.search = $.trim($(this).val());
      renderTable();
    });

    $container.on('click.qFirewall', '#q-fw-add-btn', function () {
      openRuleModal(null);
    });

    $container.on('click.qFirewall', '#q-fw-raw-btn', openRawModal);

    $container.on('click.qFirewall', '#q-fw-reload-btn', function () {
      var $btn = $(this);
      if ($btn.hasClass('loading')) return;
      $btn.addClass('loading disabled');
      Hive.services.firewall
        .reload()
        .then(function () {
          Hive.ui.notify({ title: 'Firewall Reloaded', message: 'S35nftables reloaded cleanly.', type: 'success' });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Reload Failed', message: err.message || 'nftables reload error', type: 'error' });
        })
        .finally(function () {
          $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qFirewall', '#q-fw-aliases-btn', function () {
      renderAliasesTable();
      resetAliasForm();
      Hive.ui.openModal('#q-fw-aliases-modal');
    });

    $container.on('click.qFirewall', '#q-fw-sim-toggle', function () {
      state.simOpen = !state.simOpen;
      var $panel = $('#q-fw-sim-panel');
      if (state.simOpen) {
        $panel.removeAttr('hidden');
      } else {
        $panel.attr('hidden', true);
        state.matchedRuleId = null;
        renderTable();
      }
    });

    $container.on('submit.qFirewall', '#q-sim-form', function (e) {
      e.preventDefault();
      runPacketSimulator();
    });

    $container.on('click.qFirewall', '#q-sim-clear-btn', function () {
      state.matchedRuleId = null;
      $('#q-sim-result').attr('hidden', true);
      renderTable();
    });

    $container.on('click.qFirewall', '.q-fw-edit-btn', function () {
      openRuleModal($(this).attr('data-id'));
    });

    $container.on('click.qFirewall', '.q-fw-del-btn', function () {
      var id = $(this).attr('data-id');
      Hive.services.firewall.deleteRule(id).then(function () {
        Hive.ui.notify({
          title: 'Rule Deletion Staged',
          message: 'Rule ' + id + ' queued for removal.',
          type: 'warning',
          displayTime: 2200
        });
      });
    });

    $container.on('change.qFirewall', '.q-fw-toggle input', function () {
      var $toggle = $(this).closest('.q-fw-toggle');
      var id = $toggle.attr('data-id');
      var enabled = this.checked;
      $toggle.closest('tr').toggleClass('q-rule-disabled', !enabled);
      Hive.services.firewall.toggleRule(id, enabled);
    });

    $(document).on('click.qFirewallModal', '#q-fw-save-btn', saveRuleModal);
    $(document).on('submit.qFirewallModal', '#q-fw-rule-form', function (e) { e.preventDefault(); saveRuleModal(); });
    $(document).on('submit.qFirewallModal', '#q-al-form', function (e) { e.preventDefault(); saveAliasForm(); });
    $(document).on('click.qFirewallModal', '#q-al-cancel-edit', resetAliasForm);
    $(document).on('click.qFirewallModal', '.q-al-edit-btn', function () {
      var name = $(this).attr('data-name');
      var a = state.aliases[name];
      if (!a) return;
      state.editingAliasName = name;
      $('#q-al-form-title').text('Edit Alias (' + name + ')');
      $('#q-al-name').val(name);
      $('#q-al-type-dd').dropdown('set selected', a.type);
      $('#q-al-members').val((a.members || []).join(', '));
      $('#q-al-desc').val(a.description || '');
      $('#q-al-save-btn').text('Update Alias');
      $('#q-al-cancel-edit').removeAttr('hidden');
    });
    $(document).on('click.qFirewallModal', '.q-al-del-btn', function () {
      var name = $(this).attr('data-name');
      Hive.services.firewall.deleteAlias(name).then(function () {
        if (state.editingAliasName === name) resetAliasForm();
        Hive.ui.notify({ title: 'Alias Removed', message: 'Alias ' + name + ' deleted.', type: 'warning' });
      });
    });

    $(document).on('click.qFirewallModal', '#q-fw-load-ruleset-tab', function () {
      $('#q-fw-ruleset-pre').text('Querying live kernel ruleset...');
      Hive.services.firewall
        .getRuleset()
        .then(function (rs) {
          $('#q-fw-ruleset-pre').text(JSON.stringify(rs, null, 2));
        })
        .catch(function (err) {
          $('#q-fw-ruleset-pre').text('Error reading ruleset: ' + (err.message || err));
        });
    });

    $(document).on('click.qFirewallModal', '#q-fw-raw-save-btn', function () {
      var $btn = $(this);
      if ($btn.hasClass('loading')) return;
      $btn.addClass('loading disabled');
      var content = $('#q-fw-raw-editor').val() || '';
      Hive.services.firewall
        .saveRaw(content)
        .then(function () {
          $('#q-fw-raw-modal').modal('hide');
          Hive.ui.notify({
            title: 'Custom Drop-In Applied',
            message: '00-custom.nft validated and loaded. Confirm within 60s in the rollback banner.',
            type: 'warning',
            displayTime: 4500
          });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'nftables Validation Failed', message: err.message || 'Syntax error in 00-custom.nft', type: 'error', displayTime: 5000 });
        })
        .finally(function () {
          $btn.removeClass('loading disabled');
        });
    });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (reason === 'telemetry' || reason === 'flows-tick' || reason === 'audit' || reason === 'kernel-log') return;
      if (reason === 'inline-toggle') {
        Hive.services.firewall.getOverview().then(function (data) {
          state.rules = data.rules || [];
          state.config = data.config || state.config;
          state.aliases = data.aliases || {};
        });
        return;
      }
      loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    if (state.reorderFlashTimer) {
      window.clearTimeout(state.reorderFlashTimer);
      state.reorderFlashTimer = null;
    }
    clearDragVisuals();
    $(document).off('.qFirewallModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qFirewall');
      state.$root = null;
    }
  }

  Hive.router.register('/security/firewall', {
    title: 'Firewall Rules',
    group: 'Security',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
