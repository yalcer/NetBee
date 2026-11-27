/* ==========================================================================
   Hive — Security Module: Ad/Tracker Block (#/security/adblock)
   AdGuardHome DNSBL Feeds, Custom Rules, 1-Click App Blocking & Query Log
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    adblock: null,
    editingFeedId: null,
    serviceSearch: '',
    querySearch: '',
    queryAction: 'all',
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-ab-feed-modal, #q-ab-rule-modal').modal('hide').remove();
  }

  function normalizeRuleDomainInput(raw, selectedType) {
    var s = String(raw || '').trim();
    var listType = selectedType || 'block';
    if (!s) return { valid: false, domain: '', listType: listType };

    // Handle /etc/hosts lines like "0.0.0.0 ads.example.com" or "127.0.0.1 tracker.net"
    var hostsMatch = s.match(/^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)$/);
    if (hostsMatch) {
      s = hostsMatch[1];
    }

    // Handle AdGuard syntax like "@@||example.com^$important" or "||example.com^"
    if (s.indexOf('@@||') === 0) {
      listType = 'allow';
      s = s.slice(4);
      var cA = s.indexOf('^');
      if (cA !== -1) s = s.slice(0, cA);
    } else if (s.indexOf('||') === 0) {
      s = s.slice(2);
      var cB = s.indexOf('^');
      if (cB !== -1) s = s.slice(0, cB);
    } else if (/^https?:\/\//i.test(s)) {
      s = s.replace(/^https?:\/\//i, '').split(/[/?#]/)[0].split(':')[0];
    }

    s = s.trim().toLowerCase().replace(/\.$/, '');
    var domainCheck = s.replace(/^\*\./, '');
    var validLabelDomain = /^(?=.{1,253}$)(?:_[a-z0-9-]+|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:_[a-z0-9-]+|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$/i.test(domainCheck);
    var isValid = Hive.validators.isDomainOrWildcard(s) || validLabelDomain;
    return { valid: isValid, domain: s, listType: listType };
  }

  function renderModalsHtml() {
    return (
      // Add / Edit Custom Blocklist Feed Modal
      '<div class="ui small modal" id="q-ab-feed-modal" role="dialog" aria-labelledby="q-ab-feed-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-ab-feed-title"><i data-lucide="list" class="q-icon q-text-accent"></i><span id="q-ab-feed-heading">Add DNSBL Filter List</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-ab-feed-form" novalidate>' +
      '      <div class="field required" id="q-ab-fname-field"><label for="q-ab-fname">Filter Name</label><input id="q-ab-fname" type="text" placeholder="OISD Big / HaGeZi Pro"><span class="q-field-error" id="q-ab-fname-err" hidden>Enter a filter list name.</span></div>' +
      '      <div class="field required" id="q-ab-furl-field" style="margin-bottom:0;"><label for="q-ab-furl">Blocklist URL (HTTP / HTTPS)</label><input id="q-ab-furl" type="url" class="q-mono" placeholder="https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"><span class="q-field-error" id="q-ab-furl-err" hidden>Enter a valid http:// or https:// URL.</span></div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-ab-feed-save-btn">Stage Filter List</button>' +
      '  </div>' +
      '</div>' +

      // Add Custom Block / Allowlist Rule Modal
      '<div class="ui small modal" id="q-ab-rule-modal" role="dialog" aria-labelledby="q-ab-rule-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-ab-rule-title"><i data-lucide="shield-alert" class="q-icon q-text-accent"></i><span>Add Custom Filtering Rule</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-ab-rule-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field"><label>Rule Action</label><div class="ui fluid selection dropdown" id="q-ab-rtype-dd"><input type="hidden" id="q-ab-rtype" value="block"><i class="dropdown icon"></i><div class="text">Block Domain (||domain^)</div><div class="menu"><div class="item" data-value="block">Block Domain (||domain^)</div><div class="item" data-value="allow">Allow Domain (@@||domain^)</div></div></div></div>' +
      '        <div class="field required" id="q-ab-rdom-field"><label for="q-ab-rdom">Domain</label><input id="q-ab-rdom" type="text" class="q-mono" placeholder="telemetry.example.com"><span class="q-field-error" id="q-ab-rdom-err" hidden>Enter a valid domain or *.wildcard domain.</span></div>' +
      '      </div>' +
      '      <div class="field" style="margin-bottom:0;"><label for="q-ab-rreason">Note (Optional)</label><input id="q-ab-rreason" type="text" placeholder="Optional note"></div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-ab-rule-save-btn">Stage Rule</button>' +
      '  </div>' +
      '</div>'
    );
  }

  function updateKpis() {
    if (!state.$root || !state.adblock) return;
    var ab = state.adblock;
    var fmt = Hive.format;

    var activeRules = (ab.feeds || []).reduce(function (sum, f) { return sum + (f.enabled ? Number(f.domains || 0) : 0); }, 0) + (ab.customBlocked || []).length;
    var activeFeeds = (ab.feeds || []).filter(function (f) { return f.enabled; }).length;
    var blockedServicesCount = (ab.blockedServices || []).length;

    state.$root.find('#q-ab-kpi-status').html(
      ab.enabled
        ? '<span class="q-text-success">Protected</span>'
        : '<span class="q-text-warning">Paused</span>'
    );
    state.$root.find('#q-ab-kpi-running').text(ab.running ? 'AdGuardHome running' : 'Daemon offline');
    state.$root.find('#q-ab-kpi-blocked').text(fmt.number(ab.blockedToday || 0));
    state.$root.find('#q-ab-kpi-pct').text((ab.blockedPercent || 0) + '% of ' + fmt.number(ab.queriesToday || 0) + ' queries');
    state.$root.find('#q-ab-kpi-domains').text(fmt.number(activeRules));
    state.$root.find('#q-ab-kpi-feeds-sub').text(activeFeeds + '/' + (ab.feeds || []).length + ' lists · ' + blockedServicesCount + ' apps blocked');
    state.$root.find('#q-ab-kpi-latency').text((ab.avgLatencyMs || 0) + ' ms');
    state.$root.find('#q-ab-kpi-forcedns').html(ab.forceDns ? '<span class="q-text-success">Force :53 On</span>' : '<span class="q-text-muted">Force :53 Off</span>');
  }

  function renderBlockedServicesGrid() {
    if (!state.$root || !state.adblock) return;
    var esc = Hive.format.escapeHtml;
    var ab = state.adblock;
    var blockedSet = {};
    (ab.blockedServices || []).forEach(function (id) { blockedSet[id] = true; });

    var catalog = ab.availableServices && ab.availableServices.length
      ? ab.availableServices
      : [
          { id: 'youtube', name: 'YouTube' },
          { id: 'tiktok', name: 'TikTok' },
          { id: 'instagram', name: 'Instagram' },
          { id: 'facebook', name: 'Facebook' },
          { id: 'discord', name: 'Discord' },
          { id: 'snapchat', name: 'Snapchat' },
          { id: 'twitch', name: 'Twitch' },
          { id: 'netflix', name: 'Netflix' },
          { id: 'steam', name: 'Steam' },
          { id: 'roblox', name: 'Roblox' },
          { id: 'epic_games', name: 'Epic Games' },
          { id: 'reddit', name: 'Reddit' }
        ];

    var q = state.serviceSearch.toLowerCase();
    var filtered = catalog.filter(function (s) {
      return !q || s.name.toLowerCase().indexOf(q) !== -1 || s.id.toLowerCase().indexOf(q) !== -1;
    });

    state.$root.find('[data-ab-count="services"]').text((ab.blockedServices || []).length);

    var $grid = state.$root.find('#q-ab-services-grid');
    if (!filtered.length) {
      $grid.html('<div style="grid-column:1/-1;padding:24px;text-align:center;color:var(--q-text-muted);">No services match "' + esc(state.serviceSearch) + '".</div>');
      return;
    }

    var html = filtered
      .map(function (svc) {
        var isBlk = Boolean(blockedSet[svc.id]);
        return (
          '<div class="q-service-block-item' + (isBlk ? ' is-blocked' : '') + '" data-svc-card="' + esc(svc.id) + '" role="group" aria-label="' + esc(svc.name) + '">' +
          '  <div style="cursor:pointer;">' +
          '    <div style="font-weight:600;color:var(--q-text);">' + esc(svc.name) + '</div>' +
          '    <div class="q-mono q-text-muted" style="font-size:11px;">' + esc(svc.id) + '</div>' +
          '  </div>' +
          '  <div class="ui fitted toggle checkbox q-ab-svc-toggle" data-svc-id="' + esc(svc.id) + '">' +
          '    <input type="checkbox"' + (isBlk ? ' checked' : '') + ' aria-label="Block ' + esc(svc.name) + '"><label></label>' +
          '  </div>' +
          '</div>'
        );
      })
      .join('');
    $grid.html(html);
    $grid.find('.ui.checkbox').checkbox();
  }

  function renderQueryLog() {
    if (!state.$root || !state.adblock) return;
    var esc = Hive.format.escapeHtml;
    var q = state.querySearch.toLowerCase();
    var rows = (state.adblock.queryLog || []).filter(function (r) {
      if (state.queryAction === 'blocked' && r.action !== 'blocked') return false;
      if (state.queryAction === 'allowed' && r.action === 'blocked') return false;
      if (q && (r.domain + ' ' + r.clientName + ' ' + r.clientIp + ' ' + r.source).toLowerCase().indexOf(q) === -1) return false;
      return true;
    });

    var $tbody = state.$root.find('#q-ab-qlog-tbody');
    if (!rows.length) {
      $tbody.html('<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--q-text-muted);">No DNS queries recorded matching the current filter.</td></tr>');
      return;
    }

    var html = rows
      .map(function (r) {
        var isBlocked = r.action === 'blocked';
        var alreadyAllowed = (state.adblock.allowlist || []).some(function (a) { return a.domain.toLowerCase() === r.domain.toLowerCase(); });
        var alreadyBlocked = (state.adblock.customBlocked || []).some(function (b) { return b.domain.toLowerCase() === r.domain.toLowerCase(); });

        var actionBtn = isBlocked
          ? (alreadyAllowed
              ? '<span class="ui mini label q-status-success">Allowlisted</span>'
              : '<button type="button" class="ui mini secondary button q-ab-quick-allow" data-domain="' + esc(r.domain) + '">Allow</button>')
          : (alreadyBlocked
              ? '<span class="ui mini label q-status-danger">Blocked</span>'
              : '<button type="button" class="ui mini basic negative button q-ab-quick-block" data-domain="' + esc(r.domain) + '">Block</button>');

        return (
          '<tr>' +
          '  <td class="q-mono q-text-muted">' + esc(r.time) + '</td>' +
          '  <td><strong class="q-mono">' + esc(r.clientIp) + '</strong>' + (r.clientName && r.clientName !== r.clientIp ? '<span class="q-rule-desc">' + esc(r.clientName) + '</span>' : '') + '</td>' +
          '  <td class="q-mono"><strong>' + esc(r.domain) + '</strong> <span class="q-text-muted">(' + esc(r.type) + ')</span></td>' +
          '  <td><span class="ui label ' + (isBlocked ? 'q-status-danger' : 'q-status-success') + '"><span class="q-status-dot ' + (isBlocked ? 'is-danger' : 'is-success') + '"></span>' + (isBlocked ? 'Blocked' : 'Resolved') + '</span></td>' +
          '  <td class="q-text-secondary">' + esc(r.source) + '<span class="q-rule-desc q-mono">' + r.latencyMs + ' ms</span></td>' +
          '  <td>' + actionBtn + '</td>' +
          '</tr>'
        );
      })
      .join('');
    $tbody.html(html);
  }

  function renderAllTabs() {
    if (!state.$root || !state.adblock) return;
    var ab = state.adblock;
    var fmt = Hive.format;
    var esc = fmt.escapeHtml;

    $('#q-ab-enabled-chk').checkbox(ab.enabled ? 'set checked' : 'set unchecked');
    $('#q-ab-force-chk').checkbox(ab.forceDns ? 'set checked' : 'set unchecked');
    state.$root.find('[data-ab-count="feeds"]').text((ab.feeds || []).length);
    state.$root.find('[data-ab-count="rules"]').text((ab.customBlocked || []).length + (ab.allowlist || []).length);
    updateKpis();

    // Tab 1: Blocklist Feeds
    var feedRows = (ab.feeds || [])
      .map(function (f) {
        return (
          '<tr class="' + (f.enabled ? '' : 'q-rule-disabled') + '">' +
          '  <td><strong>' + esc(f.name) + '</strong><span class="q-rule-desc q-mono">' + esc(f.url) + '</span></td>' +
          '  <td class="q-mono">' + fmt.number(f.domains) + '</td>' +
          '  <td class="q-mono q-text-muted">' + esc(f.lastUpdated) + '</td>' +
          '  <td><div class="ui fitted toggle checkbox q-ab-feed-toggle" data-id="' + esc(f.id) + '"><input type="checkbox"' + (f.enabled ? ' checked' : '') + ' aria-label="Toggle feed ' + esc(f.name) + '"><label></label></div></td>' +
          '  <td><div class="q-row-actions">' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-ab-feed-edit" data-id="' + esc(f.id) + '" aria-label="Edit filter list ' + esc(f.name) + '"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-ab-feed-del" data-id="' + esc(f.id) + '" aria-label="Remove filter list ' + esc(f.name) + '"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-ab-feeds-tbody').html(feedRows || '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--q-text-muted);">No blocklist feeds configured.</td></tr>');

    // Tab 2: Custom Blocked & Allowlist Tables
    var blkRows = (ab.customBlocked || [])
      .map(function (r) {
        return (
          '<tr>' +
          '  <td class="q-mono"><strong>' + esc(r.domain) + '</strong><span class="q-rule-desc">' + esc(r.reason) + '</span></td>' +
          '  <td class="q-mono q-text-muted">' + esc(r.addedAt) + '</td>' +
          '  <td><button type="button" class="ui mini icon button q-btn-ghost q-ab-rule-del" data-list="block" data-id="' + esc(r.id) + '" aria-label="Delete blocked domain"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-ab-blk-tbody').html(blkRows || '<tr><td colspan="3" style="text-align:center;padding:20px;color:var(--q-text-muted);">No custom blocked domains.</td></tr>');

    var alwRows = (ab.allowlist || [])
      .map(function (r) {
        return (
          '<tr>' +
          '  <td class="q-mono"><strong>' + esc(r.domain) + '</strong><span class="q-rule-desc">' + esc(r.reason) + '</span></td>' +
          '  <td class="q-mono q-text-muted">' + esc(r.addedAt) + '</td>' +
          '  <td><button type="button" class="ui mini icon button q-btn-ghost q-ab-rule-del" data-list="allow" data-id="' + esc(r.id) + '" aria-label="Delete allowlist domain"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-ab-alw-tbody').html(alwRows || '<tr><td colspan="3" style="text-align:center;padding:20px;color:var(--q-text-muted);">No allowlist exceptions configured.</td></tr>');

    renderBlockedServicesGrid();
    renderQueryLog();

    if (Hive.icons) Hive.icons.render();
    state.$root.find('#q-ab-feeds-tbody .ui.checkbox').checkbox();
  }

  function openFeedModal(id) {
    state.editingFeedId = id || null;
    var f = id && state.adblock && state.adblock.feeds
      ? state.adblock.feeds.find(function (x) { return x.id === id; })
      : null;
    $('#q-ab-feed-heading').text(f ? 'Edit DNSBL Filter List' : 'Add DNSBL Filter List');
    $('#q-ab-fname').val(f ? f.name : '');
    $('#q-ab-furl').val(f ? f.url : '');
    $('#q-ab-fname-field, #q-ab-furl-field').removeClass('error');
    $('#q-ab-fname-err').text('Enter a filter list name.').attr('hidden', true);
    $('#q-ab-furl-err').text('Enter a valid http:// or https:// URL.').attr('hidden', true);
    Hive.ui.openModal('#q-ab-feed-modal');
  }

  function saveFeedModal() {
    var name = $.trim($('#q-ab-fname').val());
    var url = $.trim($('#q-ab-furl').val());
    var ok = true;
    $('#q-ab-fname-field, #q-ab-furl-field').removeClass('error');
    $('#q-ab-fname-err, #q-ab-furl-err').attr('hidden', true);
    if (!name) { $('#q-ab-fname-field').addClass('error'); $('#q-ab-fname-err').removeAttr('hidden'); ok = false; }
    if (!Hive.validators.isHttpUrl(url)) { $('#q-ab-furl-field').addClass('error'); $('#q-ab-furl-err').text('Enter a valid http:// or https:// URL.').removeAttr('hidden'); ok = false; }
    if (!ok) return;

    Hive.services.adblock.saveFeed({ id: state.editingFeedId, name: name, url: url }).then(function (res) {
      if (res && res.ok === false) {
        $('#q-ab-furl-field').addClass('error');
        $('#q-ab-furl-err').text(res.reason || 'Duplicate filter URL.').removeAttr('hidden');
        return;
      }
      $('#q-ab-feed-modal').modal('hide');
      Hive.ui.notify({
        title: state.editingFeedId ? 'Filter List Updated' : 'Filter List Staged',
        message: '"' + name + '" queued in pending changes.',
        type: 'success'
      });
    });
  }

  function saveRuleModal() {
    var selectedType = $('#q-ab-rtype').val() || 'block';
    var parsed = normalizeRuleDomainInput($('#q-ab-rdom').val(), selectedType);
    var reason = $.trim($('#q-ab-rreason').val());
    $('#q-ab-rdom-field').removeClass('error');
    $('#q-ab-rdom-err').text('Enter a valid domain (e.g. ads.example.com, *.example.com, or ||domain^).').attr('hidden', true);

    if (!parsed.valid) {
      $('#q-ab-rdom-field').addClass('error');
      $('#q-ab-rdom-err').removeAttr('hidden');
      return;
    }

    Hive.services.adblock.addRule(parsed.listType, { domain: parsed.domain, reason: reason }).then(function (res) {
      if (!res.ok) {
        $('#q-ab-rdom-field').addClass('error');
        $('#q-ab-rdom-err').text(res.reason).removeAttr('hidden');
        return;
      }
      $('#q-ab-rule-modal').modal('hide');
      $('#q-ab-tabs-ctx .ui.menu .item[data-tab="rules"]').tab('change tab', 'rules');
      Hive.ui.notify({
        title: parsed.listType === 'allow' ? 'Allowlist Rule Staged' : 'Block Rule Staged',
        message: parsed.domain + ' queued for commit.',
        type: 'success'
      });
    });
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.adblock.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.adblock = data;
      renderAllTabs();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.serviceSearch = '';
    state.querySearch = '';
    state.queryAction = 'all';
    cleanupDetachedModals();

    Hive.services.adblock.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.adblock = data;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Ad/Tracker Block</h1>' +
        '    <p class="q-page-subtitle">AdGuardHome network-wide DNS filtering, 1-click app blocking, and live LAN query inspection.</p>' +
        '  </div>' +
        '  <div class="q-page-actions">' +
        '    <div class="ui toggle checkbox" id="q-ab-enabled-chk" style="margin-right:8px;"><input type="checkbox" id="q-ab-enabled"><label for="q-ab-enabled">DNS Protection</label></div>' +
        '    <button type="button" class="ui secondary button" id="q-ab-refresh-btn"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Update Lists</span></button>' +
        '    <button type="button" class="ui primary button" id="q-ab-open-rule-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add Domain Rule</span></button>' +
        '  </div>' +
        '</div>' +

        // KPI Strip
        '<div class="q-kpi-grid">' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Protection Status</span><span class="q-kpi-icon"><i data-lucide="shield-alert" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-ab-kpi-status">—</div><div class="q-kpi-sub"><span id="q-ab-kpi-running"></span><span>:53</span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Blocked Queries</span><span class="q-kpi-icon"><i data-lucide="activity" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-ab-kpi-blocked">0</div><div class="q-kpi-sub"><span id="q-ab-kpi-pct"></span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Active Filter Rules</span><span class="q-kpi-icon"><i data-lucide="list" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-ab-kpi-domains">0</div><div class="q-kpi-sub"><span id="q-ab-kpi-feeds-sub"></span></div></div>' +
        '  <div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Avg DNS Latency</span><span class="q-kpi-icon"><i data-lucide="globe" class="q-icon q-icon-sm"></i></span></div><div class="q-kpi-value" id="q-ab-kpi-latency">0 ms</div><div class="q-kpi-sub"><span id="q-ab-kpi-forcedns"></span></div></div>' +
        '</div>' +

        '<div id="q-ab-tabs-ctx">' +
        '  <div class="q-zone-tabs-bar">' +
        '    <div class="ui secondary pointing menu" data-tab-context="#q-ab-tabs-ctx">' +
        '      <a class="item active" data-tab="feeds">Blocklist Feeds <span class="ui label q-mono" data-ab-count="feeds">0</span></a>' +
        '      <a class="item" data-tab="rules">Custom Rules &amp; Allowlist <span class="ui label q-mono" data-ab-count="rules">0</span></a>' +
        '      <a class="item" data-tab="services">Blocked Apps <span class="ui label q-mono" data-ab-count="services">0</span></a>' +
        '      <a class="item" data-tab="queries">Live Query Log</a>' +
        '    </div>' +
        '  </div>' +

        // Tab 1: Blocklist Feeds
        '  <div class="ui tab active q-tab-plain" data-tab="feeds">' +
        '    <div class="q-card">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title">Subscribed AdGuard / Hosts Filter Lists</h2><p class="q-card-subtitle">Toggle DNSBL subscriptions or add custom filter URLs.</p></div><button type="button" class="ui mini secondary button" id="q-ab-open-feed-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add Filter List</span></button></div>' +
        '      <div class="q-table-wrap"><table class="ui selectable striped table"><thead><tr><th>Filter Name &amp; URL</th><th style="width:120px;">Rules</th><th style="width:160px;">Last Synced</th><th style="width:66px;">State</th><th style="width:86px;">Edit</th></tr></thead><tbody id="q-ab-feeds-tbody"></tbody></table></div>' +
        '    </div>' +
        '  </div>' +

        // Tab 2: Custom Rules & Allowlist
        '  <div class="ui tab q-tab-plain" data-tab="rules">' +
        '    <div class="q-ab-rules-grid">' +
        '      <div class="q-card">' +
        '        <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="shield-alert" class="q-icon q-text-danger"></i><span>Custom Blocked Domains</span></h2><p class="q-card-subtitle">Compiled as <code>||domain^</code> user rules in AdGuardHome.</p></div></div>' +
        '        <div class="q-table-wrap"><table class="ui striped table"><thead><tr><th>Domain &amp; Note</th><th style="width:94px;">Status</th><th style="width:52px;">Del</th></tr></thead><tbody id="q-ab-blk-tbody"></tbody></table></div>' +
        '      </div>' +
        '      <div class="q-card">' +
        '        <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="shield-check" class="q-icon q-text-success"></i><span>Allowlist Exceptions</span></h2><p class="q-card-subtitle">Compiled as <code>@@||domain^</code> overrides bypassing blocklists.</p></div></div>' +
        '        <div class="q-table-wrap"><table class="ui striped table"><thead><tr><th>Domain &amp; Note</th><th style="width:94px;">Status</th><th style="width:52px;">Del</th></tr></thead><tbody id="q-ab-alw-tbody"></tbody></table></div>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +

        // Tab 3: Blocked Services (1-Click App Blocking)
        '  <div class="ui tab q-tab-plain" data-tab="services">' +
        '    <div class="q-card">' +
        '      <div class="q-toolbar">' +
        '        <div class="q-toolbar-left">' +
        '          <div><h2 class="q-card-title">1-Click Service &amp; Application Blocking</h2><p class="q-card-subtitle">Block entire platforms (all associated CDN/API domains) across LAN &amp; WireGuard clients.</p></div>' +
        '        </div>' +
        '        <div class="q-toolbar-right">' +
        '          <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-ab-svc-search" placeholder="Search YouTube, TikTok, Steam..."></div>' +
        '        </div>' +
        '      </div>' +
        '      <div class="q-service-block-grid" id="q-ab-services-grid"></div>' +
        '    </div>' +
        '  </div>' +

        // Tab 4: Live Query Log & Transparent DNS Redirect
        '  <div class="ui tab q-tab-plain" data-tab="queries">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;">' +
        '        <div>' +
        '          <h2 class="q-card-title" style="margin-bottom:4px;">Force Router DNS (Intercept Hardcoded :53 Bypasses)</h2>' +
        '          <p class="q-card-subtitle">Redirects any LAN TCP/UDP port 53 traffic aimed at external DNS servers transparently into NetBee OS AdGuardHome via <code>nftables</code>.</p>' +
        '        </div>' +
        '        <div class="ui toggle checkbox" id="q-ab-force-chk"><input type="checkbox" id="q-ab-force"><label for="q-ab-force">Transparent :53 Redirect</label></div>' +
        '      </div>' +
        '    </div>' +

        '    <div class="q-card">' +
        '      <div class="q-toolbar">' +
        '        <div class="q-toolbar-left">' +
        '          <h2 class="q-card-title" style="margin-right:12px;">Recent DNS Queries</h2>' +
        '          <div class="ui input q-input-icon"><i data-lucide="search" class="q-icon"></i><input type="search" id="q-ab-qsearch" placeholder="Search domain, client IP, reason..."></div>' +
        '          <div class="ui selection dropdown" id="q-ab-qact-dd" data-q-manual-init style="min-width:136px;"><input type="hidden" value="all"><i class="dropdown icon"></i><div class="text">All Queries</div><div class="menu"><div class="item" data-value="all">All Queries</div><div class="item" data-value="blocked">Blocked Only</div><div class="item" data-value="allowed">Resolved Only</div></div></div>' +
        '        </div>' +
        '        <div class="q-toolbar-right">' +
        '          <button type="button" class="ui mini basic button" id="q-ab-qlog-refresh"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Refresh Log</span></button>' +
        '        </div>' +
        '      </div>' +
        '      <div class="q-table-wrap"><table class="ui selectable striped table"><thead><tr><th style="width:86px;">Time</th><th>Client</th><th>Queried Domain</th><th style="width:112px;">Status</th><th>Filter / Latency</th><th style="width:94px;">Quick Rule</th></tr></thead><tbody id="q-ab-qlog-tbody"></tbody></table></div>' +
        '    </div>' +
        '  </div>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);

      $('#q-ab-qact-dd').dropdown({ onChange: function (v) { state.queryAction = v || 'all'; renderQueryLog(); } });
      renderAllTabs();
    });

    $container.on('change.qAdblock', '#q-ab-enabled', function () {
      var enabled = this.checked;
      if (state.adblock) state.adblock.enabled = enabled;
      updateKpis();
      Hive.services.adblock.toggleEnabled(enabled).then(function () {
        Hive.ui.notify({ title: 'DNS Protection Staged', message: 'Protection ' + (enabled ? 'enabled' : 'paused') + ' in pending changes.', type: 'info', displayTime: 2200 });
      });
    });

    $container.on('change.qAdblock', '#q-ab-force', function () {
      var enabled = this.checked;
      if (state.adblock) state.adblock.forceDns = enabled;
      updateKpis();
      Hive.services.adblock.toggleForceDns(enabled).then(function () {
        Hive.ui.notify({ title: 'Transparent DNS Staged', message: 'Port 53 redirect ' + (enabled ? 'enabled' : 'disabled') + ' in pending changes.', type: 'info', displayTime: 2200 });
      });
    });

    $container.on('change.qAdblock', '.q-ab-feed-toggle input', function () {
      var $toggle = $(this).closest('.q-ab-feed-toggle');
      var id = $toggle.attr('data-id');
      var enabled = this.checked;
      $toggle.closest('tr').toggleClass('q-rule-disabled', !enabled);
      Hive.services.adblock.toggleFeed(id, enabled);
    });

    $container.on('click.qAdblock', '.q-service-block-item', function (e) {
      if ($(e.target).closest('.q-ab-svc-toggle').length) return;
      $(this).find('.q-ab-svc-toggle').checkbox('toggle');
    });

    $container.on('change.qAdblock', '.q-ab-svc-toggle input', function () {
      var $toggle = $(this).closest('.q-ab-svc-toggle');
      var svcId = $toggle.attr('data-svc-id');
      var blocked = this.checked;
      $toggle.closest('.q-service-block-item').toggleClass('is-blocked', blocked);
      Hive.services.adblock.toggleBlockedService(svcId, blocked);
    });

    $container.on('input.qAdblock', '#q-ab-svc-search', function () {
      state.serviceSearch = $.trim($(this).val());
      renderBlockedServicesGrid();
    });

    $container.on('click.qAdblock', '#q-ab-refresh-btn', function () {
      var $btn = $(this);
      if ($btn.hasClass('loading')) return;
      $btn.addClass('loading disabled');
      Hive.services.adblock
        .refreshFeeds()
        .then(function () {
          Hive.ui.notify({ title: 'Filter Lists Synced', message: 'AdGuardHome refreshed all active DNSBL subscriptions.', type: 'success' });
          loadAndRender();
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Refresh Failed', message: err.message || 'Could not refresh filter lists.', type: 'error' });
        })
        .finally(function () {
          if (state.$root) $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qAdblock', '#q-ab-qlog-refresh', function () {
      var $btn = $(this);
      if ($btn.hasClass('loading')) return;
      $btn.addClass('loading disabled');
      Hive.services.adblock
        .refreshQueryLog()
        .then(function (data) {
          if (!state.$root) return;
          state.adblock = data;
          updateKpis();
          renderQueryLog();
          Hive.ui.notify({ title: 'Query Log Refreshed', message: 'Fetched latest DNS queries and counters.', type: 'info', displayTime: 1800 });
        })
        .finally(function () {
          if (state.$root) $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qAdblock', '#q-ab-open-feed-btn', function () {
      openFeedModal(null);
    });

    $container.on('click.qAdblock', '.q-ab-feed-edit', function () {
      openFeedModal($(this).attr('data-id'));
    });

    $container.on('click.qAdblock', '#q-ab-open-rule-btn', function () {
      $('#q-ab-rdom, #q-ab-rreason').val('');
      $('#q-ab-rdom-field').removeClass('error');
      $('#q-ab-rdom-err').attr('hidden', true);
      Hive.ui.openModal('#q-ab-rule-modal');
    });

    $container.on('click.qAdblock', '.q-ab-feed-del', function () {
      Hive.services.adblock.deleteFeed($(this).attr('data-id')).then(function () {
        Hive.ui.notify({ title: 'Filter List Removal Staged', message: 'Subscription queued for removal.', type: 'warning' });
      });
    });

    $container.on('click.qAdblock', '.q-ab-rule-del', function () {
      var listType = $(this).attr('data-list');
      Hive.services.adblock.deleteRule(listType, $(this).attr('data-id')).then(function () {
        Hive.ui.notify({ title: 'Rule Removal Staged', message: 'Domain rule queued for deletion.', type: 'warning' });
      });
    });

    $container.on('click.qAdblock', '.q-ab-quick-allow', function () {
      var dom = $(this).attr('data-domain');
      Hive.services.adblock.addRule('allow', { domain: dom, reason: 'Allowed from query log' }).then(function (res) {
        if (res.ok) Hive.ui.notify({ title: 'Allowlist Staged', message: dom + ' added to Allowlist exceptions.', type: 'success' });
      });
    });

    $container.on('click.qAdblock', '.q-ab-quick-block', function () {
      var dom = $(this).attr('data-domain');
      Hive.services.adblock.addRule('block', { domain: dom, reason: 'Blocked from query log' }).then(function (res) {
        if (res.ok) Hive.ui.notify({ title: 'Block Rule Staged', message: dom + ' added to Custom Blocked Domains.', type: 'warning' });
      });
    });

    $container.on('input.qAdblock', '#q-ab-qsearch', function () {
      state.querySearch = $.trim($(this).val());
      renderQueryLog();
    });

    $(document).on('click.qAdblockModal', '#q-ab-feed-save-btn', saveFeedModal);
    $(document).on('click.qAdblockModal', '#q-ab-rule-save-btn', saveRuleModal);
    $(document).on('submit.qAdblockModal', '#q-ab-feed-form', function (e) { e.preventDefault(); saveFeedModal(); });
    $(document).on('submit.qAdblockModal', '#q-ab-rule-form', function (e) { e.preventDefault(); saveRuleModal(); });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (Hive.store.isRuntimeOnlyReason(reason)) return;
      if (reason === 'inline-toggle') {
        state.adblock = JSON.parse(JSON.stringify(Hive.store.getState().adblock));
        if (state.$root) {
          state.$root.find('[data-ab-count="feeds"]').text((state.adblock.feeds || []).length);
          state.$root.find('[data-ab-count="services"]').text((state.adblock.blockedServices || []).length);
          $('#q-ab-enabled-chk').checkbox(state.adblock.enabled ? 'set checked' : 'set unchecked');
          $('#q-ab-force-chk').checkbox(state.adblock.forceDns ? 'set checked' : 'set unchecked');
          updateKpis();
        }
        return;
      }
      state.adblock = JSON.parse(JSON.stringify(Hive.store.getState().adblock));
      renderAllTabs();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    $(document).off('.qAdblockModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qAdblock');
      state.$root = null;
    }
  }

  Hive.router.register('/security/adblock', {
    title: 'Ad/Tracker Block',
    group: 'Security',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
