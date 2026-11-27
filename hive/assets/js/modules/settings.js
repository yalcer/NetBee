/* ==========================================================================
   Hive — System Module: General & Services (#/system/settings)
   Hostname/Timezone/Chrony NTP, 17 System Daemons, Crond & Kernel Sysctl
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var CRON_SERVICE_TARGETS = [
    'adguardhome',
    'chronyd',
    'dhcpcd',
    'dropbear',
    'radvd',
    'vnstatd',
    'sqm',
    'nftables',
    'nft-offload'
  ];

  var state = {
    $root: null,
    mountToken: 0,
    data: null,
    editingCronId: null,
    pendingPowerAction: null,
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-cron-modal, #q-power-modal').modal('hide').remove();
  }

  function validCronExpr(expr) {
    var s = $.trim(expr || '');
    if (!s || /[#;\r\n]/.test(s)) return false;
    var parts = s.split(/\s+/);
    if (parts.length !== 5) return false;
    return parts.every(function (p) { return /^[0-9*,/-]+$/.test(p); });
  }

  function renderModalsHtml() {
    var esc = Hive.format.escapeHtml;
    var actions = (state.data && state.data.cron && state.data.cron.supportedActions) || [];
    if (!actions.length) {
      actions = [
        { action: 'wan_reconnect', description: 'Reconnect WAN (renew DHCP or redial PPPoE/ONT)', needs_target: false },
        { action: 'firewall_reload', description: 'Reload nftables firewall ruleset', needs_target: false },
        { action: 'sqm_start', description: 'Enable/restart SQM CAKE traffic shaping', needs_target: false },
        { action: 'sqm_stop', description: 'Stop SQM CAKE and re-enable gigabit flow offload', needs_target: false },
        { action: 'logs_rotate', description: 'Force immediate RAM syslog rotation', needs_target: false },
        { action: 'conntrack_flush', description: 'Flush active NAT/conntrack session table', needs_target: false },
        { action: 'service_restart', description: 'Restart a specific managed service', needs_target: true },
        { action: 'reboot', description: 'Reboot the router cleanly', needs_target: false }
      ];
    }

    var actionMenu = actions
      .map(function (a) {
        return '<div class="item" data-value="' + esc(a.action) + '"><span class="q-mono">' + esc(a.action) + '</span> — ' + esc(a.description) + '</div>';
      })
      .join('');

    var targetMenu = CRON_SERVICE_TARGETS
      .map(function (svc) {
        return '<div class="item" data-value="' + esc(svc) + '"><span class="q-mono">' + esc(svc) + '</span></div>';
      })
      .join('');

    return (
      // Scheduled Task (Cron) Modal
      '<div class="ui small modal" id="q-cron-modal" role="dialog" aria-labelledby="q-cron-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-cron-title"><i data-lucide="clock" class="q-icon q-text-accent"></i><span id="q-cron-heading">Add Scheduled Task</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-cron-form" novalidate>' +
      '      <div class="two fields">' +
      '        <div class="field required" id="q-cron-name-field">' +
      '          <label for="q-cron-name">Task Name</label>' +
      '          <input id="q-cron-name" type="text" placeholder="Nightly PPPoE Reconnect">' +
      '          <span class="q-field-error" id="q-cron-name-err" hidden>Enter a safe task name (1–64 chars).</span>' +
      '        </div>' +
      '        <div class="field required" id="q-cron-sched-field">' +
      '          <label for="q-cron-sched">5-Field Cron Schedule (min hour dom mon dow)</label>' +
      '          <input id="q-cron-sched" type="text" class="q-mono" value="0 4 * * *" placeholder="0 4 * * *">' +
      '          <span class="q-field-error" id="q-cron-sched-err" hidden>Enter a valid 5-field cron expression, e.g. 0 4 * * *.</span>' +
      '        </div>' +
      '      </div>' +
      '      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:var(--q-space-3);">' +
      '        <button type="button" class="ui mini basic button q-cron-preset" data-expr="0 4 * * *">Daily 04:00</button>' +
      '        <button type="button" class="ui mini basic button q-cron-preset" data-expr="0 4 * * 0">Weekly Sun 04:00</button>' +
      '        <button type="button" class="ui mini basic button q-cron-preset" data-expr="*/30 * * * *">Every 30 min</button>' +
      '        <button type="button" class="ui mini basic button q-cron-preset" data-expr="0 */6 * * *">Every 6 hours</button>' +
      '      </div>' +
      '      <div class="two fields">' +
      '        <div class="field">' +
      '          <label>Whitelisted Router Action</label>' +
      '          <div class="ui fluid selection dropdown" id="q-cron-action-dd" data-q-manual-init>' +
      '            <input type="hidden" id="q-cron-action" value="wan_reconnect"><i class="dropdown icon"></i><div class="text">wan_reconnect</div>' +
      '            <div class="menu">' + actionMenu + '</div>' +
      '          </div>' +
      '        </div>' +
      '        <div class="field" id="q-cron-target-wrap">' +
      '          <label>Target Service (for service_restart)</label>' +
      '          <div class="ui fluid selection dropdown" id="q-cron-target-dd">' +
      '            <input type="hidden" id="q-cron-target" value="adguardhome"><i class="dropdown icon"></i><div class="text">adguardhome</div>' +
      '            <div class="menu">' + targetMenu + '</div>' +
      '          </div>' +
      '        </div>' +
      '      </div>' +
      '      <div class="field" style="margin-bottom:0;">' +
      '        <div class="ui toggle checkbox" id="q-cron-enabled-chk"><input type="checkbox" id="q-cron-enabled" checked><label for="q-cron-enabled">Schedule enabled</label></div>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-cron-save-btn">Save Schedule</button>' +
      '  </div>' +
      '</div>' +

      // Power Action Confirmation Modal
      '<div class="ui mini modal" id="q-power-modal" role="dialog" aria-labelledby="q-power-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-power-title"><i data-lucide="power" class="q-icon q-text-danger"></i><span id="q-power-heading">Confirm Power Action</span></span>' +
      '  </div>' +
      '  <div class="content"><p id="q-power-desc"></p></div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui negative button" id="q-power-confirm-btn">Confirm</button>' +
      '  </div>' +
      '</div>'
    );
  }

  function renderAll() {
    if (!state.$root || !state.data) return;
    var d = state.data;
    var esc = Hive.format.escapeHtml;
    var fmt = Hive.format;

    state.$root.find('[data-set-count="daemons"]').text((d.daemons || []).length);
    state.$root.find('[data-set-count="cron"]').text((d.cron && d.cron.jobs ? d.cron.jobs.length : 0));

    // Tab 1: General Identity & Chrony NTP
    var $genForm = state.$root.find('#q-set-general-form');
    var genEditing = $genForm.length && $genForm[0].contains(document.activeElement);
    if (!genEditing) {
      $('#q-set-host').val(d.hostname || 'netbee');
      var tzs = (d.general && d.general.availableTimezones && d.general.availableTimezones.length)
        ? d.general.availableTimezones
        : ['UTC', 'Europe/Istanbul', 'Europe/Berlin', 'Europe/London', 'America/New_York'];
      var curTz = (d.general && d.general.timezone) || 'UTC';
      if (tzs.indexOf(curTz) === -1) tzs = [curTz].concat(tzs);
      var tzItems = tzs.map(function (z) {
        return '<div class="item" data-value="' + esc(z) + '">' + esc(z) + '</div>';
      }).join('');
      var $tzDd = $('#q-set-tz-dd');
      $tzDd.find('.menu').html(tzItems);
      $tzDd.dropdown('refresh').dropdown('set selected', curTz);
      $('#q-set-ntp-list').val(((d.general && d.general.ntpServers) || ['0.pool.ntp.org']).join(', '));
      $('#q-set-ntp-lan-chk').checkbox(d.general && d.general.ntpServeLan ? 'set checked' : 'set unchecked');
    }
    var stLan = Hive.store ? Hive.store.getState().lanConfig : null;
    var lanSubnetLbl = stLan && stLan.ip ? (stLan.ip.split('.').slice(0, 3).join('.') + '.0/24') : '192.168.10.0/24';
    if (stLan && stLan.netmask && stLan.netmask !== '255.255.255.0') {
      lanSubnetLbl = stLan.ip + ' / ' + stLan.netmask;
    }
    state.$root.find('#q-set-ntp-lan-subnet').text(lanSubnetLbl);

    var trackingOut = (d.general && d.general.ntpTracking) || 'Chrony tracking telemetry unavailable in current environment.';
    var sourcesOut = (d.general && d.general.ntpSources) ? ('\n\n' + d.general.ntpSources) : '';
    state.$root.find('#q-set-ntp-status').text(trackingOut + sourcesOut);

    // Tab 2: Daemons Table
    var rows = (d.daemons || [])
      .map(function (svc) {
        var running = Boolean(svc.running);
        var acts = Array.isArray(svc.actions) && svc.actions.length ? svc.actions : ['restart'];
        var btns = acts
          .map(function (act) {
            var cls = act === 'stop' ? 'basic negative' : act === 'start' ? 'primary' : act === 'reload' ? 'secondary' : 'basic';
            return '<button type="button" class="ui mini ' + cls + ' button q-svc-op-btn" data-name="' + esc(svc.name) + '" data-action="' + esc(act) + '">' + esc(act.charAt(0).toUpperCase() + act.slice(1)) + '</button>';
          })
          .join('');

        return (
          '<tr>' +
          '  <td><strong class="q-mono">' + esc(svc.name) + '</strong><span class="q-rule-desc">' + esc(svc.description) + '</span></td>' +
          '  <td><span class="ui label ' + (running ? 'q-status-success' : 'q-status-danger') + '"><span class="q-status-dot ' + (running ? 'is-success' : 'is-danger') + '"></span>' + (running ? 'running' : 'stopped') + '</span></td>' +
          '  <td class="q-mono q-text-secondary">' + esc(svc.pid || '—') + '</td>' +
          '  <td><div class="q-row-actions" style="flex-wrap:wrap;">' + btns + '</div></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-set-daemons-tbody').html(rows || '<tr><td colspan="4" style="text-align:center;padding:24px;color:var(--q-text-muted);">No service telemetry reported.</td></tr>');

    // Tab 3: Scheduled Tasks (crond)
    var cron = d.cron || { crondRunning: false, systemJobs: [], jobs: [] };
    state.$root.find('#q-cron-daemon-badge')
      .attr('class', 'ui label q-mono ' + (cron.crondRunning ? 'q-status-success' : 'q-status-warning'))
      .text(cron.crondRunning ? 'crond Running' : 'crond Standby');

    var sysJob = (cron.systemJobs && cron.systemJobs[0]) || '0 * * * * /usr/sbin/logrotate /etc/logrotate.conf >/dev/null 2>&1';
    state.$root.find('#q-cron-sysjob').text(sysJob);

    var cronRows = (cron.jobs || [])
      .map(function (j) {
        var actDesc = j.action + (j.target ? ' (' + j.target + ')' : '');
        return (
          '<tr class="' + (j.enabled ? '' : 'q-rule-disabled') + '">' +
          '  <td><strong>' + esc(j.name) + '</strong><span class="q-rule-desc q-mono">' + esc(j.id) + '</span></td>' +
          '  <td class="q-mono">' + esc(j.schedule) + '</td>' +
          '  <td><span class="ui label q-badge-square q-mono">' + esc(actDesc) + '</span></td>' +
          '  <td><span class="ui label ' + (j.enabled ? 'q-status-success' : '') + '">' + (j.enabled ? 'Enabled' : 'Disabled') + '</span></td>' +
          '  <td><div class="q-row-actions">' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-cron-edit-btn" data-id="' + esc(j.id) + '" title="Edit task" aria-label="Edit scheduled task ' + esc(j.name) + '"><i data-lucide="pencil" class="q-icon q-icon-sm"></i></button>' +
          '    <button type="button" class="ui mini icon button q-btn-ghost q-cron-del-btn" data-id="' + esc(j.id) + '" data-name="' + esc(j.name) + '" title="Delete task" aria-label="Delete scheduled task ' + esc(j.name) + '"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button>' +
          '  </div></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-cron-tbody').html(cronRows || '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--q-text-muted);">No user scheduled tasks configured.</td></tr>');

    // Tab 4: Kernel Sysctl
    var sc = d.sysctl || {};
    state.$root.find('#q-sc-ctcur').text('Active sessions: ' + fmt.number(sc.conntrackCount || 0));
    var $scForm = state.$root.find('#q-sysctl-form');
    var scEditing = $scForm.length && $scForm[0].contains(document.activeElement);
    if (!scEditing) {
      $('#q-sc-ctmax').val(sc.conntrackMax || 131072);
      $('#q-sc-rpf-dd').dropdown('set selected', String(sc.rpFilter !== undefined ? sc.rpFilter : 1));
      $('#q-sc-syncookies-chk').checkbox(sc.tcpSyncookies !== false ? 'set checked' : 'set unchecked');
      $('#q-sc-bcast-chk').checkbox(sc.icmpEchoIgnoreBroadcasts !== false ? 'set checked' : 'set unchecked');
      $('#q-sc-v4fwd-chk').checkbox(sc.ipv4Forwarding !== false ? 'set checked' : 'set unchecked');
      $('#q-sc-v6fwd-chk').checkbox(sc.ipv6Forwarding !== false ? 'set checked' : 'set unchecked');
    }

    if (Hive.icons) Hive.icons.render();
  }

  function syncCronTargetField(act) {
    var needsTarget = String(act || $('#q-cron-action').val()) === 'service_restart';
    $('#q-cron-target-dd').toggleClass('disabled', !needsTarget);
  }

  function openCronModal(id) {
    state.editingCronId = id || null;
    var jobs = (state.data && state.data.cron && state.data.cron.jobs) || [];
    var j = id ? jobs.find(function (x) { return x.id === id; }) : null;

    $('#q-cron-heading').text(j ? 'Edit Scheduled Task (' + j.name + ')' : 'Add Scheduled Task');
    $('#q-cron-name').val(j ? j.name : '');
    $('#q-cron-sched').val(j ? j.schedule : '0 4 * * *');
    var act = j ? j.action : 'wan_reconnect';
    $('#q-cron-action-dd')
      .dropdown({ onChange: syncCronTargetField })
      .dropdown('set selected', act);
    $('#q-cron-target-dd').dropdown('set selected', j && j.target ? j.target : 'adguardhome');
    syncCronTargetField(act);
    $('#q-cron-enabled-chk').checkbox(!j || j.enabled ? 'set checked' : 'set unchecked');

    $('#q-cron-name-field, #q-cron-sched-field').removeClass('error');
    $('#q-cron-name-err, #q-cron-sched-err').attr('hidden', true);
    Hive.ui.openModal('#q-cron-modal');
  }

  function saveCronModal() {
    var name = $.trim($('#q-cron-name').val());
    var schedule = $.trim($('#q-cron-sched').val()).replace(/\s+/g, ' ');
    var action = $('#q-cron-action').val() || 'wan_reconnect';
    var target = action === 'service_restart' ? ($('#q-cron-target').val() || 'adguardhome') : '';
    var enabled = $('#q-cron-enabled').is(':checked');

    var ok = true;
    $('#q-cron-name-field, #q-cron-sched-field').removeClass('error');
    $('#q-cron-name-err, #q-cron-sched-err').attr('hidden', true);

    if (!name || name.length > 64 || /[<>&"';`$]/.test(name)) {
      $('#q-cron-name-field').addClass('error');
      $('#q-cron-name-err').removeAttr('hidden');
      ok = false;
    }
    if (!validCronExpr(schedule)) {
      $('#q-cron-sched-field').addClass('error');
      $('#q-cron-sched-err').removeAttr('hidden');
      ok = false;
    }
    if (!ok) return;

    var $btn = $('#q-cron-save-btn');
    if ($btn.hasClass('loading')) return;
    $btn.addClass('loading disabled');

    var payload = { name: name, schedule: schedule, action: action, target: target, enabled: enabled };
    var req = state.editingCronId
      ? Hive.services.settings.updateCronJob(state.editingCronId, payload)
      : Hive.services.settings.addCronJob(payload);

    req
      .then(function () {
        $('#q-cron-modal').modal('hide');
        Hive.ui.notify({ title: 'Cron Schedule Saved', message: 'Updated /etc/cron/crontabs/root and reloaded crond.', type: 'success' });
        loadAndRender();
      })
      .catch(function (err) {
        Hive.ui.notify({ title: 'Invalid Schedule', message: err.message || 'Failed to save cron job.', type: 'error', displayTime: 4500 });
      })
      .finally(function () {
        $btn.removeClass('loading disabled');
      });
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.settings.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.data = data;
      renderAll();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    cleanupDetachedModals();

    Hive.services.settings.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.data = data;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">General &amp; Services</h1>' +
        '    <p class="q-page-subtitle">Hostname, timezone, Chrony NTP server, 17 init.d daemons, BusyBox <code>crond</code> tasks, and kernel <code>sysctl</code> tuning.</p>' +
        '  </div>' +
        '</div>' +

        '<div id="q-set-tabs-ctx">' +
        '  <div class="q-zone-tabs-bar">' +
        '    <div class="ui secondary pointing menu" data-tab-context="#q-set-tabs-ctx">' +
        '      <a class="item active" data-tab="general">Identity &amp; Chrony NTP</a>' +
        '      <a class="item" data-tab="daemons">System Daemons <span class="ui label q-mono" data-set-count="daemons">0</span></a>' +
        '      <a class="item" data-tab="cron">Scheduled Tasks <span class="ui label q-mono" data-set-count="cron">0</span></a>' +
        '      <a class="item" data-tab="sysctl">Kernel Tuning &amp; Power</a>' +
        '    </div>' +
        '  </div>' +

        // Tab 1: General Identity & Time
        '  <div class="ui tab active q-tab-plain" data-tab="general">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="sliders-horizontal" class="q-icon q-text-accent"></i><span>Hostname, Timezone &amp; Chrony NTP</span></h2><p class="q-card-subtitle">Updates <code>/etc/hostname</code>, <code>/etc/localtime</code>, and <code>/etc/chrony.conf</code>.</p></div></div>' +
        '      <form class="ui form" id="q-set-general-form" novalidate>' +
        '        <div class="two fields">' +
        '          <div class="field required" id="q-set-host-field"><label for="q-set-host">Router Hostname</label><input id="q-set-host" type="text" class="q-mono" placeholder="netbee"><span class="q-field-error" id="q-set-host-err" hidden>Enter a valid single-label RFC hostname (letters, digits, hyphens).</span></div>' +
        '          <div class="field"><label>Installed Timezone</label><div class="ui fluid search selection dropdown" id="q-set-tz-dd"><input type="hidden" id="q-set-tz" value="UTC"><i class="dropdown icon"></i><div class="text">UTC</div><div class="menu"></div></div></div>' +
        '        </div>' +
        '        <div class="field required" id="q-set-ntp-field">' +
        '          <label for="q-set-ntp-list">Upstream NTP Servers (Comma-Separated)</label>' +
        '          <input id="q-set-ntp-list" type="text" class="q-mono" placeholder="0.pool.ntp.org, 1.pool.ntp.org, time.cloudflare.com">' +
        '          <span class="q-field-error" id="q-set-ntp-err" hidden>Enter one or more valid NTP hostnames or IP addresses.</span>' +
        '        </div>' +
        '        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;">' +
        '          <div class="ui toggle checkbox" id="q-set-ntp-lan-chk"><input type="checkbox" id="q-set-ntp-lan"><label for="q-set-ntp-lan">Serve NTP time to LAN clients on <span class="q-mono" id="q-set-ntp-lan-subnet">192.168.10.0/24</span> (UDP/123)</label></div>' +
        '          <button type="submit" class="ui primary small button">Stage Identity &amp; NTP</button>' +
        '        </div>' +
        '      </form>' +
        '    </div>' +

        '    <div class="q-card">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="clock" class="q-icon q-text-accent"></i><span>Live Chrony Synchronization Status</span></h2><p class="q-card-subtitle">Output from <code>chronyc tracking</code> and <code>chronyc sources</code>.</p></div></div>' +
        '      <pre class="q-code-block" id="q-set-ntp-status" style="max-height:240px;"></pre>' +
        '    </div>' +
        '  </div>' +

        // Tab 2: System Daemons
        '  <div class="ui tab q-tab-plain" data-tab="daemons">' +
        '    <div class="q-card">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="cpu" class="q-icon q-text-accent"></i><span>Managed NetBee OS Services</span></h2><p class="q-card-subtitle">Live process state and direct SysV <code>/etc/init.d/S*</code> service controls.</p></div><button type="button" class="ui mini basic button" id="q-set-svc-refresh"><i data-lucide="refresh-cw" class="q-icon q-icon-sm"></i><span>Refresh</span></button></div>' +
        '      <div class="q-table-wrap"><table class="ui selectable striped table"><thead><tr><th>Service &amp; Role</th><th style="width:120px;">Status</th><th style="width:90px;">PID</th><th style="width:260px;">Actions</th></tr></thead><tbody id="q-set-daemons-tbody"></tbody></table></div>' +
        '    </div>' +
        '  </div>' +

        // Tab 3: Scheduled Tasks (crond)
        '  <div class="ui tab q-tab-plain" data-tab="cron">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">' +
        '        <div>' +
        '          <h2 class="q-card-title" style="margin-bottom:4px;">Mandatory RAM Logrotate Safeguard</h2>' +
        '          <code id="q-cron-sysjob" style="font-size:12px;"></code>' +
        '        </div>' +
        '        <span class="ui label q-mono" id="q-cron-daemon-badge">—</span>' +
        '      </div>' +
        '    </div>' +

        '    <div class="q-card">' +
        '      <div class="q-card-header">' +
        '        <div><h2 class="q-card-title">Custom Scheduled Tasks (<code>/etc/cron/crontabs/root</code>)</h2><p class="q-card-subtitle">Injection-safe whitelisted router maintenance schedules executed by BusyBox <code>crond</code>.</p></div>' +
        '        <button type="button" class="ui primary small button" id="q-cron-add-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add Task</span></button>' +
        '      </div>' +
        '      <div class="q-table-wrap"><table class="ui selectable striped table"><thead><tr><th>Task Name</th><th style="width:150px;">Cron Expression</th><th>Action</th><th style="width:100px;">Status</th><th style="width:86px;">Edit</th></tr></thead><tbody id="q-cron-tbody"></tbody></table></div>' +
        '    </div>' +
        '  </div>' +

        // Tab 4: Kernel Tuning & Power
        '  <div class="ui tab q-tab-plain" data-tab="sysctl">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="terminal" class="q-icon q-text-accent"></i><span>Router Kernel Parameters (<code>99-netbee-router.conf</code>)</span></h2><p class="q-card-subtitle">Applied immediately via <code>sysctl -p</code> and persisted across reboots.</p></div></div>' +
        '      <form class="ui form" id="q-sysctl-form" novalidate>' +
        '        <div class="two fields">' +
        '          <div class="field">' +
        '            <label for="q-sc-ctmax">Max Conntrack Entries (4096 – 1048576)</label>' +
        '            <input id="q-sc-ctmax" type="number" class="q-mono" min="4096" max="1048576" value="131072">' +
        '            <small class="q-text-muted q-mono" id="q-sc-ctcur"></small>' +
        '          </div>' +
        '          <div class="field">' +
        '            <label>Reverse Path Filtering (rp_filter)</label>' +
        '            <div class="ui fluid selection dropdown" id="q-sc-rpf-dd">' +
        '              <input type="hidden" id="q-sc-rpf" value="1"><i class="dropdown icon"></i><div class="text">Strict (1)</div>' +
        '              <div class="menu">' +
        '                <div class="item" data-value="1">1 — Strict (Recommended anti-spoofing)</div>' +
        '                <div class="item" data-value="2">2 — Loose (Multi-WAN / asymmetric routes)</div>' +
        '                <div class="item" data-value="0">0 — Disabled</div>' +
        '              </div>' +
        '            </div>' +
        '          </div>' +
        '        </div>' +
        '        <div class="two fields">' +
        '          <div class="field"><div class="ui toggle checkbox" id="q-sc-syncookies-chk"><input type="checkbox" id="q-sc-syncookies"><label for="q-sc-syncookies">TCP SYN Cookies (SYN flood protection)</label></div></div>' +
        '          <div class="field"><div class="ui toggle checkbox" id="q-sc-bcast-chk"><input type="checkbox" id="q-sc-bcast"><label for="q-sc-bcast">Ignore ICMP Broadcast Echoes (Smurf protection)</label></div></div>' +
        '        </div>' +
        '        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;">' +
        '          <div style="display:flex;gap:24px;flex-wrap:wrap;">' +
        '            <div class="ui toggle checkbox" id="q-sc-v4fwd-chk"><input type="checkbox" id="q-sc-v4fwd"><label for="q-sc-v4fwd">IPv4 Packet Forwarding</label></div>' +
        '            <div class="ui toggle checkbox" id="q-sc-v6fwd-chk"><input type="checkbox" id="q-sc-v6fwd"><label for="q-sc-v6fwd">IPv6 Packet Forwarding</label></div>' +
        '          </div>' +
        '          <button type="submit" class="ui primary small button" id="q-sc-save-btn">Apply Kernel Parameters</button>' +
        '        </div>' +
        '      </form>' +
        '    </div>' +

        '    <div class="q-card">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="power" class="q-icon q-text-danger"></i><span>Appliance Power Management</span></h2><p class="q-card-subtitle">Gracefully reboot or halt the Raspberry Pi 5 hardware.</p></div></div>' +
        '      <div style="display:flex;gap:12px;flex-wrap:wrap;">' +
        '        <button type="button" class="ui secondary button" id="q-pwr-reboot-btn"><i data-lucide="rotate-ccw" class="q-icon q-icon-sm"></i><span>Reboot Router</span></button>' +
        '        <button type="button" class="ui basic negative button" id="q-pwr-halt-btn"><i data-lucide="power" class="q-icon q-icon-sm"></i><span>Power Off Router</span></button>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);
      renderAll();
    });

    // Tab 1 Submit
    $container.on('submit.qSettings', '#q-set-general-form', function (e) {
      e.preventDefault();
      var v = Hive.validators;
      var hostname = $.trim($('#q-set-host').val());
      var timezone = $('#q-set-tz').val() || 'UTC';
      var rawNtp = $.trim($('#q-set-ntp-list').val());
      var ntpServers = rawNtp.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      var serveLan = $('#q-set-ntp-lan').is(':checked');

      var ok = true;
      $('#q-set-host-field, #q-set-ntp-field').removeClass('error');
      $('#q-set-host-err, #q-set-ntp-err').attr('hidden', true);

      if (!v.isHostname(hostname) || hostname.indexOf('.') !== -1) {
        $('#q-set-host-field').addClass('error');
        $('#q-set-host-err').removeAttr('hidden');
        ok = false;
      }
      if (!ntpServers.length || !ntpServers.every(function (h) { return v.isHostname(h) || v.isIPv4(h) || v.isIPv6(h); })) {
        $('#q-set-ntp-field').addClass('error');
        $('#q-set-ntp-err').removeAttr('hidden');
        ok = false;
      }
      if (!ok) return;

      Hive.services.settings
        .updateGeneral({ hostname: hostname, timezone: timezone, ntpServers: ntpServers, ntpServeLan: serveLan })
        .then(function () {
          Hive.ui.notify({ title: 'Identity & NTP Staged', message: hostname + ' (' + timezone + ') queued in pending changes.', type: 'success' });
        });
    });

    // Tab 2 Daemon Actions
    $container.on('click.qSettings', '#q-set-svc-refresh', function () {
      Hive.services.system.getSnapshot().then(loadAndRender);
    });

    $container.on('click.qSettings', '.q-svc-op-btn', function () {
      var $btn = $(this);
      if ($btn.hasClass('loading')) return;
      var name = $btn.attr('data-name');
      var action = $btn.attr('data-action') || 'restart';

      function runServiceOp() {
        $btn.addClass('loading disabled');
        Hive.services.settings
          .serviceAction(name, action)
          .then(function () {
            Hive.ui.notify({ title: 'Service ' + action.toUpperCase(), message: name + ' executed ' + action + ' cleanly.', type: 'success' });
            loadAndRender();
          })
          .catch(function (err) {
            Hive.ui.notify({ title: 'Service Action Failed', message: err.message || ('Failed to ' + action + ' ' + name), type: 'error' });
          })
          .finally(function () {
            if (state.$root) $btn.removeClass('loading disabled');
          });
      }

      if (action === 'stop') {
        Hive.ui.confirm({
          title: 'Stop System Service (' + name + ')?',
          message: 'Stopping "' + name + '" immediately halts its daemon process on the live router until manually restarted.',
          confirmText: 'Stop Service',
          danger: true,
          onConfirm: runServiceOp
        });
        return;
      }
      runServiceOp();
    });

    // Tab 3 Cron
    $container.on('click.qSettings', '#q-cron-add-btn', function () { openCronModal(null); });
    $container.on('click.qSettings', '.q-cron-edit-btn', function () { openCronModal($(this).attr('data-id')); });
    $container.on('click.qSettings', '.q-cron-del-btn', function () {
      var id = $(this).attr('data-id');
      var taskName = $(this).attr('data-name') || id;
      Hive.ui.confirm({
        title: 'Delete Scheduled Task?',
        message: 'Remove "' + taskName + '" from /etc/cron/crontabs/root permanently?',
        confirmText: 'Delete Task',
        danger: true,
        onConfirm: function () {
          Hive.services.settings
            .deleteCronJob(id)
            .then(function () {
              Hive.ui.notify({ title: 'Scheduled Task Deleted', message: 'Removed task from /etc/cron/crontabs/root.', type: 'warning' });
              loadAndRender();
            })
            .catch(function (err) {
              Hive.ui.notify({ title: 'Delete Failed', message: err.message || 'Could not remove task.', type: 'error' });
            });
        }
      });
    });

    // Tab 4 Sysctl & Power
    $container.on('submit.qSettings', '#q-sysctl-form', function (e) {
      e.preventDefault();
      var ctMax = Number($('#q-sc-ctmax').val() || 131072);
      if (!Number.isInteger(ctMax) || ctMax < 4096 || ctMax > 1048576) {
        Hive.ui.notify({ title: 'Invalid Conntrack Max', message: 'Enter an integer between 4096 and 1048576.', type: 'error' });
        return;
      }
      var $btn = $('#q-sc-save-btn');
      $btn.addClass('loading disabled');
      Hive.services.settings
        .saveSysctl({
          conntrack_max: ctMax,
          rp_filter: Number($('#q-sc-rpf').val() || 1),
          tcp_syncookies: $('#q-sc-syncookies').is(':checked'),
          icmp_echo_ignore_broadcasts: $('#q-sc-bcast').is(':checked'),
          ipv4_forwarding: $('#q-sc-v4fwd').is(':checked'),
          ipv6_forwarding: $('#q-sc-v6fwd').is(':checked')
        })
        .then(function () {
          Hive.ui.notify({ title: 'Kernel Parameters Applied', message: '99-netbee-router.conf updated and applied via sysctl.', type: 'success' });
          loadAndRender();
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Sysctl Error', message: err.message || 'Failed to apply sysctl parameters.', type: 'error' });
        })
        .finally(function () {
          if (state.$root) $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qSettings', '#q-pwr-reboot-btn', function () {
      state.pendingPowerAction = 'reboot';
      $('#q-power-heading').text('Reboot NetBee OS Router');
      $('#q-power-desc').text('Active LAN/WAN sessions will pause briefly (~25 seconds) while the Raspberry Pi 5 restarts.');
      $('#q-power-confirm-btn').text('Reboot Now');
      Hive.ui.openModal('#q-power-modal');
    });

    $container.on('click.qSettings', '#q-pwr-halt-btn', function () {
      state.pendingPowerAction = 'poweroff';
      $('#q-power-heading').text('Power Off NetBee OS Router');
      $('#q-power-desc').text('Warning: Halting the appliance shuts down all network routing and SSH/Web access until physical power is cycled.');
      $('#q-power-confirm-btn').text('Power Off');
      Hive.ui.openModal('#q-power-modal');
    });

    $(document).on('click.qSettingsModal', '.q-cron-preset', function () {
      $('#q-cron-sched').val($(this).attr('data-expr'));
    });
    $(document).on('click.qSettingsModal', '#q-cron-save-btn', saveCronModal);
    $(document).on('submit.qSettingsModal', '#q-cron-form', function (e) { e.preventDefault(); saveCronModal(); });

    $(document).on('click.qSettingsModal', '#q-power-confirm-btn', function () {
      var act = state.pendingPowerAction;
      $('#q-power-modal').modal('hide');
      if (act === 'reboot') {
        Hive.services.settings.reboot().then(function () {
          Hive.ui.notify({ title: 'Reboot Initiated', message: 'Router is restarting...', type: 'warning', displayTime: 6000 });
        });
      } else if (act === 'poweroff') {
        Hive.services.settings.poweroff().then(function () {
          Hive.ui.notify({ title: 'Shutting Down', message: 'Router is powering off cleanly.', type: 'warning', displayTime: 6000 });
        });
      }
    });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (Hive.store.isRuntimeOnlyReason(reason)) return;
      loadAndRender();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    $(document).off('.qSettingsModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qSettings');
      state.$root = null;
    }
  }

  Hive.router.register('/system/settings', {
    title: 'General & Services',
    group: 'System',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
