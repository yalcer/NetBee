/* ==========================================================================
   Hive — System Module: Users & Access (#/system/access)
   Web Admin & OS Passwords, Dropbear SSH Policy, Authorized Keys & TLS Certs
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    access: null,
    targetOsUser: 'netbee',
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-os-pw-modal, #q-ssh-modal').modal('hide').remove();
  }

  function validOpenSshKey(raw) {
    var s = $.trim(raw || '');
    if (!s || s.length > 4096 || /[\r\n]/.test(s)) return false;
    return Hive.validators.isSshPublicKey(s);
  }

  function renderModalsHtml() {
    return (
      // Set OS Account Password Modal (root / netbee)
      '<div class="ui mini modal" id="q-os-pw-modal" role="dialog" aria-labelledby="q-ospw-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-ospw-title"><i data-lucide="lock-keyhole" class="q-icon q-text-accent"></i><span>Set SSH / Console Password: <span class="q-mono" id="q-ospw-user"></span></span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-ospw-form" novalidate>' +
      '      <div class="field required" id="q-ospw-p1-field">' +
      '        <label for="q-ospw-p1">New UNIX Password (min 8 characters)</label>' +
      '        <input id="q-ospw-p1" type="password" autocomplete="new-password" placeholder="Minimum 8 characters">' +
      '        <span class="q-field-error" id="q-ospw-err" hidden>Password must be 8–128 characters and match confirmation.</span>' +
      '      </div>' +
      '      <div class="field required" style="margin-bottom:0;">' +
      '        <label for="q-ospw-p2">Confirm Password</label>' +
      '        <input id="q-ospw-p2" type="password" autocomplete="new-password" placeholder="Repeat password">' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-ospw-save-btn">Update OS Password</button>' +
      '  </div>' +
      '</div>' +

      // Authorize SSH Public Key Modal
      '<div class="ui small modal" id="q-ssh-modal" role="dialog" aria-labelledby="q-ssh-title">' +
      '  <div class="header">' +
      '    <span class="q-modal-header-title" id="q-ssh-title"><i data-lucide="key-round" class="q-icon q-text-accent"></i><span>Authorize SSH Public Key</span></span>' +
      '    <button type="button" class="ui mini icon button q-btn-ghost cancel" aria-label="Close"><i data-lucide="x" class="q-icon"></i></button>' +
      '  </div>' +
      '  <div class="content">' +
      '    <form class="ui form" id="q-ssh-form" novalidate>' +
      '      <div class="field">' +
      '        <label>Target OS Account</label>' +
      '        <div class="ui fluid selection dropdown" id="q-ssh-owner-dd">' +
      '          <input type="hidden" id="q-ssh-owner" value="netbee"><i class="dropdown icon"></i><div class="text">netbee</div>' +
      '          <div class="menu">' +
      '            <div class="item" data-value="netbee"><span class="q-mono">netbee</span> — Unprivileged Admin (/home/netbee/.ssh/authorized_keys)</div>' +
      '            <div class="item" data-value="root"><span class="q-mono">root</span> — Superuser (/root/.ssh/authorized_keys)</div>' +
      '          </div>' +
      '        </div>' +
      '      </div>' +
      '      <div class="field required" id="q-ssh-key-field" style="margin-bottom:0;">' +
      '        <label for="q-ssh-key">OpenSSH Public Key (ssh-ed25519 / ecdsa / ssh-rsa)</label>' +
      '        <textarea id="q-ssh-key" rows="3" class="q-mono" placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@workstation"></textarea>' +
      '        <span class="q-field-error" id="q-ssh-key-err" hidden>Paste a valid single-line OpenSSH public key.</span>' +
      '      </div>' +
      '    </form>' +
      '  </div>' +
      '  <div class="actions">' +
      '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
      '    <button type="button" class="ui primary button" id="q-ssh-save-btn">Add Authorized Key</button>' +
      '  </div>' +
      '</div>'
    );
  }

  function renderTables() {
    if (!state.$root || !state.access) return;
    var esc = Hive.format.escapeHtml;
    var acc = state.access;
    var ssh = acc.ssh || {};
    var tls = acc.tls || {};

    var users = acc.osUsers && acc.osUsers.length
      ? acc.osUsers
      : [
          { username: 'root', uid: 0, gid: 0, role: 'superuser', home: '/root', shell: '/bin/sh', login_enabled: true, groups: ['root', 'wheel'], ssh_keys_count: 0 },
          { username: 'netbee', uid: 1000, gid: 1000, role: 'admin', home: '/home/netbee', shell: '/bin/sh', login_enabled: true, groups: ['netbee', 'wheel'], ssh_keys_count: 0 }
        ];

    state.$root.find('[data-acc-count="users"]').text(users.length);
    state.$root.find('[data-acc-count="keys"]').text((ssh.sshKeys || []).length);

    // Tab 1: Pre-Created NetBee OS Accounts
    var userRows = users
      .map(function (u) {
        var canSetPw = u.username === 'root' || u.username === 'netbee';
        var roleCls = u.role === 'superuser' ? 'q-net-firewall' : u.role === 'admin' ? 'q-net-wan' : 'q-badge-square';
        return (
          '<tr>' +
          '  <td><strong class="q-mono">' + esc(u.username) + '</strong><span class="q-rule-desc q-mono">UID ' + u.uid + ':' + u.gid + ' · ' + esc(u.home) + '</span></td>' +
          '  <td><span class="ui label ' + roleCls + ' q-badge-square">' + esc(u.role || 'service') + '</span></td>' +
          '  <td class="q-mono q-text-secondary">' + esc(u.shell || '/sbin/nologin') + '<span class="q-rule-desc">' + esc((u.groups || []).join(', ') || '—') + '</span></td>' +
          '  <td class="q-mono">' + (canSetPw ? (Number(u.ssh_keys_count || 0) + ' keys') : '<span class="q-text-muted">Isolated</span>') + '</td>' +
          '  <td>' + (u.login_enabled ? '<span class="ui label q-status-success">Interactive</span>' : '<span class="ui label q-badge-square">Locked Daemon</span>') + '</td>' +
          '  <td>' + (canSetPw ? '<button type="button" class="ui mini secondary button q-os-pw-btn" data-user="' + esc(u.username) + '">Set Password</button>' : '<span class="q-text-muted" style="font-size:11px;">System</span>') + '</td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-os-users-tbody').html(userRows);

    // Tab 2: Dropbear SSH Policy & Authorized Keys
    var $sshForm = state.$root.find('#q-ssh-pol-form');
    var sshEditing = $sshForm.length && $sshForm[0].contains(document.activeElement);
    if (!sshEditing) {
      $('#q-ssh-pwauth-chk').checkbox(ssh.passwordAuth ? 'set checked' : 'set unchecked');
      $('#q-ssh-root-chk').checkbox(ssh.allowRootLogin ? 'set checked' : 'set unchecked');
      $('#q-ssh-timeout').val(ssh.idleTimeout !== undefined ? ssh.idleTimeout : 300);
    }

    var keys = ssh.sshKeys || [];
    var keyRows = keys
      .map(function (k) {
        var shortBody = k.keyBody && k.keyBody.length > 28 ? (k.keyBody.slice(0, 16) + '…' + k.keyBody.slice(-10)) : k.keyBody;
        var ownerCls = k.owner === 'root' ? 'q-net-firewall' : 'q-net-wan';
        return (
          '<tr>' +
          '  <td><span class="ui label ' + ownerCls + ' q-badge-square q-mono">' + esc(k.owner) + '</span></td>' +
          '  <td><strong class="q-mono">' + esc(k.label) + '</strong><span class="q-rule-desc q-mono">' + esc(k.type) + '</span></td>' +
          '  <td><div class="q-key-copy-row"><span class="q-mono q-text-secondary">' + esc(shortBody) + '</span><button type="button" class="ui mini icon button q-btn-ghost" data-q-copy="' + esc(k.publicKey) + '" data-q-copy-label="SSH public key" title="Copy full public key" aria-label="Copy SSH public key ' + esc(k.label) + '"><i data-lucide="copy" class="q-icon q-icon-sm"></i></button></div></td>' +
          '  <td><button type="button" class="ui mini icon button q-btn-ghost q-ssh-del-btn" data-owner="' + esc(k.owner) + '" data-index="' + k.index + '" data-label="' + esc(k.label) + '" title="Revoke SSH key" aria-label="Revoke SSH key ' + esc(k.label) + '"><i data-lucide="trash-2" class="q-icon q-icon-sm q-text-danger"></i></button></td>' +
          '</tr>'
        );
      })
      .join('');
    state.$root.find('#q-ssh-tbody').html(keyRows || '<tr><td colspan="4" style="text-align:center;padding:24px;color:var(--q-text-muted);">No SSH public keys authorized yet. Add an Ed25519 key before disabling password authentication.</td></tr>');

    // Tab 3: HTTPS / TLS Certificate Metadata
    var sanList = [].concat(tls.dnsNames || [], tls.ipAddresses || []);
    state.$root.find('#q-tls-badge')
      .attr('class', 'ui label q-mono ' + (tls.autoSelfSigned ? 'q-status-info' : 'q-status-success'))
      .text(tls.autoSelfSigned ? 'Auto Self-Signed ECDSA' : 'Custom X.509 Certificate');

    state.$root.find('#q-tls-meta').html(
      '<div class="q-kv-row"><span class="q-kv-label">Subject</span><span class="q-kv-value q-mono">' + esc(tls.subject || 'CN=netbee.lan') + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Issuer</span><span class="q-kv-value q-mono">' + esc(tls.issuer || 'NetBee OS Self-Signed') + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">Valid From → Until</span><span class="q-kv-value q-mono">' + esc(tls.notBefore || '—') + ' → ' + esc(tls.notAfter || '—') + '</span></div>' +
      '<div class="q-kv-row"><span class="q-kv-label">SAN (DNS &amp; IPs)</span><span class="q-kv-value q-mono">' + esc(sanList.join(', ') || 'netbee.lan, 192.168.10.1') + '</span></div>'
    );
    $('#q-tls-reset-btn').toggle(!tls.autoSelfSigned);

    if (Hive.icons) Hive.icons.render();
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.access.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.access = data;
      renderTables();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    cleanupDetachedModals();

    Hive.services.access.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.access = data;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Users &amp; Access</h1>' +
        '    <p class="q-page-subtitle">Web administrator credentials, pre-created Linux accounts (<code>root</code> / <code>netbee</code>), Dropbear SSH hardening, and HTTPS TLS certificates.</p>' +
        '  </div>' +
        '</div>' +

        '<div id="q-acc-tabs-ctx">' +
        '  <div class="q-zone-tabs-bar">' +
        '    <div class="ui secondary pointing menu" data-tab-context="#q-acc-tabs-ctx">' +
        '      <a class="item active" data-tab="accounts">Passwords &amp; OS Accounts <span class="ui label q-mono" data-acc-count="users">0</span></a>' +
        '      <a class="item" data-tab="ssh">Dropbear SSH &amp; Keys <span class="ui label q-mono" data-acc-count="keys">0</span></a>' +
        '      <a class="item" data-tab="tls">HTTPS / TLS Certificate</a>' +
        '    </div>' +
        '  </div>' +

        // Tab 1: Web Password & Pre-Created OS Accounts
        '  <div class="ui tab active q-tab-plain" data-tab="accounts">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="shield-check" class="q-icon q-text-accent"></i><span>Change Web Control Plane Password (<code>admin</code>)</span></h2><p class="q-card-subtitle">Hashed with Argon2id / bcrypt in <code>netbeed</code> state. Optionally synchronize with SSH/console UNIX accounts.</p></div></div>' +
        '      <form class="ui form" id="q-web-pw-form" novalidate>' +
        '        <div class="three fields">' +
        '          <div class="field required"><label for="q-wpw-cur">Current Web Password</label><input id="q-wpw-cur" type="password" autocomplete="current-password" required></div>' +
        '          <div class="field required"><label for="q-wpw-new">New Password (min 8 chars)</label><input id="q-wpw-new" type="password" autocomplete="new-password" required></div>' +
        '          <div class="field required"><label for="q-wpw-cfm">Confirm New Password</label><input id="q-wpw-cfm" type="password" autocomplete="new-password" required></div>' +
        '        </div>' +
        '        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;">' +
        '          <div style="display:flex;gap:24px;flex-wrap:wrap;">' +
        '            <div class="ui checkbox" id="q-wpw-sync-netbee-chk"><input type="checkbox" id="q-wpw-sync-netbee"><label for="q-wpw-sync-netbee">Also set as <code>netbee</code> SSH/console password</label></div>' +
        '            <div class="ui checkbox" id="q-wpw-sync-root-chk"><input type="checkbox" id="q-wpw-sync-root"><label for="q-wpw-sync-root">Also set as <code>root</code> SSH/console password</label></div>' +
        '          </div>' +
        '          <button type="submit" class="ui primary small button" id="q-wpw-btn">Update Web Password</button>' +
        '        </div>' +
        '      </form>' +
        '    </div>' +

        '    <div class="q-card">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="users" class="q-icon q-text-accent"></i><span>NetBee OS System &amp; Administrator Accounts</span></h2><p class="q-card-subtitle">Read directly from <code>/etc/passwd</code> and <code>/etc/shadow</code>. Service daemons run under locked non-interactive accounts.</p></div></div>' +
        '      <div class="q-table-wrap">' +
        '        <table class="ui selectable striped table">' +
        '          <thead><tr><th>Account &amp; Home</th><th>Role</th><th>Shell &amp; Groups</th><th>SSH Keys</th><th>Login Posture</th><th style="width:136px;">Password</th></tr></thead>' +
        '          <tbody id="q-os-users-tbody"></tbody>' +
        '        </table>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +

        // Tab 2: Dropbear SSH Policy & Authorized Keys
        '  <div class="ui tab q-tab-plain" data-tab="ssh">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="terminal" class="q-icon q-text-accent"></i><span>Dropbear SSH Daemon Policy (LAN :22)</span></h2><p class="q-card-subtitle">Bound strictly to LAN interface in <code>/etc/default/dropbear</code> with anti-lockout key verification.</p></div><span class="ui label q-status-success">Server-Only Hardened</span></div>' +
        '      <form class="ui form" id="q-ssh-pol-form" novalidate>' +
        '        <div class="three fields" style="align-items:center;">' +
        '          <div class="field"><div class="ui toggle checkbox" id="q-ssh-pwauth-chk"><input type="checkbox" id="q-ssh-pwauth"><label for="q-ssh-pwauth">Allow SSH Password Login</label></div></div>' +
        '          <div class="field"><div class="ui toggle checkbox" id="q-ssh-root-chk"><input type="checkbox" id="q-ssh-root"><label for="q-ssh-root">Allow Direct <code>root</code> SSH Login</label></div></div>' +
        '          <div class="field"><label for="q-ssh-timeout">Idle Session Timeout (seconds, 0 = none)</label><input id="q-ssh-timeout" type="number" class="q-mono" min="0" max="86400" value="300"></div>' +
        '        </div>' +
        '        <div style="display:flex;justify-content:flex-end;">' +
        '          <button type="submit" class="ui primary small button">Stage SSH Policy</button>' +
        '        </div>' +
        '      </form>' +
        '    </div>' +

        '    <div class="q-card">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="key-round" class="q-icon q-text-accent"></i><span>Authorized OpenSSH Public Keys</span></h2><p class="q-card-subtitle">Managed across <code>/home/netbee/.ssh/authorized_keys</code> and <code>/root/.ssh/authorized_keys</code>.</p></div><button type="button" class="ui secondary small button" id="q-open-ssh-btn"><i data-lucide="plus" class="q-icon q-icon-sm"></i><span>Add SSH Key</span></button></div>' +
        '      <div class="q-table-wrap"><table class="ui striped table"><thead><tr><th style="width:100px;">Account</th><th>Comment / Algorithm</th><th>Key Material</th><th style="width:68px;">Revoke</th></tr></thead><tbody id="q-ssh-tbody"></tbody></table></div>' +
        '    </div>' +
        '  </div>' +

        // Tab 3: HTTPS / TLS Certificate
        '  <div class="ui tab q-tab-plain" data-tab="tls">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="lock" class="q-icon q-text-accent"></i><span>Active HTTPS Listener Certificate</span></h2><p class="q-card-subtitle">Served by <code>netbeed</code> on TCP/443 (TLS 1.2+ modern cipher suites only).</p></div><span class="ui label q-mono" id="q-tls-badge">—</span></div>' +
        '      <div class="q-kv-list" id="q-tls-meta"></div>' +
        '      <div style="display:flex;justify-content:flex-end;margin-top:var(--q-space-3);">' +
        '        <button type="button" class="ui basic negative small button" id="q-tls-reset-btn" style="display:none;">Revert to Auto Self-Signed Certificate</button>' +
        '      </div>' +
        '    </div>' +

        '    <div class="q-card">' +
        '      <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="upload" class="q-icon q-text-accent"></i><span>Install Custom PEM Certificate &amp; Private Key</span></h2><p class="q-card-subtitle">Validates X.509 keypair match before atomic replacement.</p></div></div>' +
        '      <form class="ui form" id="q-tls-form" novalidate>' +
        '        <div class="two fields">' +
        '          <div class="field required"><label for="q-tls-cert">Certificate Chain (PEM)</label><textarea id="q-tls-cert" rows="6" class="q-mono" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea></div>' +
        '          <div class="field required"><label for="q-tls-key">Private Key (PEM, unencrypted)</label><textarea id="q-tls-key" rows="6" class="q-mono" placeholder="-----BEGIN EC PRIVATE KEY-----&#10;...&#10;-----END EC PRIVATE KEY-----"></textarea></div>' +
        '        </div>' +
        '        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">' +
        '          <div class="ui toggle checkbox" id="q-tls-reload-chk"><input type="checkbox" id="q-tls-reload" checked><label for="q-tls-reload">Hot-reload HTTPS listener immediately</label></div>' +
        '          <button type="submit" class="ui primary small button" id="q-tls-save-btn">Install TLS Certificate</button>' +
        '        </div>' +
        '      </form>' +
        '    </div>' +
        '  </div>' +
        '</div>' +
        renderModalsHtml();

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);
      renderTables();
    });

    // Web Password Change
    $container.on('submit.qAccess', '#q-web-pw-form', function (e) {
      e.preventDefault();
      var cur = $('#q-wpw-cur').val() || '';
      var nw = $('#q-wpw-new').val() || '';
      var cfm = $('#q-wpw-cfm').val() || '';
      if (!cur || nw.length < 8 || nw.length > 128) {
        Hive.ui.notify({ title: 'Password Too Short', message: 'New password must be between 8 and 128 characters.', type: 'error' });
        return;
      }
      if (nw !== cfm) {
        Hive.ui.notify({ title: 'Password Mismatch', message: 'New password and confirmation do not match.', type: 'error' });
        return;
      }
      var $btn = $('#q-wpw-btn');
      $btn.addClass('loading disabled');
      Hive.services.access
        .changeWebPassword({
          currentPassword: cur,
          newPassword: nw,
          syncNetbeeSsh: $('#q-wpw-sync-netbee').is(':checked'),
          syncRootSsh: $('#q-wpw-sync-root').is(':checked')
        })
        .then(function () {
          $('#q-wpw-cur, #q-wpw-new, #q-wpw-cfm').val('');
          if (Hive.auth && typeof Hive.auth.clearMustChangePassword === 'function') {
            Hive.auth.clearMustChangePassword();
          }
          $('#q-notif-dot').attr('hidden', true);
          Hive.ui.notify({ title: 'Password Updated', message: 'Administrator password updated cleanly.', type: 'success' });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Password Update Failed', message: err.message || 'Check current password.', type: 'error' });
        })
        .finally(function () {
          if (state.$root) $btn.removeClass('loading disabled');
        });
    });

    // Open OS Account Password Modal
    $container.on('click.qAccess', '.q-os-pw-btn', function () {
      state.targetOsUser = $(this).attr('data-user') || 'netbee';
      $('#q-ospw-user').text(state.targetOsUser);
      $('#q-ospw-p1, #q-ospw-p2').val('');
      $('#q-ospw-p1-field').removeClass('error');
      $('#q-ospw-err').attr('hidden', true);
      Hive.ui.openModal('#q-os-pw-modal');
    });

    // Stage Dropbear SSH Policy
    $container.on('submit.qAccess', '#q-ssh-pol-form', function (e) {
      e.preventDefault();
      var pwAuth = $('#q-ssh-pwauth').is(':checked');
      var allowRoot = $('#q-ssh-root').is(':checked');
      var idle = Math.max(0, Math.min(86400, Number($('#q-ssh-timeout').val() || 0)));
      var keys = (state.access && state.access.ssh && state.access.ssh.sshKeys) || [];

      if (!pwAuth) {
        var usableKeys = keys.filter(function (k) { return allowRoot || k.owner === 'netbee'; });
        if (!usableKeys.length) {
          Hive.ui.notify({
            title: 'Anti-Lockout Guard',
            message: allowRoot ? 'Authorize at least one SSH public key before disabling password login.' : 'Authorize at least one SSH key for netbee before disabling both password login and root SSH.',
            type: 'warning',
            displayTime: 4800
          });
          return;
        }
      }

      Hive.services.access
        .stageSshPolicy({ passwordAuth: pwAuth, allowRootLogin: allowRoot, idleTimeout: idle })
        .then(function () {
          Hive.ui.notify({ title: 'SSH Policy Staged', message: 'Dropbear policy queued in pending changes.', type: 'success' });
        });
    });

    // Open SSH Key Modal & Delete Key
    $container.on('click.qAccess', '#q-open-ssh-btn', function () {
      $('#q-ssh-owner-dd').dropdown('set selected', 'netbee');
      $('#q-ssh-key').val('');
      $('#q-ssh-key-field').removeClass('error');
      $('#q-ssh-key-err').attr('hidden', true);
      Hive.ui.openModal('#q-ssh-modal');
    });

    $container.on('click.qAccess', '.q-ssh-del-btn', function () {
      var owner = $(this).attr('data-owner');
      var idx = Number($(this).attr('data-index'));
      var keyLbl = $(this).attr('data-label') || ('key #' + (idx + 1));
      Hive.ui.confirm({
        title: 'Revoke Authorized SSH Key?',
        message: 'Remove "' + keyLbl + '" from ' + owner + ' authorized_keys immediately?',
        confirmText: 'Revoke Key',
        danger: true,
        onConfirm: function () {
          Hive.services.access
            .deleteSshKey(owner, idx)
            .then(function () {
              Hive.ui.notify({ title: 'SSH Key Revoked', message: 'Removed key from ' + owner + ' authorized_keys.', type: 'warning' });
              loadAndRender();
            })
            .catch(function (err) {
              Hive.ui.notify({ title: 'Cannot Revoke Key', message: err.message || 'Anti-lockout check prevented removal.', type: 'error', displayTime: 4500 });
            });
        }
      });
    });

    // TLS Certificate Upload & Reset
    $container.on('submit.qAccess', '#q-tls-form', function (e) {
      e.preventDefault();
      var certPem = $.trim($('#q-tls-cert').val());
      var keyPem = $.trim($('#q-tls-key').val());
      var reload = $('#q-tls-reload').is(':checked');
      if (certPem.indexOf('BEGIN CERTIFICATE') === -1 || keyPem.indexOf('PRIVATE KEY') === -1) {
        Hive.ui.notify({ title: 'Invalid PEM Input', message: 'Provide both a PEM certificate chain and PEM private key.', type: 'error' });
        return;
      }
      var $btn = $('#q-tls-save-btn');
      $btn.addClass('loading disabled');
      Hive.services.access
        .saveTls({ certPem: certPem, keyPem: keyPem, reload: reload })
        .then(function () {
          $('#q-tls-cert, #q-tls-key').val('');
          Hive.ui.notify({ title: 'TLS Certificate Installed', message: 'X.509 certificate verified and persisted.', type: 'success' });
          loadAndRender();
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Certificate Validation Failed', message: err.message || 'Mismatched or malformed PEM.', type: 'error', displayTime: 4800 });
        })
        .finally(function () {
          if (state.$root) $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qAccess', '#q-tls-reset-btn', function () {
      Hive.ui.confirm({
        title: 'Revert Custom TLS Certificate?',
        message: 'Delete the custom X.509 certificate and regenerate NetBee OS automatic self-signed ECDSA certificate?',
        confirmText: 'Revert Certificate',
        danger: true,
        onConfirm: function () {
          Hive.services.access
            .deleteTls()
            .then(function () {
              Hive.ui.notify({ title: 'Custom TLS Removed', message: 'Reverted to automatic self-signed ECDSA certificate.', type: 'info' });
              loadAndRender();
            })
            .catch(function (err) {
              Hive.ui.notify({ title: 'TLS Reset Error', message: err.message || 'Could not reset certificate.', type: 'error' });
            });
        }
      });
    });

    // Modal Handlers
    function saveOsPassword() {
      var p1 = $('#q-ospw-p1').val() || '';
      var p2 = $('#q-ospw-p2').val() || '';
      if (p1.length < 8 || p1.length > 128 || p1 !== p2) {
        $('#q-ospw-p1-field').addClass('error');
        $('#q-ospw-err').removeAttr('hidden');
        return;
      }
      var $btn = $('#q-ospw-save-btn');
      $btn.addClass('loading disabled');
      Hive.services.access
        .setOsUserPassword(state.targetOsUser, p1)
        .then(function () {
          $('#q-os-pw-modal').modal('hide');
          Hive.ui.notify({ title: 'OS Password Updated', message: 'Updated UNIX shadow password for ' + state.targetOsUser + '.', type: 'success' });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Update Failed', message: err.message || 'chpasswd error.', type: 'error' });
        })
        .finally(function () {
          $btn.removeClass('loading disabled');
        });
    }

    function saveSshKey() {
      var owner = $('#q-ssh-owner').val() || 'netbee';
      var pubKey = $.trim($('#q-ssh-key').val());
      $('#q-ssh-key-field').removeClass('error');
      $('#q-ssh-key-err').attr('hidden', true);
      if (!validOpenSshKey(pubKey)) {
        $('#q-ssh-key-field').addClass('error');
        $('#q-ssh-key-err').removeAttr('hidden');
        return;
      }
      var $btn = $('#q-ssh-save-btn');
      $btn.addClass('loading disabled');
      Hive.services.access
        .addSshKey(owner, pubKey)
        .then(function () {
          $('#q-ssh-modal').modal('hide');
          Hive.ui.notify({ title: 'SSH Key Authorized', message: 'Added key to ' + owner + ' authorized_keys.', type: 'success' });
          loadAndRender();
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'SSH Key Rejected', message: err.message || 'Invalid or duplicate key.', type: 'error' });
        })
        .finally(function () {
          $btn.removeClass('loading disabled');
        });
    }

    $(document).on('click.qAccessModal', '#q-ospw-save-btn', saveOsPassword);
    $(document).on('submit.qAccessModal', '#q-ospw-form', function (e) { e.preventDefault(); saveOsPassword(); });
    $(document).on('click.qAccessModal', '#q-ssh-save-btn', saveSshKey);
    $(document).on('submit.qAccessModal', '#q-ssh-form', function (e) { e.preventDefault(); saveSshKey(); });

    state.stateListener = function (e) {
      var reason = e && e.detail ? e.detail.reason : '';
      if (Hive.store.isRuntimeOnlyReason(reason) || reason === 'inline-toggle') return;
      state.access = JSON.parse(JSON.stringify(Hive.store.getState().access));
      renderTables();
    };
    window.addEventListener('hive:statechange', state.stateListener);
  }

  function unmount() {
    state.mountToken += 1;
    $(document).off('.qAccessModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qAccess');
      state.$root = null;
    }
  }

  Hive.router.register('/system/access', {
    title: 'Users & Access',
    group: 'System',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
