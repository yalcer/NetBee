/* ==========================================================================
   Hive — System Module: Backup & System Image (#/system/firmware)
   NetBee OS Running Image / Storage Summary & Verified .tar.gz Backup/Restore
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    system: null,
    pendingRestoreBuffer: null,
    pendingRestoreName: '',
    stateListener: null
  };

  function cleanupDetachedModals() {
    $('#q-restore-confirm-modal').modal('hide').remove();
  }

  function formatDiskMb(mbVal, bytesFallback) {
    var mb = mbVal !== undefined && mbVal !== null ? Number(mbVal) : Number(bytesFallback || 0) / 1048576;
    if (mb >= 1024) return (mb / 1024).toFixed(2) + ' GB';
    return mb.toFixed(1) + ' MB';
  }

  function diskPartitionLabel(mount) {
    if (mount === '/var/log') return '/var/log (RAM tmpfs — SD wear protection)';
    if (mount === '/boot') return '/boot (FAT32 Boot Firmware Partition)';
    if (mount === '/') return '/ (Persistent Root Filesystem)';
    return mount + ' (Mounted Partition)';
  }

  function renderContent() {
    if (!state.$root || !state.system) return;
    var sys = state.system;
    var fmt = Hive.format;
    var esc = fmt.escapeHtml;

    state.$root.find('#q-fw-kpis').html(
      '<div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Running OS Image</span><span class="ui label q-status-success q-mono">Active</span></div><div class="q-kpi-value" style="font-size:18px;">' + esc(sys.firmware || 'NetBee OS') + '</div><div class="q-kpi-sub"><span class="q-mono">' + esc(sys.model || 'Raspberry Pi 5') + '</span></div></div>' +
      '<div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Linux Kernel</span></div><div class="q-kpi-value" style="font-size:18px;">' + esc(sys.kernel || 'Linux aarch64') + '</div><div class="q-kpi-sub"><span class="q-mono">' + esc(sys.arch || 'aarch64') + '</span><span>nftables + CAKE</span></div></div>' +
      '<div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">Root Partition</span></div><div class="q-kpi-value" style="font-size:18px;">' + (sys.rootfsExpanded ? '<span class="q-text-success">Expanded</span>' : '<span class="q-text-warning">Initial Size</span>') + '</div><div class="q-kpi-sub"><span>ext4 + RAM /var/log</span></div></div>' +
      '<div class="q-kpi-card"><div class="q-kpi-head"><span class="q-kpi-label">System Uptime</span></div><div class="q-kpi-value" style="font-size:18px;">' + esc(fmt.uptime(sys.uptimeSeconds || 0)) + '</div><div class="q-kpi-sub"><span class="q-mono">' + esc(sys.fqdn || 'netbee.lan') + '</span></div></div>'
    );

    var disks = Array.isArray(sys.disks) && sys.disks.length
      ? sys.disks
      : [{ mount: '/', total_mb: 0, used_mb: 0, used_pct: 0 }];

    var diskHtml = disks
      .map(function (d) {
        var rawPct = d.used_pct !== undefined ? d.used_pct : d.used_percent;
        var pct = Math.min(100, Math.max(0, Math.round(Number(rawPct || 0))));
        var sev = fmt.progressSeverityClass(pct);
        var label = diskPartitionLabel(d.mount || '/');
        return (
          '<div style="margin-bottom:var(--q-space-3);">' +
          '  <div style="display:flex;justify-content:space-between;margin-bottom:6px;font-size:12.5px;">' +
          '    <strong class="q-mono">' + esc(label) + '</strong>' +
          '    <span class="q-mono q-text-secondary">' + formatDiskMb(d.used_mb, d.used_bytes) + ' / ' + formatDiskMb(d.total_mb, d.total_bytes) + ' (' + pct + '%)</span>' +
          '  </div>' +
          '  <div class="ui tiny ' + sev + ' progress" data-percent="' + pct + '" style="margin:0;"><div class="bar" style="width:' + pct + '%;"></div></div>' +
          '</div>'
        );
      })
      .join('');
    state.$root.find('#q-fw-disks').html(diskHtml);
    if (Hive.icons) Hive.icons.render(state.$root[0]);
  }

  function loadAndRender() {
    var token = state.mountToken;
    Hive.services.firmware.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.system = data.system;
      renderContent();
    });
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.pendingRestoreBuffer = null;
    cleanupDetachedModals();

    Hive.services.firmware.getOverview().then(function (data) {
      if (!state.$root || token !== state.mountToken) return;
      state.system = data.system;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">System &amp; Backup</h1>' +
        '    <p class="q-page-subtitle">Running NetBee OS Buildroot image metadata, partition telemetry, and full <code>.tar.gz</code> configuration backup &amp; restore.</p>' +
        '  </div>' +
        '</div>' +

        '<div class="q-kpi-grid" id="q-fw-kpis"></div>' +

        '<div class="q-backup-grid" style="margin-bottom:var(--q-space-4);">' +
        '  <div class="q-card">' +
        '    <div class="q-card-header">' +
        '      <div>' +
        '        <h2 class="q-card-title"><i data-lucide="download" class="q-icon q-text-accent"></i><span>Download Configuration Backup (<code>.tar.gz</code>)</span></h2>' +
        '        <p class="q-card-subtitle">Exports <code>/var/lib/netbee/state.json</code>, custom <code>nftables</code> rules, WireGuard keys, AdGuardHome config, Dropbear SSH keys, and TLS certs into a verified archive.</p>' +
        '      </div>' +
        '    </div>' +
        '    <button type="button" class="ui primary button" id="q-fw-backup-dl-btn"><i data-lucide="download" class="q-icon q-icon-sm"></i><span>Download .tar.gz Backup</span></button>' +
        '  </div>' +

        '  <div class="q-card">' +
        '    <div class="q-card-header">' +
        '      <div>' +
        '        <h2 class="q-card-title"><i data-lucide="upload" class="q-icon q-text-accent"></i><span>Restore Configuration Archive (<code>.tar.gz</code>)</span></h2>' +
        '        <p class="q-card-subtitle">Validates path safety against traversal/symlinks, restores whitelisted NetBee OS configuration files atomically, and reloads system services.</p>' +
        '      </div>' +
        '    </div>' +
        '    <input type="file" id="q-fw-restore-input" accept=".tar.gz,.tgz,application/gzip,application/x-gzip" hidden>' +
        '    <button type="button" class="ui secondary button" id="q-fw-restore-btn"><i data-lucide="upload" class="q-icon q-icon-sm"></i><span>Select .tar.gz Archive to Restore</span></button>' +
        '  </div>' +
        '</div>' +

        '<div class="q-card">' +
        '  <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="hard-drive" class="q-icon q-text-accent"></i><span>Storage &amp; SD Card Wear-Protection Layout</span></h2><p class="q-card-subtitle">High-frequency syslog and DHCP/DNS runtime logs live in RAM <code>tmpfs</code> to preserve microSD endurance.</p></div></div>' +
        '  <div id="q-fw-disks"></div>' +
        '</div>' +

        // Restore Confirmation Modal
        '<div class="ui mini modal" id="q-restore-confirm-modal" role="dialog" aria-labelledby="q-rest-title">' +
        '  <div class="header">' +
        '    <span class="q-modal-header-title" id="q-rest-title"><i data-lucide="alert-triangle" class="q-icon q-text-warning"></i><span>Restore Backup Archive?</span></span>' +
        '  </div>' +
        '  <div class="content">' +
        '    <p>Overwrite active router configuration with <strong class="q-mono" id="q-rest-filename"></strong> and reload firewall, network, and DNS/DHCP services?</p>' +
        '  </div>' +
        '  <div class="actions">' +
        '    <button type="button" class="ui secondary cancel button">Cancel</button>' +
        '    <button type="button" class="ui primary button" id="q-rest-confirm-btn">Restore Now</button>' +
        '  </div>' +
        '</div>';

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);
      renderContent();
    });

    $container.on('click.qFirmware', '#q-fw-backup-dl-btn', function () {
      var $btn = $(this);
      if ($btn.hasClass('loading')) return;
      $btn.addClass('loading disabled');
      Hive.services.firmware
        .downloadBackup()
        .then(function (res) {
          Hive.ui.downloadBlob(res.filename || 'netbee-backup.tar.gz', res.blob);
          Hive.ui.notify({ title: 'Backup Downloaded', message: 'Saved ' + (res.filename || 'netbee-backup.tar.gz') + '.', type: 'success' });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Backup Failed', message: err.message || 'Could not generate backup archive.', type: 'error' });
        })
        .finally(function () {
          if (state.$root) $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qFirmware', '#q-fw-restore-btn', function () {
      $('#q-fw-restore-input').val('').trigger('click');
    });

    $container.on('change.qFirmware', '#q-fw-restore-input', function () {
      var file = this.files && this.files[0];
      if (!file) return;
      if (file.size > 16 * 1024 * 1024) {
        Hive.ui.notify({ title: 'Archive Too Large', message: 'Backup archive exceeds 16 MB limit.', type: 'error' });
        return;
      }
      file.arrayBuffer().then(function (buf) {
        state.pendingRestoreBuffer = buf;
        state.pendingRestoreName = file.name;
        $('#q-rest-filename').text(file.name);
        Hive.ui.openModal('#q-restore-confirm-modal');
      });
    });

    $(document).on('click.qFirmwareModal', '#q-rest-confirm-btn', function () {
      if (!state.pendingRestoreBuffer) return;
      var $btn = $(this);
      $btn.addClass('loading disabled');
      Hive.services.firmware
        .restoreBackup(state.pendingRestoreBuffer)
        .then(function () {
          state.pendingRestoreBuffer = null;
          $('#q-restore-confirm-modal').modal('hide');
          Hive.ui.notify({ title: 'Configuration Restored', message: 'Archive restored and services reloaded.', type: 'success', displayTime: 4500 });
          loadAndRender();
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Restore Rejected', message: err.message || 'Invalid or corrupted .tar.gz backup archive.', type: 'error', displayTime: 5000 });
        })
        .finally(function () {
          $btn.removeClass('loading disabled');
        });
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
    state.pendingRestoreBuffer = null;
    $(document).off('.qFirmwareModal');
    cleanupDetachedModals();
    if (state.stateListener) {
      window.removeEventListener('hive:statechange', state.stateListener);
      state.stateListener = null;
    }
    if (state.$root) {
      state.$root.off('.qFirmware');
      state.$root = null;
    }
  }

  Hive.router.register('/system/firmware', {
    title: 'System & Backup',
    group: 'System',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
