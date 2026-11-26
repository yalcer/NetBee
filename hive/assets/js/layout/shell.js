/* ==========================================================================
   Hive — Application Shell Controller (Auth, Live SSE Stream & 60s Rollback)
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});
  var SIDEBAR_KEY = (Hive.config && Hive.config.storageKeys.sidebarCollapsed) || 'hive.sidebarCollapsed';
  var MOBILE_BREAKPOINT = 992;

  var sseSource = null;
  var sseReconnectTimer = null;
  var rollbackInterval = null;
  var rollbackExpiresMs = 0;
  var routerStarted = false;

  function safeEscape(str) {
    if (Hive.format && Hive.format.escapeHtml) return Hive.format.escapeHtml(str);
    return String(str === undefined || str === null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function renderSidebarNav(pageType) {
    var $container = $('#q-sidebar-nav-groups');
    if (!$container.length) return;

    var groups = (Hive.config && Hive.config.navigation) || [];
    var html = '';

    groups.forEach(function (group) {
      html += '<div class="q-nav-group" role="group" aria-labelledby="q-nav-group-' + group.id + '">';
      html += '<div class="q-nav-group-label" id="q-nav-group-' + group.id + '">' + group.label + '</div>';
      html += '<ul class="q-nav-list">';

      group.items.forEach(function (item) {
        var href = pageType === 'design-system' ? 'index.html#' + item.route : '#' + item.route;
        html += '<li>';
        html +=
          '<a href="' +
          href +
          '" class="q-nav-item" data-q-route="' +
          item.route +
          '" data-q-label="' +
          item.label +
          '" title="' +
          item.label +
          '">';
        html += '<i data-lucide="' + item.icon + '" class="q-icon"></i>';
        html += '<span class="q-nav-label">' + item.label + '</span>';
        html += '</a>';
        html += '</li>';
      });

      html += '</ul></div>';
    });

    $container.html(html);
  }

  function updateBreadcrumbs(segments) {
    var html = '<ol>';
    segments.forEach(function (seg, idx) {
      var isLast = idx === segments.length - 1;
      html += '<li>';
      if (idx > 0) {
        html += '<span class="q-breadcrumb-sep" aria-hidden="true">/</span>';
      }
      if (isLast) {
        html += '<span class="q-breadcrumb-current" aria-current="page">' + safeEscape(seg.label) + '</span>';
      } else if (seg.href) {
        html += '<a class="q-breadcrumb-link" href="' + safeEscape(seg.href) + '">' + safeEscape(seg.label) + '</a>';
      } else {
        html += '<span>' + safeEscape(seg.label) + '</span>';
      }
      html += '</li>';
    });
    html += '</ol>';

    $('[data-q-breadcrumbs]').html(html);
  }

  function syncCollapsedTooltips(collapsed) {
    var $items = $('#q-sidebar .q-nav-item');
    if (!$items.length || typeof $items.popup !== 'function') return;

    $items.popup('destroy');
    if (collapsed && window.innerWidth > MOBILE_BREAKPOINT) {
      $items.each(function () {
        var $el = $(this);
        var label = $el.attr('data-q-label') || $el.find('.q-nav-label').text();
        if (label) {
          $el.removeAttr('title');
          $el.popup({
            content: label,
            position: 'right center',
            variation: 'mini',
            delay: { show: 80, hide: 0 }
          });
        }
      });
    } else {
      $items.each(function () {
        var $el = $(this);
        var label = $el.attr('data-q-label') || $el.find('.q-nav-label').text();
        if (label) $el.attr('title', label);
      });
    }
  }

  function setDesktopCollapsed(collapsed) {
    var root = document.documentElement;
    root.classList.toggle('q-sidebar-collapsed', collapsed);
    $('[data-q-sidebar-toggle]').attr('aria-expanded', String(!collapsed));
    syncCollapsedTooltips(collapsed);

    try {
      window.localStorage.setItem(SIDEBAR_KEY, String(collapsed));
    } catch (err) {
      // Ignore storage errors
    }
  }

  function setMobileDrawer(open) {
    var root = document.documentElement;
    root.classList.toggle('q-mobile-nav-open', open);
    $('[data-q-mobile-menu]').attr('aria-expanded', String(open));
    $('#q-sidebar').attr('aria-hidden', window.innerWidth <= MOBILE_BREAKPOINT ? String(!open) : 'false');
  }

  function syncHostnameDisplay() {
    if (!Hive.store) return;
    var st = Hive.store.getState();
    var sys = st.system || {};
    var host = sys.hostname || 'netbee';
    $('[data-q-host-label]').text(host);
    $('[data-q-login-host]').text(host + '.lan');
    $('[data-q-copy-host]').attr('data-q-copy-host', host).attr('aria-label', 'Copy appliance hostname ' + host);
    $('[data-q-fqdn-label]').text(sys.fqdn || (host + '.lan'));
    $('[data-q-mgmt-endpoint]').text((window.location.host || ((st.lanConfig && st.lanConfig.ip) || '192.168.10.1') + ':443'));
    if (sys.firmware) {
      $('[data-q-os-version]').text(sys.firmware);
    }
    if (Hive.auth) {
      var sess = Hive.auth.getSession();
      var uname = sess.username || 'admin';
      $('[data-q-user-name]').text(uname);
      $('[data-q-session-user]').text(uname);
      $('[data-q-user-initials]').text(uname.slice(0, 2).toUpperCase());
      $('[data-q-session-exp]').text(sess.expiresAt ? String(sess.expiresAt).replace('T', ' ').slice(0, 19) : 'Active');
    }
  }

  /* ---- Staged Diff & 60-Second Server Auto-Rollback Dock ---- */

  function syncStagedIndicator() {
    if (!Hive.services || !Hive.services.staging) return;
    var list = Hive.services.staging.list();
    var count = list.length;
    var $btn = $('#q-pending-btn');
    var $dock = $('#q-staged-banner');
    var rollbackVisible = $('#q-rollback-banner').hasClass('is-visible');
    var wasVisible = $dock.hasClass('is-visible');

    $('[data-q-pending-count]').text(count);

    if (count > 0 && !rollbackVisible) {
      var latest = list[0];
      var summary = latest ? latest.summary : 'Staged edits ready to apply.';
      if (count > 1) {
        summary += ' (+' + (count - 1) + ' more)';
      }
      $('[data-q-pending-summary]').text(summary).attr('title', summary);
      $btn.removeAttr('hidden');
      if (!wasVisible) {
        $dock.removeClass('is-minimized');
        $('[data-q-staged-minimize]').attr('aria-expanded', 'true');
      }
      $dock.addClass('is-visible').attr('aria-hidden', 'false');
    } else {
      if (count === 0) $btn.attr('hidden', true);
      else $btn.removeAttr('hidden');
      $dock.removeClass('is-visible is-minimized').attr('aria-hidden', 'true');
      if (count === 0 && $('#q-staged-modal').hasClass('active')) {
        $('#q-staged-modal').modal('hide');
      }
    }
  }

  function clearRollbackTimer() {
    if (rollbackInterval) {
      window.clearInterval(rollbackInterval);
      rollbackInterval = null;
    }
    rollbackExpiresMs = 0;
    $('#q-rollback-banner').removeClass('is-visible').attr('aria-hidden', 'true');
    syncStagedIndicator();
  }

  function syncRollbackBanner(status) {
    if (!status || !status.pending) {
      clearRollbackTimer();
      return;
    }
    var rem = Math.max(1, Number(status.remaining_seconds || 60));
    rollbackExpiresMs = Date.now() + rem * 1000;
    $('#q-rollback-reason').text((status.reason || 'Configuration change') + ' — confirm or auto-reverts.');
    $('#q-rollback-countdown').text(rem + 's');
    $('#q-staged-banner').removeClass('is-visible').attr('aria-hidden', 'true');
    $('#q-rollback-banner').addClass('is-visible').attr('aria-hidden', 'false');
    if (Hive.icons) Hive.icons.render();

    if (rollbackInterval) window.clearInterval(rollbackInterval);
    rollbackInterval = window.setInterval(function () {
      var left = Math.max(0, Math.ceil((rollbackExpiresMs - Date.now()) / 1000));
      $('#q-rollback-countdown').text(left + 's');
      if (left <= 0) {
        clearRollbackTimer();
        Hive.ui.notify({
          title: 'Auto-Rollback Triggered',
          message: 'Unconfirmed changes expired and reverted on the router.',
          type: 'warning',
          displayTime: 5000
        });
        if (Hive.services && Hive.services.bootstrapAll) {
          Hive.services.bootstrapAll();
        }
      }
    }, 1000);
  }

  function openStagedReviewModal() {
    if (!Hive.services || !Hive.services.staging) return;
    var list = Hive.services.staging.list();
    var esc = safeEscape;
    var $list = $('#q-staged-diff-list');

    if (!list.length) {
      $list.html('<p class="q-text-muted" style="margin:0;">No pending configuration changes.</p>');
    } else {
      var badgeMap = {
        ADD: 'q-status-success',
        EDIT: 'q-status-info',
        DELETE: 'q-status-danger',
        REORDER: 'q-status-warning'
      };
      var html = list
        .map(function (item) {
          return (
            '<div class="q-diff-item">' +
            '  <div class="q-diff-main">' +
            '    <span class="ui label ' + (badgeMap[item.action] || '') + ' q-badge-square q-mono">' + esc(item.action) + '</span>' +
            '    <div>' +
            '      <div class="q-diff-summary">' + esc(item.summary) + '</div>' +
            '      <div class="q-diff-detail"><span class="q-mono">' + esc(item.module) + '</span>' + (item.detail ? ' · ' + esc(item.detail) : '') + '</div>' +
            '    </div>' +
            '  </div>' +
            '  <span class="q-diff-time">' + esc(item.timestamp) + '</span>' +
            '</div>'
          );
        })
        .join('');
      $list.html(html);
    }

    Hive.ui.openModal('#q-staged-modal');
  }

  /* ---- Live SSE Telemetry Stream (/api/v1/system/stream) ---- */

  function stopTelemetryStream() {
    if (sseReconnectTimer) {
      window.clearTimeout(sseReconnectTimer);
      sseReconnectTimer = null;
    }
    if (sseSource) {
      try {
        sseSource.close();
      } catch (err) {}
      sseSource = null;
    }
  }

  function startTelemetryStream() {
    stopTelemetryStream();
    if (!window.EventSource || !Hive.auth || !Hive.auth.isAuthenticated()) return;

    try {
      sseSource = new window.EventSource('/api/v1/system/stream');
    } catch (err) {
      return;
    }

    sseSource.onopen = function () {
      $('[data-q-stream-dot]').removeClass('is-warning is-danger').addClass('is-success');
    };

    sseSource.onmessage = function (ev) {
      if (!ev || !ev.data || !Hive.store) return;
      var frame = null;
      try {
        frame = JSON.parse(ev.data);
      } catch (e) {
        return;
      }
      Hive.store.updateTelemetry(function (sys, st) {
        sys.cpuPercent = Math.round(Number(frame.cpu_pct || 0));
        if (frame.cpu_freq_mhz !== undefined) sys.cpuFreqMhz = frame.cpu_freq_mhz;
        if (frame.mem_used_mb !== undefined) sys.memUsedMb = Number(frame.mem_used_mb);
        if (frame.mem_total_mb !== undefined) sys.memTotalMb = Number(frame.mem_total_mb);
        sys.memUsedGb = Number((sys.memUsedMb / 1024).toFixed(2));
        sys.memTotalGb = Number((sys.memTotalMb / 1024).toFixed(2));
        if (Array.isArray(frame.load_avg)) sys.loadAvg = frame.load_avg;
        if (frame.uptime_seconds !== undefined) sys.uptimeSeconds = Number(frame.uptime_seconds);
        if (frame.cpu_temp_c !== undefined) sys.cpuTempC = frame.cpu_temp_c;
        if (frame.fan_rpm !== undefined) sys.fanRpm = frame.fan_rpm;
        sys.undervoltage = Boolean(frame.undervoltage);
        if (frame.conntrack_count !== undefined) sys.statesActive = Number(frame.conntrack_count);

        var rates = frame.interfaces || {};
        var wanDev = (sys.gateways && sys.gateways[0] && sys.gateways[0].iface) || (st.wanConfig && st.wanConfig.interface) || 'eth1';
        if (rates.ppp0 && (st.wanConfig.mode === 'pppoe' || st.wanConfig.mode === 'ont_vlan')) {
          wanDev = 'ppp0';
        }
        var wanRate = rates[wanDev] || rates[st.wanConfig.interface] || { rx_bps: 0, tx_bps: 0 };
        var wanRxMbps = Number((((Number(wanRate.rx_bps) || 0) * 8) / 1e6).toFixed(2));
        var wanTxMbps = Number((((Number(wanRate.tx_bps) || 0) * 8) / 1e6).toFixed(2));

        var nowLabel = Hive.format ? Hive.format.clockNow() : '';
        if (!Array.isArray(sys.throughput['15m'])) sys.throughput['15m'] = [];
        if (sys.throughput['15m'].length === 1 && sys.throughput['15m'][0].label === 'Now') {
          sys.throughput['15m'] = [];
        }
        sys.throughput['15m'].push({ label: nowLabel, rx: wanRxMbps, tx: wanTxMbps });
        if (sys.throughput['15m'].length > 30) sys.throughput['15m'].shift();

        (st.interfaces || []).forEach(function (ifc) {
          var r = rates[ifc.device];
          if (r) {
            ifc.rxMbps = Number((((Number(r.rx_bps) || 0) * 8) / 1e6).toFixed(2));
            ifc.txMbps = Number((((Number(r.tx_bps) || 0) * 8) / 1e6).toFixed(2));
            if (r.rx_bytes !== undefined) ifc.rxTotalGb = Number(((Number(r.rx_bytes) || 0) / 1073741824).toFixed(2));
            if (r.tx_bytes !== undefined) ifc.txTotalGb = Number(((Number(r.tx_bytes) || 0) / 1073741824).toFixed(2));
          }
        });
      });
    };

    sseSource.onerror = function () {
      $('[data-q-stream-dot]').removeClass('is-success').addClass('is-warning');
      stopTelemetryStream();
      if (Hive.auth && Hive.auth.isAuthenticated()) {
        sseReconnectTimer = window.setTimeout(startTelemetryStream, 4000);
      }
    };
  }

  /* ---- Login / Session Lifecycle ---- */

  function showLoginScreen(errMessage) {
    stopTelemetryStream();
    clearRollbackTimer();
    $('#q-app-shell').attr('hidden', true);
    $('#q-staged-banner').removeClass('is-visible').attr('aria-hidden', 'true');
    $('#q-login-screen').removeAttr('hidden');
    if (errMessage) {
      $('#q-login-error').text(errMessage).removeAttr('hidden');
    } else {
      $('#q-login-error').attr('hidden', true).text('');
    }
    if (Hive.icons) Hive.icons.render();
    window.setTimeout(function () {
      $('#q-login-pass').trigger('focus');
    }, 50);
  }

  function enterAuthenticatedShell(session) {
    $('#q-login-screen').attr('hidden', true);
    $('#q-login-error').attr('hidden', true);
    $('#q-login-pass').val('');
    $('#q-app-shell').removeAttr('hidden');

    syncHostnameDisplay();

    if (session && session.mustChangePassword) {
      $('#q-notif-dot').removeAttr('hidden');
      $('#q-notif-list').prepend(
        '<div class="item q-notif-item">' +
        '  <span class="q-status-dot is-warning" style="margin-top: 6px;"></span>' +
        '  <div>' +
        '    <div class="q-notif-item-title">Default Password Active</div>' +
        '    <div class="q-notif-item-meta">Open <strong>Users &amp; Access</strong> to set a strong administrator password.</div>' +
        '  </div>' +
        '</div>'
      );
      Hive.ui.notify({
        title: 'Security Notice',
        message: 'Default Web API password is still active. Please update it in Users & Access.',
        type: 'warning',
        displayTime: 5500
      });
    }

    Hive.services
      .bootstrapAll()
      .catch(function () {})
      .then(function () {
        syncHostnameDisplay();
        syncStagedIndicator();
        if (!routerStarted && Hive.router) {
          routerStarted = true;
          Hive.router.start();
        } else if (Hive.router) {
          Hive.router.resolve();
        }
        startTelemetryStream();
      });
  }

  /* ---- Quick Command Palette (Ctrl+K / Cmd+K) ---- */

  var cmdState = { items: [], selectedIdx: 0 };

  function buildCommandItems(query) {
    var q = String(query || '').toLowerCase().trim();
    var all = [];

    var groups = (Hive.config && Hive.config.navigation) || [];
    groups.forEach(function (g) {
      (g.items || []).forEach(function (item) {
        all.push({
          group: 'Navigation',
          label: g.label + ' → ' + item.label,
          sub: item.route,
          icon: item.icon,
          keywords: (g.label + ' ' + item.label + ' ' + item.route + ' ' + (item.description || '')).toLowerCase(),
          run: function () {
            if (Hive.router) Hive.router.navigate(item.route);
          }
        });
      });
    });

    if (Hive.store) {
      var st = Hive.store.getState();
      (st.interfaces || []).forEach(function (iface) {
        all.push({
          group: 'Interfaces',
          label: iface.device + ' — ' + iface.label,
          sub: iface.ipv4,
          icon: 'network',
          keywords: (iface.device + ' ' + iface.label + ' ' + iface.ipv4 + ' ' + iface.zone).toLowerCase(),
          run: function () {
            if (Hive.router) Hive.router.navigate('/network/interfaces');
          }
        });
      });

      ((st.vpn && st.vpn.wireguard && st.vpn.wireguard.peers) || []).forEach(function (peer) {
        all.push({
          group: 'WireGuard Peers',
          label: peer.name,
          sub: peer.allowedIps,
          icon: 'lock-keyhole',
          keywords: (peer.name + ' ' + peer.allowedIps + ' wireguard vpn').toLowerCase(),
          run: function () {
            if (Hive.router) Hive.router.navigate('/security/vpn');
          }
        });
      });

      (st.daemons || []).forEach(function (svc) {
        all.push({
          group: 'System Daemons',
          label: svc.name + ' (' + svc.status + ')',
          sub: 'PID ' + svc.pid,
          icon: 'cpu',
          keywords: (svc.name + ' ' + svc.description + ' daemon service restart').toLowerCase(),
          run: function () {
            if (Hive.router) Hive.router.navigate('/system/settings');
          }
        });
      });
    }

    all.push({
      group: 'Actions',
      label: 'Toggle Theme (Dark Honey / Light Honey)',
      sub: 'Alt+T',
      icon: 'contrast',
      keywords: 'theme dark light honey switch appearance',
      run: function () {
        if (Hive.theme) Hive.theme.toggle({ notify: true });
      }
    });

    all.push({
      group: 'Actions',
      label: 'Sign Out',
      sub: 'End Session',
      icon: 'log-out',
      keywords: 'logout sign out exit session',
      run: function () {
        if (Hive.auth) Hive.auth.logout();
      }
    });

    if (!q) return all;
    return all.filter(function (entry) {
      return entry.keywords.indexOf(q) !== -1 || entry.label.toLowerCase().indexOf(q) !== -1;
    });
  }

  function renderCommandList(query) {
    var $list = $('#q-cmd-list');
    if (!$list.length) return;
    var esc = safeEscape;
    cmdState.items = buildCommandItems(query);
    cmdState.selectedIdx = 0;

    if (!cmdState.items.length) {
      $list.html('<div class="q-empty-state" style="padding:24px;">No matching routes, interfaces, or actions.</div>');
      return;
    }

    var lastGroup = '';
    var html = '';
    cmdState.items.forEach(function (item, idx) {
      if (item.group !== lastGroup) {
        html += '<div class="q-cmd-group">' + esc(item.group) + '</div>';
        lastGroup = item.group;
      }
      html +=
        '<button type="button" class="q-cmd-item' + (idx === 0 ? ' is-selected' : '') + '" data-cmd-idx="' + idx + '">' +
        '  <span class="q-cmd-item-left"><i data-lucide="' + esc(item.icon) + '" class="q-icon q-icon-sm"></i><span>' + esc(item.label) + '</span></span>' +
        '  <span class="q-cmd-item-sub">' + esc(item.sub) + '</span>' +
        '</button>';
    });
    $list.html(html);
    if (Hive.icons) Hive.icons.render();
  }

  function openCommandPalette() {
    if (!Hive.auth || !Hive.auth.isAuthenticated()) return;
    var $modal = $('#q-cmd-modal');
    if (!$modal.length) return;
    $('#q-cmd-input').val('');
    renderCommandList('');
    Hive.ui.openModal('#q-cmd-modal', {
      onVisible: function () {
        $('#q-cmd-input').trigger('focus');
      }
    });
  }

  function executeCommandAt(idx) {
    var item = cmdState.items[idx];
    if (!item) return;
    $('#q-cmd-modal').modal('hide');
    item.run();
  }

  function bindShellEvents(pageType) {
    // Login form submission & password visibility toggle
    $(document).on('click', '#q-login-toggle-pw', function () {
      var $inp = $('#q-login-pass');
      var isPw = $inp.attr('type') === 'password';
      $inp.attr('type', isPw ? 'text' : 'password');
    });

    $(document).on('submit', '#q-login-form', function (e) {
      e.preventDefault();
      var user = $('#q-login-user').val();
      var pass = $('#q-login-pass').val();
      var $btn = $('#q-login-submit');
      $('#q-login-error').attr('hidden', true);
      $btn.addClass('loading disabled').prop('disabled', true);

      Hive.auth
        .login(user, pass)
        .then(function (sess) {
          enterAuthenticatedShell(sess);
        })
        .catch(function (err) {
          $('#q-login-error').text(err && err.message ? err.message : 'Invalid username or password.').removeAttr('hidden');
        })
        .then(function () {
          $btn.removeClass('loading disabled').prop('disabled', false);
        });
    });

    window.addEventListener('hive:unauthorized', function () {
      showLoginScreen('Your session has ended. Please sign in again.');
    });

    window.addEventListener('hive:pendingcommit', function (e) {
      syncRollbackBanner(e.detail);
    });

    $(document).on('click', '[data-q-sidebar-toggle]', function () {
      var isCollapsed = document.documentElement.classList.contains('q-sidebar-collapsed');
      setDesktopCollapsed(!isCollapsed);
    });

    $(document).on('click', '[data-q-mobile-menu]', function () {
      var isOpen = document.documentElement.classList.contains('q-mobile-nav-open');
      setMobileDrawer(!isOpen);
    });

    $(document).on('click', '[data-q-drawer-close], #q-sidebar-backdrop', function () {
      setMobileDrawer(false);
    });

    $(document).on('click', '.q-nav-item', function () {
      if (window.innerWidth <= MOBILE_BREAKPOINT) {
        setMobileDrawer(false);
      }
    });

    if (pageType === 'shell') {
      $(document).on('click', '#q-return-shell-btn', function (e) {
        e.preventDefault();
        if (Hive.router) Hive.router.navigate('/overview/system');
      });

      $(document).on('click', '[data-q-open-staged]', openStagedReviewModal);

      $(document).on('click', '[data-q-staged-minimize]', function () {
        var $dock = $('#q-staged-banner');
        var minimized = $dock.toggleClass('is-minimized').hasClass('is-minimized');
        $(this).attr('aria-expanded', String(!minimized));
      });

      $(document).on('click', '[data-q-apply-staged]', function () {
        if (!Hive.services || !Hive.services.staging) return;
        var $btns = $('[data-q-apply-staged]');
        $btns.addClass('loading disabled').prop('disabled', true);
        Hive.services.staging
          .apply()
          .then(function (result) {
            $('#q-staged-modal').modal('hide');
            if (!result || !result.count) return;
            if (result.pendingCommit && result.pendingCommit.pending) {
              syncRollbackBanner(result.pendingCommit);
            }
            if (result.newUrl) {
              Hive.ui.notify({
                title: 'LAN IP Updated',
                message: 'Router management moved to ' + result.newUrl + '. Open and confirm within 60s!',
                type: 'warning',
                displayTime: 8000
              });
            } else {
              Hive.ui.notify({
                title: 'Changes Applied',
                message: 'Committed ' + result.count + ' configuration ' + (result.count === 1 ? 'change' : 'changes') + ' to NetBee OS.',
                type: 'success'
              });
            }
            if (Hive.router) Hive.router.resolve();
          })
          .catch(function (err) {
            Hive.ui.notify({
              title: 'Apply Failed',
              message: err && err.message ? err.message : 'Backend rejected configuration update.',
              type: 'error',
              displayTime: 5500
            });
          })
          .then(function () {
            $btns.removeClass('loading disabled').prop('disabled', false);
          });
      });

      $(document).on('click', '[data-q-discard-staged]', function () {
        if (!Hive.services || !Hive.services.staging) return;
        Hive.services.staging.discard().then(function (discarded) {
          $('#q-staged-modal').modal('hide');
          if (!discarded) return;
          Hive.ui.notify({
            title: 'Staged Changes Discarded',
            message: 'Reverted ' + discarded + ' uncommitted ' + (discarded === 1 ? 'edit' : 'edits') + '.',
            type: 'warning'
          });
          if (Hive.router) Hive.router.resolve();
        });
      });

      // 60s Server Rollback Confirm & Revert actions
      $(document).on('click', '#q-rollback-confirm-btn', function () {
        var $btn = $(this).addClass('loading disabled');
        Hive.services.system
          .confirmCommit()
          .then(function () {
            clearRollbackTimer();
            Hive.ui.notify({
              title: 'Configuration Confirmed',
              message: 'Changes permanently committed; auto-rollback timer disarmed.',
              type: 'success'
            });
          })
          .catch(function (err) {
            Hive.ui.notify({ title: 'Confirm Failed', message: err.message, type: 'error' });
          })
          .then(function () {
            $btn.removeClass('loading disabled');
          });
      });

      $(document).on('click', '#q-rollback-revert-btn', function () {
        var $btn = $(this).addClass('loading disabled');
        Hive.services.system
          .rollbackNow()
          .then(function () {
            clearRollbackTimer();
            Hive.ui.notify({
              title: 'Reverted Previous Configuration',
              message: 'Restored pre-change router state immediately.',
              type: 'warning'
            });
            if (Hive.router) Hive.router.resolve();
          })
          .catch(function (err) {
            Hive.ui.notify({ title: 'Rollback Failed', message: err.message, type: 'error' });
          })
          .then(function () {
            $btn.removeClass('loading disabled');
          });
      });

      window.addEventListener('hive:statechange', function (e) {
        syncStagedIndicator();
        if (!e.detail || e.detail.reason !== 'telemetry') {
          syncHostnameDisplay();
        }
      });
    }

    // Generic copy-to-clipboard
    $(document).on('click', '[data-q-copy], [data-q-copy-host]', function () {
      var $el = $(this);
      var text = $el.attr('data-q-copy') || $el.attr('data-q-copy-host') || 'netbee';
      var label = $el.attr('data-q-copy-label') || 'Host identifier';
      var preview = text.length > 26 ? text.slice(0, 22) + '...' : text;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(function () {});
      }
      Hive.ui.notify({
        title: 'Copied to Clipboard',
        message: label + ' (' + preview + ') copied.',
        type: 'success',
        displayTime: 2200
      });
    });

    // Notifications clear
    $(document).on('click', '[data-q-clear-notifs]', function (e) {
      e.preventDefault();
      e.stopPropagation();
      $(this).prop('disabled', true).addClass('disabled').text('All read');
      $('#q-notif-dot').attr('hidden', true);
    });

    // Profile Menu Actions
    $(document).on('click', '[data-q-action="open-shortcuts"]', function () {
      Hive.ui.openModal('#q-shortcuts-modal');
    });

    $(document).on('click', '[data-q-action="open-session"]', function () {
      syncHostnameDisplay();
      Hive.ui.openModal('#q-session-modal');
    });

    $(document).on('click', '[data-q-action="toggle-theme"]', function () {
      Hive.theme.toggle({ notify: true });
    });

    $(document).on('click', '[data-q-action="reboot-router"]', function () {
      if (!window.confirm('Reboot NetBee OS router now? Active network sessions will briefly drop.')) return;
      Hive.services.settings
        .reboot()
        .then(function () {
          Hive.ui.notify({
            title: 'Rebooting Router',
            message: 'NetBee OS is restarting. Reconnecting when HTTPS comes back online...',
            type: 'warning',
            displayTime: 8000
          });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Reboot Failed', message: err.message, type: 'error' });
        });
    });

    $(document).on('click', '[data-q-action="sign-out"]', function () {
      Hive.auth.logout();
    });

    // Quick Command Palette
    $(document).on('click', '[data-q-open-cmd]', openCommandPalette);
    $(document).on('input', '#q-cmd-input', function () {
      renderCommandList($(this).val());
    });
    $(document).on('click', '#q-cmd-list .q-cmd-item', function () {
      executeCommandAt(Number($(this).attr('data-cmd-idx')));
    });
    $(document).on('keydown', '#q-cmd-input', function (e) {
      if (!cmdState.items.length) return;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        cmdState.selectedIdx = (cmdState.selectedIdx + 1) % cmdState.items.length;
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        cmdState.selectedIdx = (cmdState.selectedIdx - 1 + cmdState.items.length) % cmdState.items.length;
      } else if (e.key === 'Enter') {
        e.preventDefault();
        executeCommandAt(cmdState.selectedIdx);
        return;
      } else {
        return;
      }
      var $items = $('#q-cmd-list .q-cmd-item');
      $items.removeClass('is-selected').eq(cmdState.selectedIdx).addClass('is-selected')[0].scrollIntoView({ block: 'nearest' });
    });

    // Global Keyboard Shortcuts
    $(document).on('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        if (Hive.auth && Hive.auth.isAuthenticated()) {
          e.preventDefault();
          openCommandPalette();
        }
        return;
      }

      var tag = (e.target.tagName || '').toLowerCase();
      var isInput = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable;

      if (e.key === 'Escape' && document.documentElement.classList.contains('q-mobile-nav-open')) {
        setMobileDrawer(false);
        return;
      }

      if (isInput) return;

      if (e.key === '[' && !e.ctrlKey && !e.metaKey && !e.altKey && window.innerWidth > MOBILE_BREAKPOINT) {
        e.preventDefault();
        var isCollapsed = document.documentElement.classList.contains('q-sidebar-collapsed');
        setDesktopCollapsed(!isCollapsed);
      } else if (e.altKey && (e.key === 't' || e.key === 'T')) {
        e.preventDefault();
        Hive.theme.toggle({ notify: true });
      }
    });

    var wasMobileViewport = window.innerWidth <= MOBILE_BREAKPOINT;
    var resizeTimer = null;
    $(window).on('resize', function () {
      var isMobile = window.innerWidth <= MOBILE_BREAKPOINT;
      if (!isMobile && document.documentElement.classList.contains('q-mobile-nav-open')) {
        setMobileDrawer(false);
      }
      if (isMobile !== wasMobileViewport) {
        wasMobileViewport = isMobile;
        if (resizeTimer) window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(function () {
          syncCollapsedTooltips(document.documentElement.classList.contains('q-sidebar-collapsed'));
        }, 120);
      }
    });
  }

  function init() {
    var pageType = document.body.getAttribute('data-q-page') || 'shell';

    renderSidebarNav(pageType);

    if (Hive.theme) Hive.theme.init();
    if (Hive.icons) Hive.icons.render();
    if (Hive.ui) Hive.ui.init(document);

    $('.q-header-dropdown').dropdown({
      action: 'hide',
      transition: 'fade down',
      duration: 140
    });

    bindShellEvents(pageType);
    syncCollapsedTooltips(document.documentElement.classList.contains('q-sidebar-collapsed'));

    if (pageType === 'design-system') {
      updateBreadcrumbs([
        { label: 'Hive', href: 'index.html#/overview/system' },
        { label: 'Design System' }
      ]);
      return;
    }

    // Probe active netbeed session before revealing shell or login screen
    Hive.auth.checkSession().then(function (sess) {
      if (sess && sess.authenticated) {
        enterAuthenticatedShell(sess);
      } else {
        showLoginScreen();
      }
    });
  }

  Hive.shell = {
    init: init,
    updateBreadcrumbs: updateBreadcrumbs,
    setDesktopCollapsed: setDesktopCollapsed,
    setMobileDrawer: setMobileDrawer,
    syncStagedIndicator: syncStagedIndicator,
    syncRollbackBanner: syncRollbackBanner
  };

  $(document).ready(function () {
    Hive.shell.init();
  });
})(window, window.jQuery);
