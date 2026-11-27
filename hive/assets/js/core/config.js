/* ==========================================================================
   Hive — Application Configuration, Navigation Manifest, Auth & Live API Client
   Connected to NetBee OS backend daemon (netbeed) over HTTPS + CSRF + SSE.
   ========================================================================== */
(function (window) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});
  var CSRF_SESSION_KEY = 'hive.csrfToken';

  Hive.config = {
    appName: 'Hive',
    slogan: 'NetBee OS Firewall',
    version: '0.1.0',
    storageKeys: {
      theme: 'hive.theme',
      sidebarCollapsed: 'hive.sidebarCollapsed',
      activeRoute: 'hive.activeRoute'
    },
    host: {
      hostname: 'netbee',
      domain: 'lan',
      managementIp: '192.168.10.1',
      operator: 'admin',
      operatorInitials: 'AD',
      role: 'Administrator'
    },
    navigation: [
      {
        id: 'overview',
        label: 'Overview',
        items: [
          {
            id: 'overview-home',
            label: 'System Overview',
            icon: 'layout-dashboard',
            route: '/overview/system',
            group: 'Overview',
            status: 'active',
            description: 'Raspberry Pi 5 hardware health, WAN/LAN throughput, gateways, and storage telemetry.'
          },
          {
            id: 'overview-flows',
            label: 'Flow Summary',
            icon: 'waves',
            route: '/overview/flows',
            group: 'Overview',
            status: 'active',
            description: 'Live nf_conntrack sessions, protocol breakdown, state inspection, and flow termination.'
          }
        ]
      },
      {
        id: 'network',
        label: 'Network',
        items: [
          {
            id: 'network-interfaces',
            label: 'Interfaces',
            icon: 'network',
            route: '/network/interfaces',
            group: 'Network',
            status: 'active',
            description: 'Configure LAN (eth0), WAN (DHCP / PPPoE / ONT VLAN), IPv6 SLAAC/PD, and ethtool NIC offloads.'
          },
          {
            id: 'network-routing',
            label: 'Routing & Gateways',
            icon: 'git-fork',
            route: '/network/routing',
            group: 'Network',
            status: 'active',
            description: 'WAN upstream gateway status, persisted static IPv4/IPv6 routes, LPM lookup, and ARP/NDP neighbors.'
          },
          {
            id: 'network-dhcp-dns',
            label: 'DHCP & DNS',
            icon: 'globe',
            route: '/network/services',
            group: 'Network',
            status: 'active',
            description: 'AdGuardHome LAN DHCP pool, active leases, static MAC reservations, upstream DNS, and rewrites.'
          },
          {
            id: 'network-sqm',
            label: 'SQM QoS',
            icon: 'gauge',
            route: '/network/sqm',
            group: 'Network',
            status: 'active',
            description: 'CAKE anti-bufferbloat queue management, ingress/egress shaping, and framing overhead.'
          },
          {
            id: 'network-diagnostics',
            label: 'Diagnostics',
            icon: 'terminal',
            route: '/network/diagnostics',
            group: 'Network',
            status: 'active',
            description: 'Live Ping, MTR traceroute, nslookup, bounded tcpdump packet capture, and iperf3 benchmark.'
          }
        ]
      },
      {
        id: 'security',
        label: 'Security',
        items: [
          {
            id: 'security-firewall',
            label: 'Firewall Rules',
            icon: 'shield',
            route: '/security/firewall',
            group: 'Security',
            status: 'active',
            description: 'nftables input/forward filter rules, flow offload, custom raw .nft snippets, and ruleset viewer.'
          },
          {
            id: 'security-nat',
            label: 'NAT & Port Forward',
            icon: 'arrow-left-right',
            route: '/security/nat',
            group: 'Security',
            status: 'active',
            description: 'Inbound WAN port forwarding (DNAT) rules with optional source CIDR restriction and WAN masquerade.'
          },
          {
            id: 'security-vpn',
            label: 'WireGuard VPN',
            icon: 'lock-keyhole',
            route: '/security/vpn',
            group: 'Security',
            status: 'active',
            description: 'Kernel WireGuard server configuration, Curve25519/PSK peer provisioning, and .conf export.'
          },
          {
            id: 'security-adblock',
            label: 'Ad/Tracker Block',
            icon: 'shield-alert',
            route: '/security/adblock',
            group: 'Security',
            status: 'active',
            description: 'AdGuardHome filter lists, custom block/allowlist domains, one-click blocked services, and query log.'
          }
        ]
      },
      {
        id: 'system',
        label: 'System',
        items: [
          {
            id: 'system-settings',
            label: 'General & Services',
            icon: 'sliders-horizontal',
            route: '/system/settings',
            group: 'System',
            status: 'active',
            description: 'Hostname, timezone, Chrony NTP, system daemons, scheduled cron jobs, sysctl tuning, and power.'
          },
          {
            id: 'system-access',
            label: 'Users & Access',
            icon: 'users',
            route: '/system/access',
            group: 'System',
            status: 'active',
            description: 'Web & OS account passwords (root/netbee), Dropbear SSH policy & authorized keys, and HTTPS TLS.'
          },
          {
            id: 'system-firmware',
            label: 'System & Backup',
            icon: 'hard-drive',
            route: '/system/firmware',
            group: 'System',
            status: 'active',
            description: 'NetBee OS build & kernel metadata, full .tar.gz system configuration backup, and verified restore.'
          },
          {
            id: 'system-service-logs',
            label: 'Service Logs',
            icon: 'scroll-text',
            route: '/system/service-logs',
            group: 'System',
            status: 'active',
            description: 'Live RAM syslog (/var/log/messages) viewer with search, rotation, clear, and CSV export.'
          },
          {
            id: 'system-kernel-logs',
            label: 'Kernel Logs',
            icon: 'cpu',
            route: '/system/kernel-logs',
            group: 'System',
            status: 'active',
            description: 'Linux kernel ring buffer (dmesg) inspection for NIC links, nftables, WireGuard, and thermal events.'
          }
        ]
      }
    ]
  };

  /* ---- Session & CSRF Manager ---- */
  var sessionState = {
    authenticated: false,
    username: 'admin',
    csrfToken: '',
    expiresAt: '',
    mustChangePassword: false
  };

  try {
    sessionState.csrfToken = window.sessionStorage.getItem(CSRF_SESSION_KEY) || '';
  } catch (err) {
    // Ignore storage restriction
  }

  function saveCsrf(token) {
    sessionState.csrfToken = token || '';
    try {
      if (token) window.sessionStorage.setItem(CSRF_SESSION_KEY, token);
      else window.sessionStorage.removeItem(CSRF_SESSION_KEY);
    } catch (err) {
      // Ignore
    }
  }

  function applySessionPayload(data) {
    sessionState.authenticated = true;
    sessionState.username = (data && data.username) || 'admin';
    sessionState.expiresAt = (data && data.expires_at) || '';
    sessionState.mustChangePassword = Boolean(data && data.must_change_password);
    if (data && data.csrf_token) {
      saveCsrf(data.csrf_token);
    }
    return Object.assign({}, sessionState);
  }

  function clearSessionState() {
    sessionState.authenticated = false;
    sessionState.expiresAt = '';
    sessionState.mustChangePassword = false;
    saveCsrf('');
  }

  Hive.auth = {
    getSession: function () {
      return Object.assign({}, sessionState);
    },
    getCsrfToken: function () {
      return sessionState.csrfToken;
    },
    isAuthenticated: function () {
      return sessionState.authenticated;
    },
    clearMustChangePassword: function () {
      sessionState.mustChangePassword = false;
    },
    checkSession: function () {
      return Hive.api
        .request('/auth/me', { method: 'GET', skipAuthRedirect: true })
        .then(function (data) {
          return applySessionPayload(data);
        })
        .catch(function () {
          clearSessionState();
          return null;
        });
    },
    login: function (username, password) {
      return Hive.api
        .request('/auth/login', {
          method: 'POST',
          skipAuthRedirect: true,
          body: { username: String(username || 'admin').trim(), password: String(password || '') }
        })
        .then(function (data) {
          var s = applySessionPayload(data);
          window.dispatchEvent(new CustomEvent('hive:authenticated', { detail: s }));
          return s;
        });
    },
    logout: function () {
      return Hive.api
        .request('/auth/logout', { method: 'POST', skipAuthRedirect: true })
        .catch(function () {})
        .then(function () {
          clearSessionState();
          window.dispatchEvent(new CustomEvent('hive:unauthorized'));
        });
    },
    handleUnauthorized: function () {
      var wasAuth = sessionState.authenticated;
      clearSessionState();
      if (wasAuth) {
        window.dispatchEvent(new CustomEvent('hive:unauthorized'));
      }
    }
  };

  /* ---- Live HTTPS REST + Binary API Client ---- */
  Hive.api = {
    baseUrl: '/api/v1',
    mode: 'live',
    request: function (endpoint, options) {
      var opts = options || {};
      var method = String(opts.method || 'GET').toUpperCase();
      var url = endpoint.indexOf('/api/') === 0 ? endpoint : Hive.api.baseUrl + (endpoint.charAt(0) === '/' ? endpoint : '/' + endpoint);

      var headers = Object.assign({}, opts.headers || {});
      if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
        var csrf = Hive.auth.getCsrfToken();
        if (csrf) {
          headers['X-CSRF-Token'] = csrf;
        }
      }

      var fetchOpts = {
        method: method,
        credentials: 'same-origin',
        headers: headers
      };

      if (opts.body !== undefined && opts.body !== null && method !== 'GET' && method !== 'HEAD') {
        if (opts.rawBody) {
          fetchOpts.body = opts.body;
          if (opts.contentType) {
            headers['Content-Type'] = opts.contentType;
          }
        } else {
          headers['Content-Type'] = 'application/json';
          fetchOpts.body = JSON.stringify(opts.body);
        }
      }

      return window.fetch(url, fetchOpts).then(function (resp) {
        if (resp.status === 401 && !opts.skipAuthRedirect) {
          Hive.auth.handleUnauthorized();
          throw new Error('Authentication required — please sign in.');
        }

        if (opts.responseType === 'blob') {
          if (!resp.ok) {
            return resp.text().then(function (txt) {
              var msg = 'HTTP ' + resp.status;
              try {
                var parsed = JSON.parse(txt);
                if (parsed && parsed.error) msg = parsed.error;
              } catch (e) {
                if (txt) msg = txt;
              }
              throw new Error(msg);
            });
          }
          var disp = resp.headers.get('Content-Disposition') || '';
          var match = disp.match(/filename="?([^";]+)"?/i);
          return resp.blob().then(function (blob) {
            return {
              blob: blob,
              filename: match ? match[1] : 'netbee-backup.tar.gz'
            };
          });
        }

        return resp.text().then(function (rawText) {
          var data = null;
          if (rawText) {
            try {
              data = JSON.parse(rawText);
            } catch (e) {
              data = { raw: rawText };
            }
          }
          if (!resp.ok) {
            var rawErr = data && typeof data.raw === 'string' ? data.raw.trim() : '';
            if (rawErr && rawErr.charAt(0) === '<') rawErr = '';
            var errMsg =
              (data && (data.error || data.message)) ||
              (rawErr ? rawErr.slice(0, 240) : '') ||
              ('Request failed (HTTP ' + resp.status + ')');
            var err = new Error(errMsg);
            err.status = resp.status;
            err.data = data;
            throw err;
          }
          if (
            data &&
            data.pending_commit &&
            (typeof data.pending_commit.active === 'boolean' || typeof data.pending_commit.pending === 'boolean')
          ) {
            window.dispatchEvent(new CustomEvent('hive:pendingcommit', { detail: data.pending_commit }));
          }
          return data;
        });
      });
    }
  };
})(window);
