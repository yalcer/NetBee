/* ==========================================================================
   Hive — Formatters, HTML Escaping & Domain Badge Helpers
   ========================================================================== */
(function (window) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  function escapeHtml(str) {
    return String(str === undefined || str === null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatNumber(n) {
    return Number(n || 0).toLocaleString('en-US');
  }

  function formatMbps(mbps) {
    var val = Number(mbps || 0);
    if (val >= 1000) {
      return (val / 1000).toFixed(2) + ' Gbps';
    }
    if (val >= 10) {
      return val.toFixed(1) + ' Mbps';
    }
    return val.toFixed(2) + ' Mbps';
  }

  function formatBytes(gb) {
    var val = Number(gb || 0);
    if (val >= 1024) {
      return (val / 1024).toFixed(2) + ' TB';
    }
    return val.toFixed(1) + ' GB';
  }

  function formatUptime(totalSeconds) {
    var s = Math.max(0, Math.floor(Number(totalSeconds || 0)));
    var days = Math.floor(s / 86400);
    var hours = Math.floor((s % 86400) / 3600);
    var mins = Math.floor((s % 3600) / 60);
    return days + 'd ' + hours + 'h ' + mins + 'm';
  }

  function formatClockNow() {
    var d = new Date();
    return d.toTimeString().slice(0, 8);
  }

  function zoneBadgeClass(zone) {
    var map = {
      wan: 'q-net-wan',
      lan: 'q-net-lan',
      vlan: 'q-net-vlan',
      vlan20: 'q-net-vlan',
      vlan30: 'q-net-wireless',
      vpn: 'q-net-vpn',
      unassigned: 'q-net-vlan',
      dmz: 'q-net-firewall',
      wireless: 'q-net-wireless',
      firewall: 'q-net-firewall'
    };
    return map[String(zone || '').toLowerCase()] || 'q-net-lan';
  }

  function zoneLabel(zone) {
    var map = {
      wan: 'WAN',
      lan: 'LAN',
      vlan: 'VLAN',
      vlan20: 'VLAN 20',
      vlan30: 'VLAN 30',
      vpn: 'VPN',
      unassigned: 'SPARE',
      dmz: 'DMZ'
    };
    return map[String(zone || '').toLowerCase()] || String(zone || '').toUpperCase();
  }

  function ifaceTypeLabel(type) {
    var map = {
      physical: 'Physical NIC',
      vlan: '802.1Q VLAN',
      bridge: 'L2 Bridge',
      bond: 'Bond / LACP',
      pppoe: 'PPPoE',
      wireguard: 'WireGuard',
      loopback: 'Loopback',
      gre: 'GRE Tunnel',
      vxlan: 'VXLAN'
    };
    return map[String(type || '').toLowerCase()] || 'Interface';
  }

  function actionBadgeClass(action) {
    var map = {
      pass: 'q-act-pass',
      block: 'q-act-block',
      reject: 'q-act-reject'
    };
    return map[String(action || '').toLowerCase()] || '';
  }

  function progressSeverityClass(pct) {
    var n = Number(pct || 0);
    if (n >= 90) return 'error';
    if (n >= 75) return 'warning';
    return 'success';
  }

  Hive.format = {
    escapeHtml: escapeHtml,
    number: formatNumber,
    mbps: formatMbps,
    bytesGb: formatBytes,
    uptime: formatUptime,
    clockNow: formatClockNow,
    zoneBadgeClass: zoneBadgeClass,
    zoneLabel: zoneLabel,
    ifaceTypeLabel: ifaceTypeLabel,
    actionBadgeClass: actionBadgeClass,
    progressSeverityClass: progressSeverityClass
  };
})(window);

