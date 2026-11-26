/* ==========================================================================
   Hive — Network & Technical Input Validators + CIDR Matching Utilities
   ========================================================================== */
(function (window) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var IPV4_RE = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  var CIDR_RE = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\/([0-9]|[12]\d|3[0-2])$/;
  var HEXTET_RE = /^[0-9a-fA-F]{1,4}$/;
  var MAC_RE = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;
  var HOSTNAME_RE = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
  var WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
  var USERNAME_RE = /^[a-z][a-z0-9._-]{2,31}$/;
  var SSH_PUBKEY_RE = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/=]{24,}(?:\s+.*)?$/;
  var ALIAS_NAME_RE = /^[A-Za-z][A-Za-z0-9_]{1,31}$/;
  var IFACE_NAME_RE = /^[a-z][a-z0-9._-]{1,14}$/;
  var DOMAIN_WILDCARD_RE = /^(\*\.)?(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
  var HTTP_URL_RE = /^https?:\/\/[a-zA-Z0-9.-]+(?::\d{1,5})?(?:\/[^\s]*)?$/;

  function isIPv4(value) {
    return IPV4_RE.test(String(value || '').trim());
  }

  function isCIDR(value) {
    return CIDR_RE.test(String(value || '').trim());
  }

  function isIPv4OrCIDR(value) {
    var v = String(value || '').trim();
    return isIPv4(v) || isCIDR(v);
  }

  function isIPv6(value) {
    var v = String(value || '').trim();
    if (!v) return false;
    var slashIdx = v.indexOf('/');
    var addr = v;
    if (slashIdx !== -1) {
      var prefixStr = v.slice(slashIdx + 1);
      if (!/^\d{1,3}$/.test(prefixStr)) return false;
      var prefix = Number(prefixStr);
      if (prefix < 0 || prefix > 128) return false;
      addr = v.slice(0, slashIdx);
    }
    if (!addr || addr.indexOf(':::') !== -1) return false;
    var doubleColon = addr.split('::');
    if (doubleColon.length > 2) return false;
    if (doubleColon.length === 2) {
      var left = doubleColon[0] ? doubleColon[0].split(':') : [];
      var right = doubleColon[1] ? doubleColon[1].split(':') : [];
      if (left.length + right.length >= 8) return false;
      return left.every(function (h) { return HEXTET_RE.test(h); }) && right.every(function (h) { return HEXTET_RE.test(h); });
    }
    var groups = addr.split(':');
    if (groups.length !== 8) return false;
    return groups.every(function (h) { return HEXTET_RE.test(h); });
  }

  function isMAC(value) {
    return MAC_RE.test(String(value || '').trim());
  }

  function isVlanId(value) {
    var n = Number(value);
    return Number.isInteger(n) && n >= 1 && n <= 4094;
  }

  function isMTU(value) {
    var n = Number(value);
    return Number.isInteger(n) && n >= 576 && n <= 9000;
  }

  function isMetric(value) {
    var n = Number(value);
    return Number.isInteger(n) && n >= 1 && n <= 9999;
  }

  function isHostname(value) {
    return HOSTNAME_RE.test(String(value || '').trim());
  }

  function isWireGuardKey(value) {
    return WG_KEY_RE.test(String(value || '').trim());
  }

  function isUsername(value) {
    return USERNAME_RE.test(String(value || '').trim());
  }

  function isPortNumber(value) {
    var n = Number(value);
    return Number.isInteger(n) && n >= 1 && n <= 65535;
  }

  function isSshPublicKey(value) {
    return SSH_PUBKEY_RE.test(String(value || '').trim());
  }

  function isAliasName(value) {
    return ALIAS_NAME_RE.test(String(value || '').trim());
  }

  function isInterfaceName(value) {
    return IFACE_NAME_RE.test(String(value || '').trim());
  }

  function isDomainOrWildcard(value) {
    return DOMAIN_WILDCARD_RE.test(String(value || '').trim().toLowerCase());
  }

  function isHttpUrl(value) {
    return HTTP_URL_RE.test(String(value || '').trim());
  }

  function isCidrList(value) {
    var parts = String(value || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    if (!parts.length) return false;
    return parts.every(function (p) { return isCIDR(p) || isIPv6(p); });
  }

  function cidrPrefixLength(cidr) {
    var str = String(cidr || '').trim();
    if (isIPv4(str)) return 32;
    if (!isCIDR(str)) return -1;
    return Number(str.split('/')[1]);
  }

  /**
   * Longest Prefix Match (LPM) route lookup over candidate IPv4 routes.
   * Tie-breaks by lowest metric.
   */
  function findLongestPrefixRoute(destIp, candidates) {
    if (!isIPv4(destIp) || !Array.isArray(candidates)) return null;
    var best = null;
    var bestPrefix = -1;
    var bestMetric = Infinity;

    candidates.forEach(function (route) {
      if (route.enabled === false) return;
      if (!ipv4MatchesCidr(destIp, route.destination)) return;
      var prefix = cidrPrefixLength(route.destination);
      var metric = Number(route.metric !== undefined ? route.metric : 100);
      if (prefix > bestPrefix || (prefix === bestPrefix && metric < bestMetric)) {
        best = route;
        bestPrefix = prefix;
        bestMetric = metric;
      }
    });

    return best ? { route: best, prefixLength: bestPrefix } : null;
  }

  function isPortToken(token) {
    var t = String(token || '').trim();
    if (!t) return false;
    if (/^\d+$/.test(t)) {
      var p = Number(t);
      return p >= 1 && p <= 65535;
    }
    var range = t.match(/^(\d+)-(\d+)$/);
    if (range) {
      var start = Number(range[1]);
      var end = Number(range[2]);
      return start >= 1 && end <= 65535 && start <= end;
    }
    return false;
  }

  function isPortSpec(value, aliases) {
    var v = String(value || '').trim();
    if (!v || v.toLowerCase() === 'any') return true;
    if (aliases && aliases[v]) return true;
    return v.split(',').every(isPortToken);
  }

  function isAddressSpec(value, aliases) {
    var v = String(value || '').trim();
    if (!v || v.toLowerCase() === 'any') return true;
    if (aliases && aliases[v]) return true;
    return isIPv4OrCIDR(v) || isIPv6(v);
  }

  /* ---- Bitwise IPv4 & Port Matching (used by Firewall Rule Simulator) ---- */

  function ipv4ToInt(ip) {
    var parts = ip.split('.').map(Number);
    return (((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + parts[3]) >>> 0;
  }

  function ipv4MatchesCidr(ip, cidrOrIp) {
    if (!isIPv4(ip)) return false;
    var target = String(cidrOrIp || '').trim();
    if (isIPv4(target)) {
      return ip === target;
    }
    if (!isCIDR(target)) return false;
    var seg = target.split('/');
    var prefix = Number(seg[1]);
    var mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipv4ToInt(ip) & mask) === (ipv4ToInt(seg[0]) & mask);
  }

  function ipMatchesRuleTarget(ip, target, aliases) {
    var t = String(target || '').trim();
    if (!t || t.toLowerCase() === 'any') return true;
    if (aliases && aliases[t]) {
      return aliases[t].members.some(function (member) {
        return ipv4MatchesCidr(ip, member);
      });
    }
    return ipv4MatchesCidr(ip, t);
  }

  function portMatchesRuleTarget(portNum, target, aliases) {
    var t = String(target || '').trim();
    if (!t || t.toLowerCase() === 'any') return true;
    if (portNum === '' || portNum === null || portNum === undefined) return false;
    var p = Number(portNum);
    if (!Number.isInteger(p) || p < 1 || p > 65535) return false;

    var list = aliases && aliases[t] ? aliases[t].members : t.split(',');
    return list.some(function (entry) {
      var e = String(entry).trim();
      if (/^\d+$/.test(e)) return Number(e) === p;
      var m = e.match(/^(\d+)-(\d+)$/);
      if (m) return p >= Number(m[1]) && p <= Number(m[2]);
      return false;
    });
  }

  Hive.validators = {
    isIPv4: isIPv4,
    isCIDR: isCIDR,
    isIPv4OrCIDR: isIPv4OrCIDR,
    isIPv6: isIPv6,
    isMAC: isMAC,
    isVlanId: isVlanId,
    isMTU: isMTU,
    isMetric: isMetric,
    isHostname: isHostname,
    isWireGuardKey: isWireGuardKey,
    isUsername: isUsername,
    isPortNumber: isPortNumber,
    isSshPublicKey: isSshPublicKey,
    isAliasName: isAliasName,
    isInterfaceName: isInterfaceName,
    isDomainOrWildcard: isDomainOrWildcard,
    isHttpUrl: isHttpUrl,
    isCidrList: isCidrList,
    cidrPrefixLength: cidrPrefixLength,
    findLongestPrefixRoute: findLongestPrefixRoute,
    isPortSpec: isPortSpec,
    isAddressSpec: isAddressSpec,
    ipv4ToInt: ipv4ToInt,
    ipv4MatchesCidr: ipv4MatchesCidr,
    ipMatchesRuleTarget: ipMatchesRuleTarget,
    portMatchesRuleTarget: portMatchesRuleTarget
  };
})(window);

