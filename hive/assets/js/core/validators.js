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
  var SSH_PUBKEY_RE = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+[A-Za-z0-9+/=]{24,}(?:\s+.*)?$/;
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

  function isIP(value) {
    var v = String(value || '').trim();
    if (!v || v.indexOf('/') !== -1) return false;
    return isIPv4(v) || isIPv6(v);
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

  function expandIPv6Hextets(addrStr) {
    var v = String(addrStr || '').trim();
    if (!v || v.indexOf('/') !== -1 || !isIPv6(v)) return null;
    var doubleColon = v.split('::');
    var groups;
    if (doubleColon.length === 2) {
      var left = doubleColon[0] ? doubleColon[0].split(':') : [];
      var right = doubleColon[1] ? doubleColon[1].split(':') : [];
      var missing = 8 - (left.length + right.length);
      groups = left.slice();
      for (var i = 0; i < missing; i++) groups.push('0');
      groups = groups.concat(right);
    } else {
      groups = v.split(':');
    }
    if (groups.length !== 8) return null;
    return groups.map(function (g) { return parseInt(g, 16) & 0xffff; });
  }

  function ipv6MatchesCidr(ip, cidrOrIp) {
    var hostHextets = expandIPv6Hextets(ip);
    if (!hostHextets) return false;
    var target = String(cidrOrIp || '').trim();
    if (!isIPv6(target)) return false;
    var slashIdx = target.indexOf('/');
    var netAddr = slashIdx === -1 ? target : target.slice(0, slashIdx);
    var prefix = slashIdx === -1 ? 128 : Number(target.slice(slashIdx + 1));
    var netHextets = expandIPv6Hextets(netAddr);
    if (!netHextets) return false;

    for (var i = 0; i < 8; i++) {
      var bits = Math.min(16, Math.max(0, prefix - i * 16));
      if (bits === 0) break;
      var mask = bits === 16 ? 0xffff : ((0xffff << (16 - bits)) & 0xffff);
      if ((hostHextets[i] & mask) !== (netHextets[i] & mask)) return false;
    }
    return true;
  }

  function ipMatchesCidr(ip, cidrOrIp) {
    var s = String(ip || '').trim();
    if (isIPv4(s)) return ipv4MatchesCidr(s, cidrOrIp);
    if (isIP(s)) return ipv6MatchesCidr(s, cidrOrIp);
    return false;
  }

  function cidrPrefixLength(cidr) {
    var str = String(cidr || '').trim();
    if (isIPv4(str)) return 32;
    if (isCIDR(str)) return Number(str.split('/')[1]);
    if (isIPv6(str)) {
      var idx = str.indexOf('/');
      return idx === -1 ? 128 : Number(str.slice(idx + 1));
    }
    return -1;
  }

  /**
   * Longest Prefix Match (LPM) route lookup over candidate IPv4 or IPv6 routes.
   * Tie-breaks by lowest metric.
   */
  function findLongestPrefixRoute(destIp, candidates) {
    var ipStr = String(destIp || '').trim();
    if (!isIP(ipStr) || !Array.isArray(candidates)) return null;
    var best = null;
    var bestPrefix = -1;
    var bestMetric = Infinity;

    candidates.forEach(function (route) {
      if (route.enabled === false) return;
      if (!ipMatchesCidr(ipStr, route.destination)) return;
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
    if (aliases && aliases[v] && aliases[v].type === 'port') return true;
    var parts = v.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    return parts.length >= 1 && parts.length <= 32 && parts.every(isPortToken);
  }

  function isAddressSpec(value, aliases) {
    var v = String(value || '').trim();
    if (!v || v.toLowerCase() === 'any') return true;
    if (aliases && aliases[v] && aliases[v].type !== 'port') return true;
    var parts = v.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    if (!parts.length || parts.length > 32) return false;
    var v4 = 0;
    var v6 = 0;
    for (var i = 0; i < parts.length; i++) {
      if (isIPv4OrCIDR(parts[i])) v4++;
      else if (isIPv6(parts[i])) v6++;
      else return false;
    }
    return !(v4 > 0 && v6 > 0);
  }

  /* ---- Bitwise IPv4/IPv6 & Port Matching (used by Firewall Rule Simulator) ---- */

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
    var list = aliases && aliases[t] ? aliases[t].members : t.split(',');
    return list.some(function (member) {
      return ipMatchesCidr(ip, String(member).trim());
    });
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
    isIP: isIP,
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
    ipv6MatchesCidr: ipv6MatchesCidr,
    ipMatchesCidr: ipMatchesCidr,
    ipMatchesRuleTarget: ipMatchesRuleTarget,
    portMatchesRuleTarget: portMatchesRuleTarget
  };
})(window);

