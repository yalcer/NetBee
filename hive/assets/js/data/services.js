/* ==========================================================================
   Hive — Live Domain Services Layer (netbeed HTTPS API Integration)
   Bridges all 16 UI modules and Hive.store staged-diff commits to netbeed.
   ========================================================================== */
(function (window) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  function clone(v) {
    return JSON.parse(JSON.stringify(v));
  }

  var idSeq = 0;
  function nextId(prefix) {
    idSeq += 1;
    return prefix + String(Date.now() % 1000000) + String(idSeq);
  }

  function safeGet(endpoint) {
    return Hive.api.request(endpoint, { method: 'GET' }).catch(function () {
      return null;
    });
  }

  function netmaskToPrefix(mask) {
    if (!mask) return 24;
    var parts = String(mask).trim().split('.');
    if (parts.length !== 4) return 24;
    var bits = 0;
    for (var i = 0; i < 4; i++) {
      var n = Number(parts[i]) & 255;
      while (n > 0) {
        bits += n & 1;
        n >>= 1;
      }
    }
    return bits || 24;
  }

  function prefixToNetmask(prefix) {
    var p = Math.max(8, Math.min(30, Number(prefix) || 24));
    var mask = [];
    for (var i = 0; i < 4; i++) {
      var n = Math.min(8, Math.max(0, p - i * 8));
      mask.push(n === 0 ? 0 : 256 - Math.pow(2, 8 - n));
    }
    return mask.join('.');
  }

  function parseCidrOrIpMask(cidrStr, fallbackMask) {
    var raw = String(cidrStr || '').trim();
    if (raw.indexOf('/') !== -1) {
      var sp = raw.split('/');
      return {
        ip: sp[0].trim(),
        netmask: prefixToNetmask(Number(sp[1]))
      };
    }
    return {
      ip: raw || '192.168.10.1',
      netmask: fallbackMask || '255.255.255.0'
    };
  }

  function parseAdGuardUserRules(rulesArr) {
    var blocked = [];
    var allowlist = [];
    var passthrough = [];
    (rulesArr || []).forEach(function (raw, idx) {
      var line = String(raw || '').trim();
      if (!line) return;
      if (line.charAt(0) === '!' || line.charAt(0) === '#') {
        passthrough.push(line);
        return;
      }
      if (line.indexOf('@@||') === 0) {
        var restA = line.slice(4);
        var caretA = restA.indexOf('^');
        var domA = (caretA !== -1 ? restA.slice(0, caretA) : restA).trim();
        var modA = caretA !== -1 ? restA.slice(caretA + 1).trim() : '';
        if (domA) {
          allowlist.push({
            id: 'alw-' + idx + '-' + domA.replace(/[^a-zA-Z0-9.-]/g, '_'),
            domain: domA,
            rawRule: line,
            reason: modA ? ('AdGuard exception (' + modA + ')') : 'AdGuard exception rule',
            addedAt: 'Active'
          });
        }
      } else if (line.indexOf('||') === 0) {
        var restB = line.slice(2);
        var caretB = restB.indexOf('^');
        var domB = (caretB !== -1 ? restB.slice(0, caretB) : restB).trim();
        var modB = caretB !== -1 ? restB.slice(caretB + 1).trim() : '';
        if (domB) {
          blocked.push({
            id: 'blk-' + idx + '-' + domB.replace(/[^a-zA-Z0-9.-]/g, '_'),
            domain: domB,
            rawRule: line,
            reason: modB ? ('AdGuard block (' + modB + ')') : 'AdGuard custom block rule',
            addedAt: 'Active'
          });
        }
      } else {
        blocked.push({
          id: 'raw-' + idx,
          domain: line,
          rawRule: line,
          reason: 'Custom filter rule',
          addedAt: 'Active'
        });
      }
    });
    return { blocked: blocked, allowlist: allowlist, passthrough: passthrough };
  }

  function buildAdGuardUserRules(blockedList, allowList, passthroughList) {
    var out = Array.isArray(passthroughList) ? passthroughList.slice() : [];
    (blockedList || []).forEach(function (item) {
      var d = String(item.domain || '').trim();
      if (!d) return;
      if (item.rawRule && item.rawRule.indexOf(d) !== -1) {
        out.push(item.rawRule);
      } else if (d.indexOf('||') === 0 || d.indexOf('@@') === 0 || d.indexOf('/') !== -1) {
        out.push(d);
      } else {
        out.push('||' + d.replace(/^\*\./, '') + '^');
      }
    });
    (allowList || []).forEach(function (item) {
      var d = String(item.domain || '').trim();
      if (!d) return;
      if (item.rawRule && item.rawRule.indexOf(d) !== -1) {
        out.push(item.rawRule);
      } else if (d.indexOf('@@') === 0) {
        out.push(d);
      } else {
        out.push('@@||' + d.replace(/^\*\./, '') + '^');
      }
    });
    return out;
  }

  function convertVnstatSeries(vnstatJson, wanDev) {
    var fallback = {
      '1h': [{ label: 'Now', rx: 0, tx: 0 }],
      '24h': [{ label: 'Now', rx: 0, tx: 0 }]
    };
    if (!vnstatJson || !Array.isArray(vnstatJson.interfaces) || !vnstatJson.interfaces.length) {
      return fallback;
    }
    var ifaceObj =
      vnstatJson.interfaces.find(function (x) { return x.name === wanDev; }) ||
      vnstatJson.interfaces[0];
    if (!ifaceObj || !ifaceObj.traffic) return fallback;

    function pad2(n) { return n < 10 ? '0' + n : String(n); }

    var fiveMin = ifaceObj.traffic.fiveminute || [];
    if (fiveMin.length) {
      var slice1h = fiveMin.slice(-12);
      fallback['1h'] = slice1h.map(function (pt) {
        var t = pt.time || {};
        return {
          label: pad2(t.hour || 0) + ':' + pad2(t.minute || 0),
          rx: Number((((Number(pt.rx) || 0) * 8) / (300 * 1e6)).toFixed(2)),
          tx: Number((((Number(pt.tx) || 0) * 8) / (300 * 1e6)).toFixed(2))
        };
      });
    }

    var hourly = ifaceObj.traffic.hour || [];
    if (hourly.length) {
      var slice24 = hourly.slice(-24);
      fallback['24h'] = slice24.map(function (pt) {
        var t = pt.time || {};
        return {
          label: pad2(t.hour || 0) + ':00',
          rx: Number((((Number(pt.rx) || 0) * 8) / (3600 * 1e6)).toFixed(2)),
          tx: Number((((Number(pt.tx) || 0) * 8) / (3600 * 1e6)).toFixed(2))
        };
      });
    }

    return fallback;
  }

  function mapSyslogLine(line, idx) {
    var raw = String(line || '');
    // BusyBox syslog format: "Nov 26 15:20:01 netbee daemon.info netbeed[123]: msg"
    var m = raw.match(/^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:([a-z0-9]+)\.([a-z0-9]+)\s+)?([^:\s]+?)(?:\[(\d+)\])?:\s*(.*)$/i);
    var sev = 'info';
    var ts = m ? m[1] : '—';
    var lvl = m && m[4] ? m[4].toLowerCase() : '';
    var proc = m ? m[5] : 'syslog';
    var msg = m ? m[7] : raw;

    if (lvl === 'err' || lvl === 'crit' || lvl === 'alert' || lvl === 'emerg' || /error|failed|fatal/i.test(msg)) {
      sev = 'error';
    } else if (lvl === 'warn' || lvl === 'warning' || /warn|reject|drop|invalid/i.test(msg)) {
      sev = 'warning';
    } else if (/started|confirmed|active|reloaded|listening/i.test(msg)) {
      sev = 'success';
    }

    return {
      id: 'log-' + idx,
      timestamp: ts,
      severity: sev,
      actor: m && m[6] ? 'PID ' + m[6] : 'system',
      sourceIp: m ? m[2] : 'netbee',
      module: proc,
      summary: msg,
      raw: raw,
      details: { raw: raw, facility: (m && m[3]) || 'daemon', level: lvl || 'info' }
    };
  }

  function mapDmesgLine(line, idx) {
    var raw = String(line || '');
    var bootTime = String(idx);
    var body = raw;
    var bm = raw.match(/^\[\s*([0-9.]+)\]\s*(.*)$/);
    if (bm) {
      bootTime = bm[1];
      body = bm[2];
    }
    var subsys = 'kernel';
    var msg = body;
    var sm = body.match(/^([a-zA-Z0-9_.-]+)(?:\s+([0-9a-f:.]+))?:\s*(.*)$/);
    if (sm) {
      subsys = sm[1];
      msg = sm[3];
    }
    var devMatch = body.match(/\b(eth\d+(?:\.\d+)?|wg\d+|ppp\d+|ifb\d+|lo)\b/);
    var level = 'info';
    if (/error|fail|panic|oops|bug|under-?voltage/i.test(body)) level = 'err';
    else if (/warn|drop|throttl|timeout/i.test(body)) level = 'warn';
    else if (/link becomes ready|up|initialized|registered/i.test(body)) level = 'notice';

    return {
      id: 'kern-' + idx,
      bootTime: bootTime,
      timestamp: '+' + bootTime + 's',
      level: level,
      subsystem: subsys,
      device: devMatch ? devMatch[1] : '—',
      message: msg,
      raw: raw
    };
  }

  function reverseMatchAlias(spec, expectedType, aliases) {
    var raw = String(spec || '').trim();
    if (!raw || !aliases) return raw || 'any';
    var norm = raw.split(',').map(function (s) { return s.trim(); }).filter(Boolean).join(',');
    var keys = Object.keys(aliases);
    for (var i = 0; i < keys.length; i++) {
      var name = keys[i];
      var a = aliases[name];
      if (!a || !Array.isArray(a.members) || !a.members.length) continue;
      if (expectedType === 'port' && a.type !== 'port') continue;
      if (expectedType !== 'port' && a.type === 'port') continue;
      var joined = a.members.map(function (m) { return String(m).trim(); }).filter(Boolean).join(',');
      if (joined === norm) return name;
    }
    return norm || 'any';
  }

  function mapRuleFromBackend(r, lanIf, wanIf, wgIf, aliases) {
    var actionMap = { accept: 'pass', drop: 'block', reject: 'reject' };
    var zone = 'wan';
    if (r.in_iface === lanIf) zone = 'lan';
    else if (r.in_iface === wgIf) zone = 'vpn';
    else if (r.chain === 'forward' && !r.in_iface) zone = 'lan';

    return {
      id: r.id,
      chain: r.chain || 'input',
      inIface: r.in_iface || '',
      outIface: r.out_iface || '',
      zone: zone,
      direction: r.chain || 'input',
      action: actionMap[r.action] || 'block',
      protocol: String(r.protocol || 'any').toUpperCase(),
      source: r.src_addr ? reverseMatchAlias(r.src_addr, 'addr', aliases) : 'any',
      destination: r.dst_addr ? reverseMatchAlias(r.dst_addr, 'addr', aliases) : 'any',
      port: r.dst_port ? reverseMatchAlias(r.dst_port, 'port', aliases) : 'any',
      log: Boolean(r.log),
      enabled: Boolean(r.enabled),
      hits: 0,
      description: r.name || r.id
    };
  }

  function resolveAliasSpec(val, aliases) {
    var s = String(val || '').trim();
    if (!s || s.toLowerCase() === 'any' || s === '*') return '';
    if (aliases && aliases[s] && Array.isArray(aliases[s].members) && aliases[s].members.length) {
      return aliases[s].members.map(function (m) { return String(m).trim(); }).filter(Boolean).join(',');
    }
    return s.split(',').map(function (p) { return p.trim(); }).filter(Boolean).join(',');
  }

  function mapRuleToBackend(r, aliases) {
    var actionMap = { pass: 'accept', accept: 'accept', block: 'drop', drop: 'drop', reject: 'reject' };
    var proto = String(r.protocol || 'any').toLowerCase();
    var chain = r.chain === 'forward' || r.direction === 'forward' ? 'forward' : 'input';
    var dstPort = resolveAliasSpec(r.port, aliases);
    if (proto !== 'tcp' && proto !== 'udp') dstPort = '';

    return {
      id: String(r.id || nextId('r')).replace(/[^a-zA-Z0-9_-]/g, ''),
      name: String(r.description || r.name || 'Rule').slice(0, 64),
      enabled: Boolean(r.enabled),
      chain: chain,
      action: actionMap[String(r.action || 'drop').toLowerCase()] || 'drop',
      protocol: proto,
      in_iface: String(r.inIface || '').trim(),
      out_iface: chain === 'forward' ? String(r.outIface || '').trim() : '',
      src_addr: resolveAliasSpec(r.source, aliases),
      dst_addr: resolveAliasSpec(r.destination, aliases),
      dst_port: dstPort,
      log: Boolean(r.log)
    };
  }

  function mapPortForwardFromBackend(pf, wanIf) {
    var protoLabel = pf.protocol === 'both' ? 'TCP+UDP' : String(pf.protocol || 'tcp').toUpperCase();
    return {
      id: pf.id,
      iface: wanIf || 'eth1',
      protocol: protoLabel,
      extPort: String(pf.ext_port || ''),
      targetIp: pf.int_ip || '',
      targetPort: pf.int_port ? String(pf.int_port) : String(pf.ext_port || ''),
      intPortRaw: Number(pf.int_port || 0),
      sourceCidr: pf.source_cidr || '',
      enabled: Boolean(pf.enabled),
      description: pf.name || pf.id
    };
  }

  function mapPortForwardToBackend(pf) {
    var p = String(pf.protocol || 'TCP').toUpperCase();
    var proto = p === 'TCP+UDP' || p === 'BOTH' ? 'both' : p.toLowerCase();
    var extPort = String(pf.extPort || '').trim();
    var intPort = 0;
    if (extPort.indexOf('-') === -1 && pf.targetPort && String(pf.targetPort).trim() !== '' && String(pf.targetPort).indexOf('-') === -1) {
      intPort = Number(pf.targetPort) || 0;
    }
    return {
      id: String(pf.id || nextId('pf')).replace(/[^a-zA-Z0-9_-]/g, ''),
      name: String(pf.description || ('DNAT ' + extPort)).slice(0, 64),
      enabled: Boolean(pf.enabled),
      protocol: proto,
      ext_port: extPort,
      int_ip: String(pf.targetIp || '').trim(),
      int_port: intPort,
      source_cidr: String(pf.sourceCidr || '').trim()
    };
  }

  /**
   * Fetch full router state from netbeed and hydrate Hive.store.
   */
  function bootstrapAll() {
    return Promise.all([
      safeGet('/system/overview'),
      safeGet('/network/interfaces'),
      safeGet('/network/lan'),
      safeGet('/network/wan'),
      safeGet('/services/ipv6'),
      safeGet('/network/routes'),
      safeGet('/network/neighbors'),
      safeGet('/firewall/config'),
      safeGet('/qos/sqm'),
      safeGet('/traffic/vnstat'),
      safeGet('/vpn/wireguard'),
      safeGet('/services/ntp'),
      safeGet('/services/ssh'),
      safeGet('/services/cron'),
      safeGet('/system/sysctl'),
      safeGet('/system/tls'),
      safeGet('/system/users'),
      safeGet('/system/timezones'),
      safeGet('/dhcp/status'),
      safeGet('/dns/config'),
      safeGet('/dns/rewrites'),
      safeGet('/dns/status'),
      safeGet('/dns/stats'),
      safeGet('/dns/filters'),
      safeGet('/dns/blocked-services'),
      safeGet('/dns/blocked-services/all')
    ]).then(function (res) {
      var sysOv = res[0];
      var netIfs = res[1];
      var lanRes = res[2];
      var wanRes = res[3];
      var ipv6Res = res[4];
      var routesRes = res[5];
      var neighRes = res[6];
      var fwRes = res[7];
      var sqmRes = res[8];
      var vnstatRes = res[9];
      var wgRes = res[10];
      var ntpRes = res[11];
      var sshRes = res[12];
      var cronRes = res[13];
      var sysctlRes = res[14];
      var tlsRes = res[15];
      var usersRes = res[16];
      var tzRes = res[17];
      var dhcpRes = res[18];
      var dnsCfgRes = res[19];
      var dnsRewRes = res[20];
      var dnsStatRes = res[21];
      var dnsMetrics = res[22];
      var dnsFiltRes = res[23];
      var blkCurRes = res[24];
      var blkAllRes = res[25];

      if (sysOv && sysOv.pending_commit) {
        window.dispatchEvent(new CustomEvent('hive:pendingcommit', { detail: sysOv.pending_commit }));
      }

      Hive.store.hydrateFromBackend(function (st) {
        var lanIf = (lanRes && lanRes.interface) || 'eth0';
        var wanCfg = (wanRes && wanRes.config) || {};
        var wanIf = wanCfg.interface || 'eth1';
        var wgCfg = (wgRes && wgRes.config) || {};
        var wgIf = wgCfg.interface || 'wg0';

        // 1. LAN / WAN / IPv6 Config
        if (lanRes) {
          st.lanConfig = {
            interface: lanIf,
            ip: lanRes.ip || '192.168.10.1',
            netmask: lanRes.netmask || '255.255.255.0',
            mtu: Number(lanRes.mtu || 1500),
            pinMac: lanRes.pin_mac || ''
          };
        }
        if (wanRes && wanRes.config) {
          var wanMode = wanCfg.mode || 'dhcp';
          var isPppMode = wanMode === 'pppoe' || wanMode === 'ont_vlan';
          st.wanConfig = {
            mode: wanMode,
            interface: wanIf,
            vlanEnabled: Boolean(wanCfg.vlan_enabled || wanMode === 'ont_vlan'),
            vlanId: Number(wanCfg.vlan_id || 35),
            staticIp: wanCfg.static_ip || '',
            staticNetmask: wanCfg.static_netmask || '255.255.255.0',
            staticGateway: wanCfg.static_gateway || '',
            pppoeUser: wanCfg.pppoe_user || '',
            pppoePassword: '',
            peerDns: wanCfg.peerdns === undefined || wanCfg.peerdns === null ? true : Boolean(wanCfg.peerdns),
            dnsServers: Array.isArray(wanCfg.dns_servers) ? wanCfg.dns_servers.slice() : [],
            macClone: wanCfg.mac_clone || '',
            pinMac: wanCfg.pin_mac || '',
            mtu: Number(wanCfg.mtu || (isPppMode ? 1492 : 1500)),
            ipv6Pd: Boolean(wanCfg.ipv6_pd),
            pppdRunning: Boolean(wanRes.pppd_running)
          };
        }
        if (ipv6Res) {
          st.ipv6Config = {
            radvdEnabled: Boolean(ipv6Res.radvd_enabled),
            radvdRunning: Boolean(ipv6Res.radvd_running),
            ipv6Pd: Boolean(ipv6Res.ipv6_pd)
          };
        }

        // 2. System Overview & Daemons
        if (sysOv && sysOv.system) {
          var s = sysOv.system;
          var os = s.os || {};
          st.system.hostname = s.hostname || 'netbee';
          st.system.fqdn = (s.hostname || 'netbee') + '.lan';
          st.system.model = s.board_model || 'Raspberry Pi 5';
          st.system.firmware = os.pretty_name || ((os.name || 'NetBee OS') + ' ' + (os.version || '')).trim();
          st.system.kernel = os.kernel ? 'Linux ' + os.kernel : 'Linux aarch64';
          st.system.arch = os.arch || 'aarch64';
          st.system.board = os.board || 'rpi5';
          st.system.uptimeSeconds = Number(s.uptime_seconds || 0);
          st.system.cpuCores = Number(s.cpu_cores || 4);
          st.system.cpuFreqMhz = s.cpu_freq_mhz !== undefined ? s.cpu_freq_mhz : null;
          st.system.cpuGovernor = s.cpu_governor || '';
          st.system.cpuTempC = s.cpu_temp_c !== undefined ? s.cpu_temp_c : null;
          st.system.fanRpm = s.fan_rpm !== undefined ? s.fan_rpm : null;
          st.system.coolingState = s.cooling_state !== undefined ? s.cooling_state : null;
          st.system.undervoltage = Boolean(s.undervoltage);
          st.system.rootfsExpanded = s.rootfs_expanded !== false;
          st.system.memTotalMb = Number(s.mem_total_mb || 4096);
          st.system.memUsedMb = Number(s.mem_used_mb || 0);
          st.system.memTotalGb = Number((st.system.memTotalMb / 1024).toFixed(2));
          st.system.memUsedGb = Number((st.system.memUsedMb / 1024).toFixed(2));
          st.system.loadAvg = Array.isArray(s.load_avg) ? s.load_avg : [0, 0, 0];
          st.system.statesActive = Number(s.conntrack_count || 0);
          st.system.statesMax = Number(s.conntrack_max || 131072);
          st.system.disks = Array.isArray(s.disks) ? s.disks : [];
          st.general.timezone = s.timezone || st.general.timezone || 'UTC';
        }

        if (sysOv && Array.isArray(sysOv.services)) {
          st.daemons = sysOv.services.map(function (svc) {
            return {
              id: svc.name,
              name: svc.name,
              description: svc.description || '',
              status: svc.running ? 'running' : 'stopped',
              running: Boolean(svc.running),
              pid: svc.pid || '—',
              actions: Array.isArray(svc.actions) ? svc.actions : ['restart']
            };
          });
        }

        // 3. Routes & Upstream Gateway Detection
        var defaultGw = '';
        var defaultGwDev = wanIf;
        var defaultGwMetric = 100;
        if (routesRes) {
          var v4List = Array.isArray(routesRes.ipv4) ? routesRes.ipv4 : [];
          var conn = [];
          v4List.forEach(function (r, idx) {
            if (r.dst === 'default' && r.gateway) {
              defaultGw = r.gateway;
              defaultGwDev = r.dev || wanIf;
              defaultGwMetric = Number(r.metric !== undefined ? r.metric : 100);
            } else if (r.dst && r.dst !== 'default' && (!r.gateway || r.protocol === 'kernel')) {
              conn.push({
                id: 'conn-' + idx,
                destination: r.dst,
                gateway: r.gateway || 'Direct (Kernel)',
                iface: r.dev || '—',
                metric: Number(r.metric || 0),
                type: 'connected',
                enabled: true,
                description: r.protocol || 'Connected subnet'
              });
            }
          });
          st.connectedRoutes = conn;
          st.staticRoutes = (routesRes.static_routes || []).map(function (rt) {
            return {
              id: rt.id,
              destination: rt.destination,
              gateway: rt.gateway || '',
              iface: rt.device || wanIf,
              metric: Number(rt.metric || 100),
              enabled: Boolean(rt.enabled),
              description: rt.name || 'Persisted static route'
            };
          });
        }

        if (Array.isArray(neighRes)) {
          st.neighbors = neighRes.map(function (n, idx) {
            return {
              id: 'nb-' + idx,
              ip: n.dst || '—',
              mac: n.lladdr || '—',
              iface: n.dev || '—',
              state: Array.isArray(n.state) ? n.state.join(', ') : String(n.state || 'REACHABLE')
            };
          });
        }

        // 4. Interfaces
        if (netIfs && Array.isArray(netIfs.interfaces)) {
          var mappedIfs = [];
          netIfs.interfaces.forEach(function (raw) {
            var dev = raw.ifname;
            if (!dev || dev === 'lo' || dev === 'ifb0') return;
            var addrInfo = Array.isArray(raw.addr_info) ? raw.addr_info : [];
            var v4 = addrInfo.find(function (a) { return a.family === 'inet'; });
            var v6 = addrInfo.find(function (a) { return a.family === 'inet6' && a.scope !== 'link'; }) ||
                     addrInfo.find(function (a) { return a.family === 'inet6'; });

            var isLan = dev === lanIf;
            var isWan = dev === wanIf || dev === 'ppp0' || dev.indexOf(wanIf + '.') === 0;
            var isWg = dev === wgIf || dev.indexOf('wg') === 0;
            var zone = isLan ? 'lan' : isWan ? 'wan' : isWg ? 'vpn' : 'unassigned';
            var type = isWg ? 'wireguard' : dev === 'ppp0' ? 'pppoe' : dev.indexOf('.') !== -1 ? 'vlan' : 'physical';

            var ipv4Str = v4 ? (v4.local + '/' + v4.prefixlen) : (isLan ? st.lanConfig.ip + '/' + netmaskToPrefix(st.lanConfig.netmask) : '—');
            var ipv6Str = v6 ? (v6.local + '/' + v6.prefixlen) : '—';
            var hasUpFlag = Array.isArray(raw.flags) && raw.flags.indexOf('UP') !== -1;
            var operUp = String(raw.operstate || '').toUpperCase() === 'UP' || raw.link_detected === true || (hasUpFlag && Boolean(v4));

            var stats = raw.stats64 || {};
            var rxB = (stats.rx && stats.rx.bytes) || 0;
            var txB = (stats.tx && stats.tx.bytes) || 0;

            var prev = (st.interfaces || []).find(function (p) { return p.device === dev; });

            var wanHasVlan = Boolean(st.wanConfig.vlanEnabled || st.wanConfig.mode === 'ont_vlan');
            var modeLabel = isLan ? 'Static' : 'Unassigned';
            if (dev === wanIf) {
              if (st.wanConfig.mode === 'pppoe' || st.wanConfig.mode === 'ont_vlan') {
                modeLabel = wanHasVlan ? ('VLAN ' + st.wanConfig.vlanId + ' + PPPoE') : 'PPPoE';
              } else if (st.wanConfig.mode === 'static') {
                modeLabel = wanHasVlan ? ('VLAN ' + st.wanConfig.vlanId + ' + Static') : 'Static WAN';
              } else {
                modeLabel = wanHasVlan ? ('VLAN ' + st.wanConfig.vlanId + ' + DHCP') : 'DHCP';
              }
            } else if (dev === 'ppp0') {
              modeLabel = 'PPPoE Session';
            } else if (type === 'vlan' && isWan) {
              modeLabel = '802.1Q VLAN ' + st.wanConfig.vlanId;
            } else if (isWg) {
              modeLabel = 'WireGuard';
            }

            var defaultLabel = isLan
              ? 'LAN Interface'
              : dev === wanIf
                ? 'WAN Interface'
                : dev === 'ppp0'
                  ? 'WAN PPPoE Tunnel'
                  : type === 'vlan' && isWan
                    ? 'WAN 802.1Q Subinterface'
                    : isWg
                      ? 'WireGuard VPN'
                      : 'Spare NIC';

            mappedIfs.push({
              id: 'if-' + dev,
              device: dev,
              type: type,
              role: raw.role || (isLan ? 'lan' : isWan ? 'wan' : isWg ? 'vpn' : 'unassigned'),
              driver: raw.driver || '',
              customLabel: raw.custom_label || '',
              removable: false,
              label: raw.custom_label || defaultLabel,
              zone: zone,
              mode: modeLabel,
              ipv4: ipv4Str,
              ipv6: ipv6Str,
              gateway: isWan && defaultGw ? defaultGw : '—',
              mac: raw.address || '—',
              mtu: Number(raw.mtu || 1500),
              speed: raw.speed ? (raw.speed + (raw.duplex ? ' ' + raw.duplex : '')) : (isWg ? 'UDP/' + (wgCfg.listen_port || 51820) : 'Virtual'),
              duplex: raw.duplex || '',
              linkDetected: Boolean(raw.link_detected),
              adminUp: hasUpFlag,
              enabled: hasUpFlag,
              status: operUp ? 'up' : 'down',
              rxMbps: prev ? prev.rxMbps : 0,
              txMbps: prev ? prev.txMbps : 0,
              rxTotalGb: Number((rxB / 1073741824).toFixed(2)),
              txTotalGb: Number((txB / 1073741824).toFixed(2))
            });
          });
          if (mappedIfs.length) {
            st.interfaces = mappedIfs;
          }
        }

        // Gateway summary object from live WAN state
        var wanIfaceEntry = st.interfaces.find(function (i) { return i.device === defaultGwDev; }) ||
                            st.interfaces.find(function (i) { return i.device === wanIf; });
        st.system.gateways = [
          {
            id: 'gw-wan',
            name: 'WAN_UPLINK (' + st.wanConfig.mode.toUpperCase() + ')',
            iface: defaultGwDev || wanIf,
            address: defaultGw || 'Awaiting lease / session',
            monitorIp: defaultGw || '1.1.1.1',
            rttMs: 0,
            lossPercent: 0,
            metric: defaultGwMetric,
            tier: 1,
            weight: 1,
            status: defaultGw || (wanIfaceEntry && wanIfaceEntry.status === 'up' && wanIfaceEntry.ipv4 !== '—') ? 'online' : 'offline',
            role: 'Primary WAN'
          }
        ];

        // 5. Historical Throughput (vnStat)
        var hist = convertVnstatSeries(vnstatRes, defaultGwDev || wanIf);
        st.system.throughput['1h'] = hist['1h'];
        st.system.throughput['24h'] = hist['24h'];

        // 6. Firewall & NAT Port Forwards
        if (fwRes && fwRes.config) {
          var fc = fwRes.config;
          st.firewallConfig = {
            transparentDns: Boolean(fc.transparent_dns),
            exposeWireguard: Boolean(fc.expose_wireguard),
            wireguardPort: Number(fc.wireguard_port || 51820),
            flowOffload: Boolean(fc.flow_offload),
            offloadActive: Boolean(fwRes.offload_active)
          };
          st.adblock.forceDns = Boolean(fc.transparent_dns);
          st.firewallRules = (fc.custom_rules || []).map(function (r) {
            return mapRuleFromBackend(r, lanIf, wanIf, wgIf, st.aliases);
          });
          st.nat.wanIface = wanIf;
          st.nat.portForwards = (fc.port_forwards || []).map(function (pf) {
            return mapPortForwardFromBackend(pf, wanIf);
          });
        }

        // 7. SQM CAKE QoS
        if (sqmRes && sqmRes.config) {
          st.sqm = {
            enabled: Boolean(sqmRes.config.enabled),
            iface: sqmRes.config.wan_interface || wanIf,
            downloadKbps: Number(sqmRes.config.download_kbit || 95000),
            uploadKbps: Number(sqmRes.config.upload_kbit || 19000),
            qdisc: 'cake',
            script: 'netbee-sqm (sch_cake + ifb0)',
            linkLayer: 'ethernet',
            overheadBytes: Number(sqmRes.config.overhead || 44),
            statusOutput: sqmRes.status || ''
          };
        }

        // 8. WireGuard VPN
        if (wgRes && wgRes.config) {
          var livePeers = wgRes.live_peers || {};
          st.vpn.wireguard = {
            enabled: Boolean(wgCfg.enabled),
            active: Boolean(wgRes.active),
            iface: wgIf,
            listenPort: Number(wgCfg.listen_port || 51820),
            tunnelSubnet: wgCfg.address || '10.66.66.1/24',
            publicKey: wgCfg.public_key || '',
            endpointHost: wgCfg.endpoint || '',
            dns: wgCfg.dns || st.lanConfig.ip,
            peers: (wgCfg.peers || []).map(function (p) {
              var lp = livePeers[p.public_key] || null;
              var hsSec = lp ? Number(lp.latest_handshake || 0) : 0;
              var nowSec = Math.floor(Date.now() / 1000);
              var hsLabel = 'Never';
              var isRecent = false;
              if (hsSec > 0) {
                var ago = Math.max(0, nowSec - hsSec);
                isRecent = ago < 180;
                hsLabel = ago < 60 ? (ago + 's ago') : ago < 3600 ? (Math.floor(ago / 60) + 'm ago') : (Math.floor(ago / 3600) + 'h ago');
              }
              return {
                id: p.id,
                name: p.name,
                publicKey: p.public_key,
                hasPsk: Boolean(p.has_psk),
                endpoint: (lp && lp.endpoint && lp.endpoint !== '(none)') ? lp.endpoint : 'Roaming',
                allowedIps: p.allowed_ips,
                lastHandshake: hsLabel,
                rxGb: lp ? Number(((Number(lp.rx_bytes) || 0) / 1073741824).toFixed(3)) : 0,
                txGb: lp ? Number(((Number(lp.tx_bytes) || 0) / 1073741824).toFixed(3)) : 0,
                enabled: Boolean(p.enabled),
                status: !p.enabled ? 'disabled' : isRecent ? 'connected' : 'idle'
              };
            })
          };
        }

        // 9. NTP, Timezones, Cron & Sysctl
        if (ntpRes) {
          st.general.ntpServers = Array.isArray(ntpRes.servers) && ntpRes.servers.length ? ntpRes.servers : ['0.pool.ntp.org'];
          st.general.ntpServeLan = Boolean(ntpRes.serve_lan);
          st.general.ntpTracking = ntpRes.tracking || '';
          st.general.ntpSources = ntpRes.sources || '';
        }
        if (tzRes) {
          if (tzRes.current) st.general.timezone = tzRes.current;
          if (Array.isArray(tzRes.timezones) && tzRes.timezones.length) {
            st.general.availableTimezones = tzRes.timezones;
          }
        }
        if (cronRes) {
          st.cron = {
            crondRunning: Boolean(cronRes.crond_running),
            systemJobs: Array.isArray(cronRes.system_jobs) ? cronRes.system_jobs : [],
            jobs: Array.isArray(cronRes.jobs) ? cronRes.jobs : [],
            supportedActions: Array.isArray(cronRes.supported_actions) ? cronRes.supported_actions : []
          };
        }
        if (sysctlRes && sysctlRes.config) {
          var sc = sysctlRes.config;
          st.sysctl = {
            conntrackMax: Number(sc.conntrack_max || 131072),
            conntrackCount: Number(sysctlRes.conntrack_count || st.system.statesActive || 0),
            tcpSyncookies: Boolean(sc.tcp_syncookies),
            rpFilter: Number(sc.rp_filter !== undefined ? sc.rp_filter : 1),
            icmpEchoIgnoreBroadcasts: Boolean(sc.icmp_echo_ignore_broadcasts),
            ipv4Forwarding: Boolean(sc.ipv4_forwarding),
            ipv6Forwarding: Boolean(sc.ipv6_forwarding)
          };
        }

        // 10. Users, SSH & TLS
        if (usersRes && Array.isArray(usersRes.users)) {
          st.access.osUsers = usersRes.users;
        }
        if (sshRes) {
          var uKeys = sshRes.users_keys || { root: [], netbee: [] };
          var flatKeys = [];
          ['root', 'netbee'].forEach(function (owner) {
            (uKeys[owner] || []).forEach(function (rawKey, idx) {
              var parts = String(rawKey).trim().split(/\s+/);
              flatKeys.push({
                id: owner + '-' + idx,
                index: idx,
                owner: owner,
                type: parts[0] || 'ssh-ed25519',
                keyBody: parts[1] || '',
                label: parts.slice(2).join(' ') || (owner + ' key #' + (idx + 1)),
                publicKey: rawKey
              });
            });
          });
          st.access.ssh = {
            passwordAuth: Boolean(sshRes.password_auth),
            allowRootLogin: Boolean(sshRes.allow_root_login),
            idleTimeout: Number(sshRes.idle_timeout || 0),
            usersKeys: uKeys,
            sshKeys: flatKeys
          };
        }
        if (tlsRes) {
          st.access.tls = {
            present: Boolean(tlsRes.present),
            subject: tlsRes.subject || '—',
            issuer: tlsRes.issuer || '—',
            notBefore: tlsRes.not_before || '—',
            notAfter: tlsRes.not_after || '—',
            dnsNames: Array.isArray(tlsRes.dns_names) ? tlsRes.dns_names : [],
            ipAddresses: Array.isArray(tlsRes.ip_addresses) ? tlsRes.ip_addresses : [],
            autoSelfSigned: Boolean(tlsRes.auto_self_signed)
          };
        }

        // 11. AdGuardHome DHCP & DNS & AdBlock
        if (dhcpRes) {
          var v4d = dhcpRes.v4 || {};
          var rStart = v4d.range_start || '192.168.10.100';
          var rEnd = v4d.range_end || '192.168.10.200';
          var pSize = 101;
          if (Hive.validators && Hive.validators.isIPv4(rStart) && Hive.validators.isIPv4(rEnd)) {
            pSize = Math.max(1, Hive.validators.ipv4ToInt(rEnd) - Hive.validators.ipv4ToInt(rStart) + 1);
          }
          var leaseSec = Number(v4d.lease_duration || 86400);
          var gwIp = v4d.gateway_ip || st.lanConfig.ip;
          var sMask = v4d.subnet_mask || st.lanConfig.netmask;

          st.dhcp.scopes = [
            {
              id: 'scope-lan',
              iface: dhcpRes.interface_name || lanIf,
              zone: 'lan',
              subnet: gwIp.split('.').slice(0, 3).join('.') + '.0/' + netmaskToPrefix(sMask),
              gatewayIp: gwIp,
              subnetMask: sMask,
              rangeStart: rStart,
              rangeEnd: rEnd,
              poolSize: pSize,
              leaseHours: Math.max(1, Math.round(leaseSec / 3600)),
              dnsServer: st.lanConfig.ip,
              enabled: Boolean(dhcpRes.enabled)
            }
          ];
          st.dhcp.leases = (dhcpRes.leases || []).map(function (l, i) {
            return {
              id: 'lease-' + i + '-' + (l.mac || ''),
              hostname: l.hostname || 'unknown-host',
              ip: l.ip || '',
              mac: (l.mac || '').toUpperCase(),
              iface: dhcpRes.interface_name || lanIf,
              expires: l.expires || 'Active',
              type: 'dynamic'
            };
          });
          st.dhcp.reservations = (dhcpRes.static_leases || []).map(function (sl) {
            var macUp = String(sl.mac || '').toUpperCase();
            return {
              id: 'res-' + macUp.replace(/[^A-F0-9]/g, ''),
              hostname: sl.hostname || 'static-host',
              ip: sl.ip || '',
              mac: macUp,
              iface: dhcpRes.interface_name || lanIf,
              description: 'AdGuardHome Static Lease'
            };
          });
        }

        if (dnsCfgRes) {
          var upstreams = (Array.isArray(dnsCfgRes.upstream_dns) ? dnsCfgRes.upstream_dns : []).filter(function (u) {
            return u && String(u).trim().charAt(0) !== '#';
          });
          st.dns.resolvers = upstreams.length ? upstreams : ['1.1.1.1', '9.9.9.9'];
          st.dns.dotEnabled = upstreams.some(function (u) { return /^tls:\/\/|^https:\/\/|^quic:\/\//i.test(u); });
          st.dns.dnssecEnabled = Boolean(dnsCfgRes.dnssec_enabled);
          st.dns.cacheSize = Number(dnsCfgRes.cache_size !== undefined ? dnsCfgRes.cache_size : 4194304);
        }

        if (Array.isArray(dnsRewRes)) {
          var vRef = Hive.validators;
          st.dns.overrides = dnsRewRes.map(function (rw) {
            var dom = String(rw.domain || '').trim().replace(/\.$/, '');
            var ans = String(rw.answer || '').trim().replace(/\.$/, '');
            var key = dom + '|' + ans;
            var recType = vRef && vRef.isIPv6(ans) ? 'AAAA' : (vRef && vRef.isIPv4(ans) ? 'A' : 'CNAME');
            return {
              id: 'rw-' + key,
              hostname: dom,
              type: recType,
              value: ans,
              ttl: 300,
              description: 'AdGuard DNS Rewrite'
            };
          });
        }

        if (dnsStatRes) {
          st.adblock.enabled = Boolean(dnsStatRes.protection_enabled);
          st.adblock.running = Boolean(dnsStatRes.running);
        }

        if (dnsMetrics) {
          var totalQ = Number(dnsMetrics.num_dns_queries || 0);
          var blkQ = Number(dnsMetrics.num_blocked_filtering || 0);
          var avgRaw = Number(dnsMetrics.avg_processing_time || 0);
          st.adblock.queriesToday = totalQ;
          st.adblock.blockedToday = blkQ;
          st.adblock.blockedPercent = totalQ > 0 ? Number(((blkQ / totalQ) * 100).toFixed(1)) : 0;
          st.adblock.avgLatencyMs = Number((avgRaw < 2 ? avgRaw * 1000 : avgRaw).toFixed(1));
        }

        if (dnsFiltRes) {
          var filtEn = dnsFiltRes.enabled !== false;
          st.adblock.filteringEnabled = filtEn;
          st.adblock.filteringInterval = Number(dnsFiltRes.interval || 24);
          if (dnsStatRes) {
            st.adblock.enabled = Boolean(dnsStatRes.protection_enabled) && filtEn;
          }
          st.adblock.feeds = (dnsFiltRes.filters || []).map(function (f) {
            return {
              id: 'feed-' + f.id,
              numericId: f.id,
              name: f.name || f.url,
              category: 'DNSBL',
              url: f.url,
              domains: Number(f.rules_count || 0),
              lastUpdated: f.last_updated ? String(f.last_updated).replace('T', ' ').slice(0, 16) : 'Synced',
              builtin: false,
              enabled: Boolean(f.enabled)
            };
          });
          var parsedRules = parseAdGuardUserRules(dnsFiltRes.user_rules || []);
          st.adblock.customBlocked = parsedRules.blocked;
          st.adblock.allowlist = parsedRules.allowlist;
          st.adblock.passthroughRules = parsedRules.passthrough || [];
        }

        if (blkCurRes) {
          if (Array.isArray(blkCurRes)) {
            st.adblock.blockedServices = blkCurRes.slice().sort();
          } else if (Array.isArray(blkCurRes.ids)) {
            st.adblock.blockedServices = blkCurRes.ids.slice().sort();
            if (blkCurRes.schedule && typeof blkCurRes.schedule === 'object') {
              st.adblock.blockedServicesSchedule = clone(blkCurRes.schedule);
            }
          }
        }
        if (blkAllRes && Array.isArray(blkAllRes.blocked_services)) {
          st.adblock.availableServices = blkAllRes.blocked_services.map(function (sv) {
            return { id: sv.id, name: sv.name || sv.id };
          });
        }
      }, 'bootstrap');

      return Hive.store.getState();
    });
  }

  /**
   * Apply all staged diffs in workingState against live netbeed API endpoints.
   */
  function applyStagedToBackend() {
    var base = Hive.store.getCommittedState();
    var next = Hive.store.getState();
    var changes = Hive.store.getStagedChanges();
    if (!changes.length) {
      return Promise.resolve({ count: 0 });
    }

    var tasks = [];
    var newLanUrl = '';
    var latestPendingCommit = null;

    function enqueue(fn) {
      tasks.push(fn);
    }

    function capturePending(resp) {
      if (resp && resp.pending_commit && (resp.pending_commit.active || resp.pending_commit.pending)) {
        latestPendingCommit = resp.pending_commit;
        window.dispatchEvent(new CustomEvent('hive:pendingcommit', { detail: resp.pending_commit }));
      }
      if (resp && resp.new_url) {
        newLanUrl = resp.new_url;
      }
      return resp;
    }

    function buildWanPayload(wc) {
      var isPpp = wc.mode === 'pppoe' || wc.mode === 'ont_vlan';
      var payload = {
        mode: wc.mode,
        interface: wc.interface || 'eth1',
        vlan_enabled: Boolean(wc.vlanEnabled || wc.mode === 'ont_vlan'),
        vlan_id: Number(wc.vlanId || 35),
        static_ip: wc.staticIp || '',
        static_netmask: wc.staticNetmask || '',
        static_gateway: wc.staticGateway || '',
        pppoe_user: wc.pppoeUser || '',
        peerdns: wc.peerDns !== false,
        dns_servers: Array.isArray(wc.dnsServers) ? wc.dnsServers : [],
        mac_clone: wc.macClone || '',
        pin_mac: wc.pinMac || '',
        mtu: Number(wc.mtu || (isPpp ? 1492 : 1500)),
        ipv6_pd: Boolean(wc.ipv6Pd)
      };
      if (wc.pppoePassword) {
        payload.pppoe_password = wc.pppoePassword;
      }
      return payload;
    }

    function buildLanPayload(lc) {
      return {
        interface: lc.interface || 'eth0',
        ip: lc.ip,
        netmask: lc.netmask,
        mtu: Number(lc.mtu || 1500),
        pin_mac: lc.pinMac || ''
      };
    }

    // 1. Hostname, Timezone, NTP
    if (base.system.hostname !== next.system.hostname) {
      enqueue(function () {
        return Hive.api.request('/system/hostname', {
          method: 'PUT',
          body: { hostname: next.system.hostname }
        });
      });
    }
    if (base.general.timezone !== next.general.timezone) {
      enqueue(function () {
        return Hive.api.request('/system/timezone', {
          method: 'PUT',
          body: { timezone: next.general.timezone }
        });
      });
    }
    if (JSON.stringify(base.general.ntpServers) !== JSON.stringify(next.general.ntpServers) || base.general.ntpServeLan !== next.general.ntpServeLan) {
      enqueue(function () {
        return Hive.api.request('/services/ntp', {
          method: 'PUT',
          body: { servers: next.general.ntpServers, serve_lan: Boolean(next.general.ntpServeLan) }
        });
      });
    }

    // 2. WAN & IPv6 (LAN / Role Swap runs last so AdGuardHome & firewall mutations commit before LAN IP moves!)
    var wanChanged = JSON.stringify(base.wanConfig) !== JSON.stringify(next.wanConfig);
    var lanChanged = JSON.stringify(base.lanConfig) !== JSON.stringify(next.lanConfig);
    var portsCrossed =
      (lanChanged || wanChanged) &&
      (next.lanConfig.interface === base.wanConfig.interface || next.wanConfig.interface === base.lanConfig.interface);

    if (!portsCrossed && wanChanged) {
      enqueue(function () {
        return Hive.api.request('/network/wan', {
          method: 'PUT',
          body: buildWanPayload(next.wanConfig)
        }).then(capturePending);
      });
    }

    if (JSON.stringify(base.ipv6Config) !== JSON.stringify(next.ipv6Config)) {
      enqueue(function () {
        return Hive.api.request('/services/ipv6', {
          method: 'PUT',
          body: {
            radvd_enabled: Boolean(next.ipv6Config.radvdEnabled),
            ipv6_pd: Boolean(next.ipv6Config.ipv6Pd)
          }
        });
      });
    }

    // 3. Static Routes
    var baseRtMap = {};
    var nextRtMap = {};
    (base.staticRoutes || []).forEach(function (r) { baseRtMap[r.id] = r; });
    (next.staticRoutes || []).forEach(function (r) { nextRtMap[r.id] = r; });

    (base.staticRoutes || []).forEach(function (r) {
      if (!nextRtMap[r.id]) {
        enqueue(function () {
          return Hive.api.request('/network/routes/' + encodeURIComponent(r.id), { method: 'DELETE' });
        });
      }
    });
    (next.staticRoutes || []).forEach(function (r) {
      var prev = baseRtMap[r.id];
      if (!prev || JSON.stringify(prev) !== JSON.stringify(r)) {
        enqueue(function () {
          return Hive.api.request('/network/routes', {
            method: 'POST',
            body: {
              id: String(r.id || '').replace(/[^a-zA-Z0-9_-]/g, ''),
              name: String(r.description || '').slice(0, 64),
              destination: r.destination,
              gateway: r.gateway || '',
              device: r.iface || '',
              metric: Number(r.metric || 100),
              enabled: Boolean(r.enabled)
            }
          });
        });
      }
    });

    // 4. Firewall Rules, Global Toggles & Port Forwards (atomic PUT /firewall/config)
    var wantTransparentDns = Boolean(next.firewallConfig.transparentDns);
    if (base.adblock.forceDns !== next.adblock.forceDns) {
      wantTransparentDns = Boolean(next.adblock.forceDns);
    }
    var fwDirty =
      JSON.stringify(base.firewallRules) !== JSON.stringify(next.firewallRules) ||
      JSON.stringify(base.nat.portForwards) !== JSON.stringify(next.nat.portForwards) ||
      base.firewallConfig.transparentDns !== wantTransparentDns ||
      base.firewallConfig.exposeWireguard !== next.firewallConfig.exposeWireguard ||
      base.firewallConfig.wireguardPort !== next.firewallConfig.wireguardPort ||
      base.firewallConfig.flowOffload !== next.firewallConfig.flowOffload;

    if (fwDirty) {
      enqueue(function () {
        var fwPayload = {
          transparent_dns: wantTransparentDns,
          expose_wireguard: Boolean(next.firewallConfig.exposeWireguard),
          wireguard_port: Number(next.firewallConfig.wireguardPort || next.vpn.wireguard.listenPort || 51820),
          flow_offload: Boolean(next.firewallConfig.flowOffload),
          custom_rules: (next.firewallRules || []).map(function (r) {
            return mapRuleToBackend(r, next.aliases);
          }),
          port_forwards: (next.nat.portForwards || []).map(mapPortForwardToBackend)
        };
        return Hive.api.request('/firewall/config', { method: 'PUT', body: fwPayload }).then(function (resp) {
          capturePending(resp);
          if (base.firewallConfig.flowOffload !== next.firewallConfig.flowOffload) {
            return Hive.api.request('/firewall/offload', {
              method: 'PUT',
              body: { enabled: Boolean(next.firewallConfig.flowOffload) }
            });
          }
          return resp;
        });
      });
    }

    // 5. SQM CAKE QoS
    if (JSON.stringify(base.sqm) !== JSON.stringify(next.sqm)) {
      enqueue(function () {
        return Hive.api.request('/qos/sqm', {
          method: 'PUT',
          body: {
            enabled: Boolean(next.sqm.enabled),
            wan_interface: next.sqm.iface || next.wanConfig.interface || 'eth1',
            download_kbit: Math.max(500, Math.round(Number(next.sqm.downloadKbps) || 95000)),
            upload_kbit: Math.max(250, Math.round(Number(next.sqm.uploadKbps) || 19000)),
            overhead: Math.max(0, Math.min(128, Math.round(Number(next.sqm.overheadBytes) || 44)))
          }
        });
      });
    }

    // 6. DHCP Scope & Static Reservations
    if (JSON.stringify(base.dhcp.scopes) !== JSON.stringify(next.dhcp.scopes) && next.dhcp.scopes[0]) {
      enqueue(function () {
        var sc = next.dhcp.scopes[0];
        return Hive.api.request('/dhcp/config', {
          method: 'PUT',
          body: {
            enabled: Boolean(sc.enabled),
            interface_name: sc.iface || next.lanConfig.interface || 'eth0',
            v4: {
              gateway_ip: next.lanConfig.ip || sc.gatewayIp || '192.168.10.1',
              subnet_mask: next.lanConfig.netmask || sc.subnetMask || '255.255.255.0',
              range_start: sc.rangeStart,
              range_end: sc.rangeEnd,
              lease_duration: Math.max(3600, Math.round(Number(sc.leaseHours || 24) * 3600))
            }
          }
        });
      });
    }

    var baseResMap = {};
    var nextResMap = {};
    (base.dhcp.reservations || []).forEach(function (r) { baseResMap[r.id] = r; });
    (next.dhcp.reservations || []).forEach(function (r) { nextResMap[r.id] = r; });

    (base.dhcp.reservations || []).forEach(function (r) {
      if (!nextResMap[r.id] || JSON.stringify(nextResMap[r.id]) !== JSON.stringify(r)) {
        enqueue(function () {
          return Hive.api.request('/dhcp/leases/static', {
            method: 'DELETE',
            body: { mac: r.mac.toLowerCase(), ip: r.ip, hostname: r.hostname }
          });
        });
      }
    });
    (next.dhcp.reservations || []).forEach(function (r) {
      if (!baseResMap[r.id] || JSON.stringify(baseResMap[r.id]) !== JSON.stringify(r)) {
        enqueue(function () {
          return Hive.api.request('/dhcp/leases/static', {
            method: 'POST',
            body: { mac: r.mac.toLowerCase(), ip: r.ip, hostname: r.hostname }
          });
        });
      }
    });

    // 7. DNS Resolver Settings & Rewrites
    if (
      JSON.stringify(base.dns.resolvers) !== JSON.stringify(next.dns.resolvers) ||
      base.dns.dnssecEnabled !== next.dns.dnssecEnabled ||
      base.dns.cacheSize !== next.dns.cacheSize
    ) {
      enqueue(function () {
        return Hive.api.request('/dns/config', {
          method: 'PUT',
          body: {
            upstream_dns: next.dns.resolvers,
            dnssec_enabled: Boolean(next.dns.dnssecEnabled),
            cache_size: Number(next.dns.cacheSize)
          }
        });
      });
    }

    var baseOvMap = {};
    var nextOvMap = {};
    (base.dns.overrides || []).forEach(function (o) { baseOvMap[o.id] = o; });
    (next.dns.overrides || []).forEach(function (o) { nextOvMap[o.id] = o; });

    (base.dns.overrides || []).forEach(function (o) {
      if (!nextOvMap[o.id] || JSON.stringify(nextOvMap[o.id]) !== JSON.stringify(o)) {
        enqueue(function () {
          return Hive.api.request('/dns/rewrites', {
            method: 'DELETE',
            body: { domain: o.hostname, answer: o.value }
          });
        });
      }
    });
    (next.dns.overrides || []).forEach(function (o) {
      if (!baseOvMap[o.id] || JSON.stringify(baseOvMap[o.id]) !== JSON.stringify(o)) {
        enqueue(function () {
          return Hive.api.request('/dns/rewrites', {
            method: 'POST',
            body: { domain: o.hostname, answer: o.value }
          });
        });
      }
    });

    // 8. Ad/Tracker Block (Protection, Filtering Engine, Feeds, Rules, Blocked Services)
    if (base.adblock.enabled !== next.adblock.enabled || (next.adblock.enabled && next.adblock.filteringEnabled === false)) {
      enqueue(function () {
        var wantEn = Boolean(next.adblock.enabled);
        return Hive.api
          .request('/dns/protection', {
            method: 'POST',
            body: { enabled: wantEn }
          })
          .then(function () {
            return Hive.api.request('/dns/filtering/config', {
              method: 'POST',
              body: {
                enabled: wantEn,
                interval: Number(next.adblock.filteringInterval || 24)
              }
            });
          });
      });
    }

    var baseFeedById = {};
    var nextFeedById = {};
    (base.adblock.feeds || []).forEach(function (f) { baseFeedById[f.id] = f; });
    (next.adblock.feeds || []).forEach(function (f) { nextFeedById[f.id] = f; });

    (base.adblock.feeds || []).forEach(function (f) {
      if (!nextFeedById[f.id]) {
        enqueue(function () {
          return Hive.api.request('/dns/filters', {
            method: 'DELETE',
            body: { url: f.url, whitelist: false }
          });
        });
      }
    });
    (next.adblock.feeds || []).forEach(function (f) {
      var prevF = baseFeedById[f.id];
      if (!prevF) {
        enqueue(function () {
          return Hive.api
            .request('/dns/filters', {
              method: 'POST',
              body: { name: f.name, url: f.url, whitelist: false }
            })
            .then(function (addRes) {
              if (!f.enabled) {
                return Hive.api.request('/dns/filters', {
                  method: 'PUT',
                  body: { url: f.url, data: { name: f.name, url: f.url, enabled: false }, whitelist: false }
                });
              }
              return addRes;
            });
        });
      } else if (prevF.enabled !== f.enabled || prevF.name !== f.name || prevF.url !== f.url) {
        enqueue(function () {
          return Hive.api.request('/dns/filters', {
            method: 'PUT',
            body: { url: prevF.url, data: { name: f.name, url: f.url, enabled: Boolean(f.enabled) }, whitelist: false }
          });
        });
      }
    });

    if (
      JSON.stringify(base.adblock.customBlocked) !== JSON.stringify(next.adblock.customBlocked) ||
      JSON.stringify(base.adblock.allowlist) !== JSON.stringify(next.adblock.allowlist)
    ) {
      enqueue(function () {
        return Hive.api.request('/dns/rules', {
          method: 'PUT',
          body: { rules: buildAdGuardUserRules(next.adblock.customBlocked, next.adblock.allowlist, next.adblock.passthroughRules) }
        });
      });
    }

    if (JSON.stringify(base.adblock.blockedServices) !== JSON.stringify(next.adblock.blockedServices)) {
      enqueue(function () {
        return Hive.api.request('/dns/blocked-services', {
          method: 'PUT',
          body: {
            ids: next.adblock.blockedServices || [],
            schedule: next.adblock.blockedServicesSchedule || { time_zone: 'Local' }
          }
        });
      });
    }

    // 9. WireGuard Server & Peer Edits
    if (
      base.vpn.wireguard.enabled !== next.vpn.wireguard.enabled ||
      base.vpn.wireguard.tunnelSubnet !== next.vpn.wireguard.tunnelSubnet ||
      base.vpn.wireguard.listenPort !== next.vpn.wireguard.listenPort ||
      base.vpn.wireguard.endpointHost !== next.vpn.wireguard.endpointHost ||
      base.vpn.wireguard.dns !== next.vpn.wireguard.dns
    ) {
      enqueue(function () {
        return Hive.api.request('/vpn/wireguard', {
          method: 'PUT',
          body: {
            enabled: Boolean(next.vpn.wireguard.enabled),
            address: next.vpn.wireguard.tunnelSubnet,
            listen_port: Number(next.vpn.wireguard.listenPort || 51820),
            endpoint: next.vpn.wireguard.endpointHost || '',
            dns: next.vpn.wireguard.dns || next.lanConfig.ip
          }
        });
      });
    }

    var basePeerMap = {};
    var nextPeerMap = {};
    (base.vpn.wireguard.peers || []).forEach(function (p) { basePeerMap[p.id] = p; });
    (next.vpn.wireguard.peers || []).forEach(function (p) { nextPeerMap[p.id] = p; });

    (base.vpn.wireguard.peers || []).forEach(function (p) {
      if (!nextPeerMap[p.id]) {
        enqueue(function () {
          return Hive.api.request('/vpn/wireguard/peers/' + encodeURIComponent(p.id), { method: 'DELETE' });
        });
      }
    });
    (next.vpn.wireguard.peers || []).forEach(function (p) {
      var prevP = basePeerMap[p.id];
      if (prevP && (prevP.name !== p.name || prevP.enabled !== p.enabled || prevP.allowedIps !== p.allowedIps)) {
        enqueue(function () {
          return Hive.api.request('/vpn/wireguard/peers/' + encodeURIComponent(p.id), {
            method: 'PATCH',
            body: { name: p.name, enabled: Boolean(p.enabled), allowed_ips: p.allowedIps }
          });
        });
      }
    });

    // 10. Dropbear SSH Policy
    if (
      base.access.ssh.passwordAuth !== next.access.ssh.passwordAuth ||
      base.access.ssh.allowRootLogin !== next.access.ssh.allowRootLogin ||
      base.access.ssh.idleTimeout !== next.access.ssh.idleTimeout
    ) {
      enqueue(function () {
        return Hive.api.request('/services/ssh', {
          method: 'PUT',
          body: {
            password_auth: Boolean(next.access.ssh.passwordAuth),
            allow_root_login: Boolean(next.access.ssh.allowRootLogin),
            idle_timeout: Number(next.access.ssh.idleTimeout || 0)
          }
        });
      });
    }

    // 11. LAN IP / Port Assignment or Atomic LAN <-> WAN Swap (runs last so AdGuardHome & firewall updates commit before LAN IP moves)
    if (portsCrossed) {
      enqueue(function () {
        return Hive.api.request('/network/swap', {
          method: 'POST',
          body: {
            lan: buildLanPayload(next.lanConfig),
            wan: buildWanPayload(next.wanConfig)
          }
        }).then(capturePending);
      });
    } else if (lanChanged) {
      enqueue(function () {
        return Hive.api.request('/network/lan', {
          method: 'PUT',
          body: buildLanPayload(next.lanConfig)
        }).then(capturePending);
      });
    }

    // Run queued API calls sequentially in dependency order
    var chain = Promise.resolve();
    tasks.forEach(function (task) {
      chain = chain.then(function () {
        return task();
      });
    });

    return chain.then(function () {
      Hive.store.commitWorkingAsClean();
      Hive.store.recordAudit({
        severity: 'success',
        module: changes.length === 1 ? changes[0].module : 'System',
        summary: 'Committed ' + changes.length + ' configuration ' + (changes.length === 1 ? 'change' : 'changes') + ' to netbeed'
      });
      return bootstrapAll()
        .catch(function () {})
        .then(function () {
          return {
            count: changes.length,
            newUrl: newLanUrl,
            pendingCommit: latestPendingCommit
          };
        });
    });
  }

  Hive.services = {
    bootstrapAll: bootstrapAll,

    system: {
      getSnapshot: function () {
        return safeGet('/system/overview').then(function (ov) {
          if (ov && ov.system) {
            Hive.store.updateTelemetry(function (sys, st) {
              var s = ov.system;
              sys.hostname = s.hostname || sys.hostname;
              sys.fqdn = (s.hostname || 'netbee') + '.lan';
              sys.model = s.board_model || sys.model;
              if (s.os) {
                sys.firmware = s.os.pretty_name || sys.firmware;
                sys.kernel = s.os.kernel ? 'Linux ' + s.os.kernel : sys.kernel;
              }
              sys.uptimeSeconds = Number(s.uptime_seconds || 0);
              sys.cpuCores = Number(s.cpu_cores || 4);
              sys.cpuFreqMhz = s.cpu_freq_mhz !== undefined ? s.cpu_freq_mhz : null;
              sys.cpuGovernor = s.cpu_governor || '';
              sys.cpuTempC = s.cpu_temp_c !== undefined ? s.cpu_temp_c : null;
              sys.fanRpm = s.fan_rpm !== undefined ? s.fan_rpm : null;
              sys.undervoltage = Boolean(s.undervoltage);
              sys.rootfsExpanded = s.rootfs_expanded !== false;
              sys.memTotalMb = Number(s.mem_total_mb || sys.memTotalMb);
              sys.memUsedMb = Number(s.mem_used_mb || sys.memUsedMb);
              sys.memTotalGb = Number((sys.memTotalMb / 1024).toFixed(2));
              sys.memUsedGb = Number((sys.memUsedMb / 1024).toFixed(2));
              sys.loadAvg = Array.isArray(s.load_avg) ? s.load_avg : sys.loadAvg;
              sys.statesActive = Number(s.conntrack_count || 0);
              sys.statesMax = Number(s.conntrack_max || 131072);
              sys.disks = Array.isArray(s.disks) ? s.disks : [];
              if (Array.isArray(ov.services)) {
                st.daemons = ov.services.map(function (svc) {
                  return {
                    id: svc.name,
                    name: svc.name,
                    description: svc.description || '',
                    status: svc.running ? 'running' : 'stopped',
                    running: Boolean(svc.running),
                    pid: svc.pid || '—',
                    actions: Array.isArray(svc.actions) ? svc.actions : ['restart']
                  };
                });
              }
            });
          }
          var st = Hive.store.getState();
          return {
            system: clone(st.system),
            interfaces: clone(st.interfaces),
            firewallConfig: clone(st.firewallConfig),
            firewallCount: st.firewallRules.length,
            firewallEnabledCount: st.firewallRules.filter(function (r) { return r.enabled; }).length
          };
        });
      },

      getPendingCommit: function () {
        return Hive.api.request('/system/pending-commit', { method: 'GET' });
      },

      confirmCommit: function () {
        return Hive.api.request('/system/confirm', { method: 'POST' });
      },

      rollbackNow: function () {
        return Hive.api.request('/system/rollback', { method: 'POST' }).then(function (res) {
          return bootstrapAll().then(function () { return res; });
        });
      }
    },

    interfaces: {
      getOverview: function () {
        var st = Hive.store.getState();
        return Promise.resolve({
          interfaces: clone(st.interfaces),
          lanConfig: clone(st.lanConfig),
          wanConfig: clone(st.wanConfig),
          ipv6Config: clone(st.ipv6Config)
        });
      },

      list: function () {
        return Promise.resolve(clone(Hive.store.getState().interfaces));
      },

      stageLan: function (patch) {
        var parsed = parseCidrOrIpMask(patch.ipv4 || patch.ip, patch.netmask);
        Hive.store.stageMutation({ module: 'Interfaces' }, function (st) {
          var prevLanIf = st.lanConfig.interface || 'eth0';
          var nextLanIf = patch.interface || prevLanIf;
          if (nextLanIf === st.wanConfig.interface && prevLanIf !== nextLanIf) {
            st.wanConfig.interface = prevLanIf;
            st.wanConfig.pinMac = '';
          }
          st.lanConfig.interface = nextLanIf;
          st.lanConfig.ip = parsed.ip;
          st.lanConfig.netmask = patch.netmask || parsed.netmask;
          st.lanConfig.mtu = Number(patch.mtu || st.lanConfig.mtu || 1500);
          st.lanConfig.pinMac = patch.pinMac !== undefined ? patch.pinMac : (st.lanConfig.pinMac || '');
          if (st.dhcp && st.dhcp.scopes && st.dhcp.scopes[0]) {
            var sc = st.dhcp.scopes[0];
            sc.iface = st.lanConfig.interface;
            sc.gatewayIp = st.lanConfig.ip;
            sc.subnetMask = st.lanConfig.netmask;
            sc.dnsServer = st.lanConfig.ip;
            sc.subnet = st.lanConfig.ip.split('.').slice(0, 3).join('.') + '.0/' + netmaskToPrefix(st.lanConfig.netmask);
          }
          var item = st.interfaces.find(function (i) { return i.device === st.lanConfig.interface; });
          if (item) {
            item.zone = 'lan';
            item.ipv4 = st.lanConfig.ip + '/' + netmaskToPrefix(st.lanConfig.netmask);
            item.mtu = st.lanConfig.mtu;
          }
        });
        return Promise.resolve(true);
      },

      stageWan: function (patch) {
        Hive.store.stageMutation({ module: 'Interfaces' }, function (st) {
          var prevWanIf = st.wanConfig.interface || 'eth1';
          var nextWanIf = patch.interface || prevWanIf;
          if (nextWanIf === st.lanConfig.interface && prevWanIf !== nextWanIf) {
            st.lanConfig.interface = prevWanIf;
            st.lanConfig.pinMac = '';
          }
          st.wanConfig.mode = patch.mode || 'dhcp';
          st.wanConfig.interface = nextWanIf;
          st.wanConfig.vlanEnabled = Boolean(patch.vlanEnabled || st.wanConfig.mode === 'ont_vlan');
          st.wanConfig.vlanId = Number(patch.vlanId || 35);
          st.wanConfig.staticIp = patch.staticIp || '';
          st.wanConfig.staticNetmask = patch.staticNetmask || '255.255.255.0';
          st.wanConfig.staticGateway = patch.staticGateway || '';
          st.wanConfig.pppoeUser = patch.pppoeUser || '';
          if (patch.pppoePassword !== undefined) {
            st.wanConfig.pppoePassword = patch.pppoePassword;
          }
          st.wanConfig.peerDns = patch.peerDns !== false;
          st.wanConfig.dnsServers = Array.isArray(patch.dnsServers) ? patch.dnsServers : [];
          st.wanConfig.macClone = patch.macClone || '';
          st.wanConfig.pinMac = patch.pinMac !== undefined ? patch.pinMac : (st.wanConfig.pinMac || '');
          var isPpp = st.wanConfig.mode === 'pppoe' || st.wanConfig.mode === 'ont_vlan';
          st.wanConfig.mtu = Number(patch.mtu || (isPpp ? 1492 : 1500));
          st.wanConfig.ipv6Pd = Boolean(patch.ipv6Pd);
          st.ipv6Config.ipv6Pd = Boolean(patch.ipv6Pd);
          if (patch.radvdEnabled !== undefined) {
            st.ipv6Config.radvdEnabled = Boolean(patch.radvdEnabled);
          }
          var item = st.interfaces.find(function (i) { return i.device === st.wanConfig.interface; });
          if (item) {
            item.zone = 'wan';
            item.mtu = st.wanConfig.mtu;
          }
        });
        return Promise.resolve(true);
      },

      swapRoles: function () {
        return Hive.api.request('/network/swap', { method: 'POST', body: {} }).then(function (res) {
          if (res && res.pending_commit && (res.pending_commit.active || res.pending_commit.pending)) {
            window.dispatchEvent(new CustomEvent('hive:pendingcommit', { detail: res.pending_commit }));
          }
          return bootstrapAll().then(function () { return res; });
        });
      },

      setLinkState: function (iface, up) {
        return Hive.api
          .request('/network/interfaces/' + encodeURIComponent(iface) + '/state', {
            method: 'POST',
            body: { up: Boolean(up) }
          })
          .then(function (res) {
            return bootstrapAll().then(function () { return res; });
          });
      },

      setLabel: function (iface, label) {
        return Hive.api
          .request('/network/interfaces/' + encodeURIComponent(iface) + '/label', {
            method: 'PUT',
            body: { label: String(label || '').trim() }
          })
          .then(function (res) {
            return bootstrapAll().then(function () { return res; });
          });
      },

      stageIpv6: function (patch) {
        Hive.store.stageMutation({ module: 'Interfaces' }, function (st) {
          st.ipv6Config.radvdEnabled = Boolean(patch.radvdEnabled);
          st.ipv6Config.ipv6Pd = Boolean(patch.ipv6Pd);
          st.wanConfig.ipv6Pd = Boolean(patch.ipv6Pd);
        });
        return Promise.resolve(true);
      },

      reconnectWan: function () {
        return Hive.api.request('/network/wan/reconnect', { method: 'POST' }).then(function (res) {
          return bootstrapAll().then(function () { return res; });
        });
      },

      getEthtool: function (iface) {
        return Hive.api.request('/network/ethtool/' + encodeURIComponent(iface), { method: 'GET' });
      },

      saveEthtool: function (iface, payload) {
        return Hive.api
          .request('/network/ethtool/' + encodeURIComponent(iface), { method: 'PUT', body: payload })
          .then(function (res) {
            return bootstrapAll().then(function () { return res; });
          });
      }
    },

    routing: {
      getOverview: function () {
        return Promise.all([safeGet('/network/routes'), safeGet('/network/neighbors')]).then(function (arr) {
          var routesRes = arr[0];
          var neighRes = arr[1];
          Hive.store.updateRuntimeState(function (st) {
            if (routesRes && Array.isArray(routesRes.ipv4)) {
              var conn = [];
              routesRes.ipv4.forEach(function (r, idx) {
                if (r.dst && r.dst !== 'default' && (!r.gateway || r.protocol === 'kernel')) {
                  conn.push({
                    id: 'conn-' + idx,
                    destination: r.dst,
                    gateway: r.gateway || 'Direct (Kernel)',
                    iface: r.dev || '—',
                    metric: Number(r.metric || 0),
                    type: 'connected',
                    enabled: true,
                    description: r.protocol || 'Connected subnet'
                  });
                }
              });
              st.connectedRoutes = conn;
            }
            if (Array.isArray(neighRes)) {
              st.neighbors = neighRes.map(function (n, idx) {
                return {
                  id: 'nb-' + idx,
                  ip: n.dst || '—',
                  mac: n.lladdr || '—',
                  iface: n.dev || '—',
                  state: Array.isArray(n.state) ? n.state.join(', ') : String(n.state || 'REACHABLE')
                };
              });
            }
          }, 'routing-refresh');

          var st = Hive.store.getState();
          return {
            gateways: clone(st.system.gateways),
            staticRoutes: clone(st.staticRoutes),
            connectedRoutes: clone(st.connectedRoutes),
            neighbors: clone(st.neighbors),
            interfaces: clone(st.interfaces)
          };
        });
      },

      saveRoute: function (route) {
        var isEdit = Boolean(route.id);
        var id = route.id || nextId('rt');
        Hive.store.stageMutation({ module: 'Routing' }, function (state) {
          if (isEdit) {
            var idx = state.staticRoutes.findIndex(function (r) { return r.id === id; });
            if (idx !== -1) state.staticRoutes[idx] = Object.assign({}, state.staticRoutes[idx], route, { id: id });
          } else {
            state.staticRoutes.push(Object.assign({}, route, { id: id }));
          }
        });
        return Promise.resolve({ id: id });
      },

      toggleRoute: function (id, enabled) {
        Hive.store.stageMutation(
          { module: 'Routing' },
          function (state) {
            var r = state.staticRoutes.find(function (x) { return x.id === id; });
            if (r) r.enabled = Boolean(enabled);
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve({ id: id });
      },

      deleteRoute: function (id) {
        Hive.store.stageMutation({ module: 'Routing' }, function (state) {
          state.staticRoutes = state.staticRoutes.filter(function (x) { return x.id !== id; });
        });
        return Promise.resolve({ id: id });
      },

      lookupRoute: function (destIp) {
        var st = Hive.store.getState();
        var v = Hive.validators;
        var isV6 = v.isIPv6(destIp) && destIp.indexOf('/') === -1;
        var candidates = [];
        (st.connectedRoutes || []).forEach(function (c) {
          if (v.isCIDR(c.destination) || v.isIPv4(c.destination) || v.isIPv6(c.destination)) {
            candidates.push(Object.assign({}, c, { sourceType: 'Connected Kernel Route', enabled: true }));
          }
        });
        (st.staticRoutes || []).forEach(function (r) {
          if (v.isCIDR(r.destination) || v.isIPv4(r.destination) || v.isIPv6(r.destination)) {
            candidates.push(Object.assign({}, r, { sourceType: 'Static Route' }));
          }
        });
        var gw = st.system.gateways && st.system.gateways[0];
        if (!isV6 && gw && gw.address && gw.address.indexOf('Awaiting') === -1) {
          candidates.push({
            id: gw.id,
            destination: '0.0.0.0/0',
            gateway: gw.address,
            iface: gw.iface,
            metric: gw.metric !== undefined ? gw.metric : 100,
            sourceType: 'Default WAN Gateway',
            enabled: true
          });
        }
        return Promise.resolve(v.findLongestPrefixRoute(destIp, candidates));
      }
    },

    dhcpDns: {
      getOverview: function () {
        var st = Hive.store.getState();
        return Promise.resolve({
          dhcp: clone(st.dhcp),
          dns: clone(st.dns),
          interfaces: clone(st.interfaces)
        });
      },

      updateScope: function (id, patch) {
        Hive.store.stageMutation({ module: 'DHCP' }, function (state) {
          var sc = state.dhcp.scopes[0];
          if (sc) {
            sc.rangeStart = patch.rangeStart;
            sc.rangeEnd = patch.rangeEnd;
            if (Hive.validators && Hive.validators.isIPv4(patch.rangeStart) && Hive.validators.isIPv4(patch.rangeEnd)) {
              sc.poolSize = Math.max(1, Hive.validators.ipv4ToInt(patch.rangeEnd) - Hive.validators.ipv4ToInt(patch.rangeStart) + 1);
            }
            sc.leaseHours = Number(patch.leaseHours || 24);
            sc.enabled = Boolean(patch.enabled);
          }
        });
        return Promise.resolve({ id: id });
      },

      promoteLease: function (leaseId) {
        var st = Hive.store.getState();
        var lease = st.dhcp.leases.find(function (l) { return l.id === leaseId; });
        if (!lease) return Promise.resolve({ ok: false, reason: 'Lease not found' });
        var exists = st.dhcp.reservations.some(function (r) {
          return r.mac.toLowerCase() === lease.mac.toLowerCase() || r.ip === lease.ip;
        });
        if (exists) return Promise.resolve({ ok: false, reason: 'Already reserved' });

        Hive.store.stageMutation({ module: 'DHCP' }, function (state) {
          state.dhcp.reservations.push({
            id: 'res-' + lease.mac.replace(/[^A-F0-9]/gi, '').toUpperCase(),
            ip: lease.ip,
            mac: lease.mac.toUpperCase(),
            hostname: lease.hostname || 'client',
            iface: state.lanConfig.interface || 'eth0',
            description: 'Pinned static lease'
          });
        });
        return Promise.resolve({ ok: true, hostname: lease.hostname, ip: lease.ip });
      },

      saveReservation: function (res) {
        var isEdit = Boolean(res.id);
        var id = res.id || ('res-' + String(res.mac || '').replace(/[^A-F0-9]/gi, '').toUpperCase());
        Hive.store.stageMutation({ module: 'DHCP' }, function (state) {
          var norm = Object.assign({}, res, {
            id: id,
            mac: String(res.mac || '').toUpperCase(),
            iface: state.lanConfig.interface || 'eth0'
          });
          if (isEdit) {
            var idx = state.dhcp.reservations.findIndex(function (x) { return x.id === id; });
            if (idx !== -1) state.dhcp.reservations[idx] = norm;
          } else {
            state.dhcp.reservations.push(norm);
          }
        });
        return Promise.resolve({ id: id });
      },

      deleteReservation: function (id) {
        Hive.store.stageMutation({ module: 'DHCP' }, function (state) {
          state.dhcp.reservations = state.dhcp.reservations.filter(function (x) { return x.id !== id; });
        });
        return Promise.resolve({ id: id });
      },

      updateDnsSettings: function (patch) {
        Hive.store.stageMutation({ module: 'DNS' }, function (state) {
          state.dns.resolvers = patch.resolvers;
          state.dns.dotEnabled = patch.resolvers.some(function (u) { return /^tls:\/\/|^https:\/\/|^quic:\/\//i.test(u); });
          state.dns.dnssecEnabled = Boolean(patch.dnssecEnabled);
          state.dns.cacheSize = Number(patch.cacheSize);
        });
        return Promise.resolve(true);
      },

      saveDnsOverride: function (ov) {
        var isEdit = Boolean(ov.id);
        var id = ov.id || nextId('rw');
        var vRef = Hive.validators;
        var cleanHost = String(ov.hostname || '').trim().replace(/\.$/, '');
        var cleanVal = String(ov.value || '').trim().replace(/\.$/, '');
        var recType = vRef && vRef.isIPv6(cleanVal) ? 'AAAA' : (vRef && vRef.isIPv4(cleanVal) ? 'A' : 'CNAME');
        Hive.store.stageMutation({ module: 'DNS' }, function (state) {
          var item = {
            id: id,
            hostname: cleanHost,
            type: recType,
            value: cleanVal,
            ttl: 300,
            description: ov.description || 'AdGuard DNS Rewrite'
          };
          if (isEdit) {
            var idx = state.dns.overrides.findIndex(function (x) { return x.id === id; });
            if (idx !== -1) state.dns.overrides[idx] = item;
          } else {
            state.dns.overrides.push(item);
          }
        });
        return Promise.resolve({ id: id });
      },

      deleteDnsOverride: function (id) {
        Hive.store.stageMutation({ module: 'DNS' }, function (state) {
          state.dns.overrides = state.dns.overrides.filter(function (x) { return x.id !== id; });
        });
        return Promise.resolve({ id: id });
      },

      clearCache: function () {
        return Hive.api.request('/dns/cache/clear', { method: 'POST' });
      }
    },

    sqm: {
      getOverview: function () {
        return safeGet('/qos/sqm').then(function (sqmRes) {
          if (sqmRes && sqmRes.config) {
            Hive.store.updateRuntimeState(function (st) {
              st.sqm.statusOutput = sqmRes.status || '';
            }, 'sqm-status');
          }
          var st = Hive.store.getState();
          return {
            sqm: clone(st.sqm),
            firewallConfig: clone(st.firewallConfig),
            interfaces: clone(st.interfaces)
          };
        });
      },

      toggleEnabled: function (enabled) {
        Hive.store.stageMutation(
          { module: 'SQM' },
          function (state) {
            if (state.sqm) state.sqm.enabled = Boolean(enabled);
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve({ enabled: Boolean(enabled) });
      },

      update: function (patch) {
        Hive.store.stageMutation({ module: 'SQM' }, function (state) {
          state.sqm = Object.assign({}, state.sqm, {
            enabled: Boolean(patch.enabled),
            iface: String(patch.iface || state.wanConfig.interface || 'eth1'),
            downloadKbps: Math.max(500, Math.round(Number(patch.downloadKbps) || 95000)),
            uploadKbps: Math.max(250, Math.round(Number(patch.uploadKbps) || 19000)),
            qdisc: 'cake',
            script: 'netbee-sqm (sch_cake + ifb0)',
            linkLayer: String(patch.linkLayer || 'ethernet'),
            overheadBytes: Math.max(0, Math.min(128, Math.round(Number(patch.overheadBytes) || 0)))
          });
        });
        return Promise.resolve(true);
      }
    },

    diagnostics: {
      ping: function (host, count) {
        return Hive.api.request('/diag/ping', {
          method: 'POST',
          body: { host: String(host || '').trim(), count: Number(count || 4) }
        });
      },

      mtr: function (host, cycles) {
        return Hive.api.request('/diag/mtr', {
          method: 'POST',
          body: { host: String(host || '').trim(), cycles: Number(cycles || 4) }
        });
      },

      dnsLookup: function (host, server) {
        return Hive.api.request('/diag/dns', {
          method: 'POST',
          body: { host: String(host || '').trim(), server: String(server || '').trim() }
        });
      },

      capture: function (opts) {
        return Hive.api.request('/diag/capture', {
          method: 'POST',
          body: {
            interface: opts.interface || 'eth0',
            count: Number(opts.count || 20),
            proto: opts.proto ? String(opts.proto).toLowerCase() : '',
            port: opts.port ? Number(opts.port) : 0
          }
        });
      },

      iperfClient: function (opts) {
        return Hive.api.request('/diag/iperf3', {
          method: 'POST',
          body: {
            host: String(opts.host || '').trim(),
            port: Number(opts.port || 5201),
            duration: Number(opts.duration || 5),
            reverse: Boolean(opts.reverse)
          }
        });
      },

      getIperfServer: function () {
        return Hive.api.request('/diag/iperf3/server', { method: 'GET' });
      },

      startIperfServer: function (opts) {
        return Hive.api.request('/diag/iperf3/server', {
          method: 'POST',
          body: {
            bind_ip: opts.bindIp || '',
            port: Number(opts.port || 5201),
            duration_seconds: Number(opts.durationSeconds || 300)
          }
        });
      },

      stopIperfServer: function () {
        return Hive.api.request('/diag/iperf3/server', { method: 'DELETE' });
      }
    },

    firewall: {
      getOverview: function () {
        var st = Hive.store.getState();
        return Promise.resolve({
          rules: clone(st.firewallRules),
          config: clone(st.firewallConfig),
          aliases: clone(st.aliases),
          interfaces: clone(st.interfaces),
          zonePolicies: clone(st.zonePolicies)
        });
      },

      stageToggles: function (patch, options) {
        Hive.store.stageMutation(
          { module: 'Firewall' },
          function (st) {
            if (patch.flowOffload !== undefined) st.firewallConfig.flowOffload = Boolean(patch.flowOffload);
            if (patch.transparentDns !== undefined) {
              st.firewallConfig.transparentDns = Boolean(patch.transparentDns);
              st.adblock.forceDns = Boolean(patch.transparentDns);
            }
            if (patch.exposeWireguard !== undefined) st.firewallConfig.exposeWireguard = Boolean(patch.exposeWireguard);
            if (patch.wireguardPort !== undefined) st.firewallConfig.wireguardPort = Number(patch.wireguardPort || 51820);
          },
          options
        );
        return Promise.resolve(true);
      },

      saveRule: function (rule) {
        var isEdit = Boolean(rule.id);
        var id = rule.id || nextId('r');
        Hive.store.stageMutation({ module: 'Firewall' }, function (state) {
          var normalized = Object.assign({}, rule, {
            id: id,
            chain: rule.chain || 'input',
            direction: rule.chain || 'input'
          });
          if (isEdit) {
            var idx = state.firewallRules.findIndex(function (r) { return r.id === id; });
            if (idx !== -1) state.firewallRules[idx] = Object.assign({}, state.firewallRules[idx], normalized);
          } else {
            state.firewallRules.unshift(Object.assign({}, normalized, { hits: 0 }));
          }
        });
        return Promise.resolve({ id: id });
      },

      toggleRule: function (id, enabled) {
        Hive.store.stageMutation(
          { module: 'Firewall' },
          function (state) {
            var r = state.firewallRules.find(function (x) { return x.id === id; });
            if (r) r.enabled = Boolean(enabled);
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve({ id: id, enabled: enabled });
      },

      deleteRule: function (id) {
        Hive.store.stageMutation({ module: 'Firewall' }, function (state) {
          state.firewallRules = state.firewallRules.filter(function (x) { return x.id !== id; });
        });
        return Promise.resolve({ id: id });
      },

      reorderRule: function (id, direction, chainFilter) {
        var cur = Hive.store.getState().firewallRules;
        var slots = [];
        for (var k = 0; k < cur.length; k++) {
          if (!chainFilter || chainFilter === 'all' || cur[k].chain === chainFilter) slots.push(k);
        }
        var curPos = slots.findIndex(function (idx) { return cur[idx].id === id; });
        var nextPos = direction === 'up' ? curPos - 1 : curPos + 1;
        if (curPos === -1 || nextPos < 0 || nextPos >= slots.length) {
          return Promise.resolve({ moved: false });
        }
        Hive.store.stageMutation({ module: 'Firewall' }, function (state) {
          var rules = state.firewallRules;
          var a = slots[curPos];
          var b = slots[nextPos];
          var tmp = rules[a];
          rules[a] = rules[b];
          rules[b] = tmp;
        });
        return Promise.resolve({ moved: true, id: id, fromIndex: curPos + 1, toIndex: nextPos + 1 });
      },

      moveRule: function (sourceId, targetId, position, chainFilter) {
        if (!sourceId || !targetId || sourceId === targetId) return Promise.resolve({ moved: false });
        var currentRules = Hive.store.getState().firewallRules;
        var matchingSlots = [];
        for (var i = 0; i < currentRules.length; i++) {
          if (!chainFilter || chainFilter === 'all' || currentRules[i].chain === chainFilter) matchingSlots.push(i);
        }
        var subset = matchingSlots.map(function (idx) { return currentRules[idx]; });
        var fromIdx = subset.findIndex(function (r) { return r.id === sourceId; });
        if (fromIdx === -1) return Promise.resolve({ moved: false });

        var sim = subset.slice();
        var item = sim.splice(fromIdx, 1)[0];
        var adjIdx = sim.findIndex(function (r) { return r.id === targetId; });
        if (adjIdx === -1) return Promise.resolve({ moved: false });
        var insertIdx = position === 'after' ? adjIdx + 1 : adjIdx;
        if (insertIdx === fromIdx) return Promise.resolve({ moved: false });

        Hive.store.stageMutation({ module: 'Firewall' }, function (state) {
          var rules = state.firewallRules;
          var list = matchingSlots.map(function (idx) { return rules[idx]; });
          var mv = list.splice(fromIdx, 1)[0];
          list.splice(insertIdx, 0, mv);
          for (var j = 0; j < matchingSlots.length; j++) {
            rules[matchingSlots[j]] = list[j];
          }
        });
        return Promise.resolve({ moved: true, id: sourceId, fromIndex: fromIdx + 1, toIndex: insertIdx + 1 });
      },

      simulatePacket: function (packet) {
        var st = Hive.store.getState();
        var chain = packet.chain || 'input';
        var proto = String(packet.protocol || 'TCP').toUpperCase();
        var src = String(packet.source || '').trim();
        var dst = String(packet.destination || '').trim();
        var port = String(packet.port || '').trim();
        var inIface = String(packet.inIface || '').trim();
        var outIface = String(packet.outIface || '').trim();

        var chainRules = st.firewallRules.filter(function (r) { return (r.chain || 'input') === chain; });
        for (var i = 0; i < chainRules.length; i++) {
          var r = chainRules[i];
          if (!r.enabled) continue;
          if (r.inIface && inIface && r.inIface !== inIface) continue;
          if (chain === 'forward' && r.outIface && outIface && r.outIface !== outIface) continue;
          var protoMatch = r.protocol === 'ANY' || r.protocol.toUpperCase() === proto;
          var srcMatch = Hive.validators.ipMatchesRuleTarget(src, r.source, st.aliases);
          var dstMatch = Hive.validators.ipMatchesRuleTarget(dst, r.destination, st.aliases);
          var portMatch = proto === 'ICMP' || proto === 'ICMPV6' || Hive.validators.portMatchesRuleTarget(port, r.port, st.aliases);
          if (protoMatch && srcMatch && dstMatch && portMatch) {
            return Promise.resolve({ matched: true, rule: clone(r), ruleIndex: i + 1, action: r.action });
          }
        }
        var wgIf = (st.vpn && st.vpn.wireguard && st.vpn.wireguard.iface) || 'wg0';
        var isTrustedIn = inIface === st.lanConfig.interface || (chain === 'forward' && inIface === wgIf);
        return Promise.resolve({
          matched: false,
          rule: null,
          action: isTrustedIn ? 'pass' : 'block',
          defaultPolicy: isTrustedIn ? 'allow (LAN / VPN default)' : 'drop (WAN hardened default)'
        });
      },

      saveAlias: function (payload) {
        var name = String(payload.name || '').trim();
        var orig = payload.originalName ? String(payload.originalName).trim() : null;
        Hive.store.stageMutation({ module: 'Firewall', persistAliases: true }, function (state) {
          if (orig && orig !== name && state.aliases[orig]) delete state.aliases[orig];
          state.aliases[name] = {
            type: payload.type,
            description: payload.description || 'Local helper alias',
            members: (payload.members || []).slice()
          };
        });
        return Promise.resolve({ ok: true, name: name });
      },

      deleteAlias: function (name) {
        Hive.store.stageMutation({ module: 'Firewall', persistAliases: true }, function (state) {
          delete state.aliases[name];
        });
        return Promise.resolve({ ok: true, name: name });
      },

      getRaw: function () {
        return Hive.api.request('/firewall/raw', { method: 'GET' });
      },

      saveRaw: function (content) {
        return Hive.api.request('/firewall/raw', { method: 'PUT', body: { content: content } });
      },

      getRuleset: function () {
        return Hive.api.request('/firewall/ruleset', { method: 'GET' });
      },

      reload: function () {
        return Hive.api.request('/firewall/reload', { method: 'POST' });
      }
    },

    nat: {
      getOverview: function () {
        var st = Hive.store.getState();
        return Promise.resolve({
          nat: clone(st.nat),
          wanConfig: clone(st.wanConfig),
          interfaces: clone(st.interfaces)
        });
      },

      savePortForward: function (rule) {
        var isEdit = Boolean(rule.id);
        var id = rule.id || nextId('pf');
        Hive.store.stageMutation({ module: 'NAT' }, function (state) {
          var entry = Object.assign({}, rule, { id: id, iface: state.wanConfig.interface || 'eth1' });
          if (isEdit) {
            var idx = state.nat.portForwards.findIndex(function (x) { return x.id === id; });
            if (idx !== -1) state.nat.portForwards[idx] = entry;
          } else {
            state.nat.portForwards.unshift(entry);
          }
        });
        return Promise.resolve({ id: id });
      },

      togglePortForward: function (id, enabled) {
        Hive.store.stageMutation(
          { module: 'NAT' },
          function (state) {
            var r = state.nat.portForwards.find(function (x) { return x.id === id; });
            if (r) r.enabled = Boolean(enabled);
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve({ id: id });
      },

      deletePortForward: function (id) {
        Hive.store.stageMutation({ module: 'NAT' }, function (state) {
          state.nat.portForwards = state.nat.portForwards.filter(function (x) { return x.id !== id; });
        });
        return Promise.resolve({ id: id });
      }
    },

    vpn: {
      getOverview: function () {
        return safeGet('/vpn/wireguard').then(function (wgRes) {
          if (wgRes && wgRes.config) {
            Hive.store.updateRuntimeState(function (st) {
              var wgCfg = wgRes.config;
              var livePeers = wgRes.live_peers || {};
              st.vpn.wireguard.active = Boolean(wgRes.active);
              st.vpn.wireguard.publicKey = wgCfg.public_key || st.vpn.wireguard.publicKey;
              (st.vpn.wireguard.peers || []).forEach(function (p) {
                var lp = livePeers[p.publicKey];
                if (lp) {
                  var hs = Number(lp.latest_handshake || 0);
                  var nowSec = Math.floor(Date.now() / 1000);
                  if (hs > 0) {
                    var ago = Math.max(0, nowSec - hs);
                    p.lastHandshake = ago < 60 ? (ago + 's ago') : ago < 3600 ? (Math.floor(ago / 60) + 'm ago') : (Math.floor(ago / 3600) + 'h ago');
                    p.status = !p.enabled ? 'disabled' : ago < 180 ? 'connected' : 'idle';
                  }
                  p.rxGb = Number(((Number(lp.rx_bytes) || 0) / 1073741824).toFixed(3));
                  p.txGb = Number(((Number(lp.tx_bytes) || 0) / 1073741824).toFixed(3));
                  if (lp.endpoint && lp.endpoint !== '(none)') p.endpoint = lp.endpoint;
                }
              });
            }, 'vpn-refresh');
          }
          var st = Hive.store.getState();
          return {
            wireguard: clone(st.vpn.wireguard),
            firewallConfig: clone(st.firewallConfig)
          };
        });
      },

      stageServer: function (patch) {
        Hive.store.stageMutation({ module: 'VPN' }, function (st) {
          st.vpn.wireguard.enabled = Boolean(patch.enabled);
          st.vpn.wireguard.tunnelSubnet = patch.tunnelSubnet || '10.66.66.1/24';
          st.vpn.wireguard.listenPort = Number(patch.listenPort || 51820);
          st.vpn.wireguard.endpointHost = patch.endpointHost || '';
          st.vpn.wireguard.dns = patch.dns || st.lanConfig.ip;
          if (patch.exposeWireguard !== undefined) {
            st.firewallConfig.exposeWireguard = Boolean(patch.exposeWireguard);
            st.firewallConfig.wireguardPort = st.vpn.wireguard.listenPort;
          }
        });
        return Promise.resolve(true);
      },

      createPeerLive: function (payload) {
        var baseWg = Hive.store.getCommittedState().vpn.wireguard;
        var nextWg = Hive.store.getState().vpn.wireguard;
        var baseFw = Hive.store.getCommittedState().firewallConfig;
        var nextFw = Hive.store.getState().firewallConfig;
        var syncSrv = Promise.resolve();
        if (
          baseWg.enabled !== nextWg.enabled ||
          baseWg.tunnelSubnet !== nextWg.tunnelSubnet ||
          baseWg.listenPort !== nextWg.listenPort ||
          baseWg.endpointHost !== nextWg.endpointHost ||
          baseWg.dns !== nextWg.dns
        ) {
          syncSrv = Hive.api
            .request('/vpn/wireguard', {
              method: 'PUT',
              body: {
                enabled: Boolean(nextWg.enabled),
                address: nextWg.tunnelSubnet,
                listen_port: Number(nextWg.listenPort || 51820),
                endpoint: nextWg.endpointHost || '',
                dns: nextWg.dns || Hive.store.getState().lanConfig.ip
              }
            })
            .then(function () {
              if (baseFw.exposeWireguard !== nextFw.exposeWireguard || baseFw.wireguardPort !== nextFw.wireguardPort) {
                return Hive.api.request('/firewall/toggles', {
                  method: 'PATCH',
                  body: {
                    expose_wireguard: Boolean(nextFw.exposeWireguard),
                    wireguard_port: Number(nextFw.wireguardPort || nextWg.listenPort || 51820)
                  }
                });
              }
            });
        }
        return syncSrv
          .then(function () {
            return Hive.api.request('/vpn/wireguard/peers', {
              method: 'POST',
              body: {
                name: payload.name,
                allowed_ips: payload.allowedIps,
                public_key: payload.publicKey || '',
                use_psk: Boolean(payload.usePsk)
              }
            });
          })
          .then(function (res) {
            return bootstrapAll().then(function () {
              return {
                peer: res.peer,
                clientConfig: res.client_config || ''
              };
            });
          });
      },

      saveWgPeer: function (peer) {
        Hive.store.stageMutation({ module: 'VPN' }, function (st) {
          var idx = st.vpn.wireguard.peers.findIndex(function (p) { return p.id === peer.id; });
          if (idx !== -1) {
            st.vpn.wireguard.peers[idx] = Object.assign({}, st.vpn.wireguard.peers[idx], {
              name: peer.name,
              allowedIps: peer.allowedIps,
              enabled: Boolean(peer.enabled),
              status: peer.enabled ? 'idle' : 'disabled'
            });
          }
        });
        return Promise.resolve({ id: peer.id });
      },

      toggleWgPeer: function (id, enabled) {
        Hive.store.stageMutation(
          { module: 'VPN' },
          function (st) {
            var p = st.vpn.wireguard.peers.find(function (x) { return x.id === id; });
            if (p) {
              p.enabled = Boolean(enabled);
              p.status = enabled ? 'idle' : 'disabled';
            }
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve({ id: id });
      },

      deleteWgPeer: function (id) {
        Hive.store.stageMutation({ module: 'VPN' }, function (st) {
          st.vpn.wireguard.peers = st.vpn.wireguard.peers.filter(function (p) { return p.id !== id; });
        });
        return Promise.resolve({ id: id });
      },

      buildWgClientConfig: function (peerId) {
        var wg = Hive.store.getState().vpn.wireguard;
        var peer = wg.peers.find(function (p) { return p.id === peerId; });
        if (!peer) return '';
        var ep = wg.endpointHost ? (wg.endpointHost + ':' + wg.listenPort) : ('<YOUR_PUBLIC_IP_OR_DDNS>:' + wg.listenPort);
        return [
          '# NetBee OS WireGuard Client Profile — ' + peer.name,
          '[Interface]',
          'PrivateKey = <CLIENT_PRIVATE_KEY>',
          'Address = ' + peer.allowedIps,
          'DNS = ' + wg.dns,
          '',
          '[Peer]',
          'PublicKey = ' + (wg.publicKey || '<ENABLE_SERVER_FIRST>'),
          peer.hasPsk ? 'PresharedKey = <CONFIGURED_AT_CREATION>' : '# No PresharedKey',
          'Endpoint = ' + ep,
          'AllowedIPs = 0.0.0.0/0, ::/0',
          'PersistentKeepalive = 25'
        ].join('\n');
      }
    },

    flows: {
      list: function () {
        return safeGet('/firewall/conntrack').then(function (res) {
          if (res && Array.isArray(res.flows)) {
            var stRef = Hive.store.getState();
            var v = Hive.validators;
            var lanIp = (stRef.lanConfig && stRef.lanConfig.ip) || '192.168.10.1';
            var lanMask = (stRef.lanConfig && stRef.lanConfig.netmask) || '255.255.255.0';
            var lanCidr = lanIp + '/' + netmaskToPrefix(lanMask);
            var wgCidr = (stRef.vpn && stRef.vpn.wireguard && stRef.vpn.wireguard.tunnelSubnet) || '10.66.66.1/24';
            var lanIfaceEntry = (stRef.interfaces || []).find(function (i) { return i.device === stRef.lanConfig.interface; });
            var lanV6Cidr = lanIfaceEntry && lanIfaceEntry.ipv6 && lanIfaceEntry.ipv6 !== '—' ? lanIfaceEntry.ipv6 : '';
            var mapped = res.flows.map(function (f, idx) {
              var proto = String(f.proto || 'tcp').toUpperCase();
              var src = f.src || '0.0.0.0';
              var dst = f.dst || '0.0.0.0';
              var bytesTotal = (Number(f.bytes) || 0) + (Number(f.reply_bytes) || 0);
              var pktsTotal = (Number(f.packets) || 0) + (Number(f.reply_packets) || 0);
              var zone = 'wan';
              if (v && v.ipMatchesCidr(src, wgCidr)) zone = 'vpn';
              else if (v && (v.ipMatchesCidr(src, lanCidr) || (lanV6Cidr && v.ipMatchesCidr(src, lanV6Cidr)))) zone = 'lan';
              return {
                id: 'ct-' + idx,
                protocol: proto,
                rawProto: String(f.proto || 'tcp').toLowerCase(),
                zone: zone,
                srcIp: src,
                srcPort: f.sport || '—',
                dstIp: dst,
                dstPort: f.dport || '—',
                state: f.state || (f.flags || 'ACTIVE').replace(/[\[\]]/g, ''),
                bytesMb: Number((bytesTotal / 1048576).toFixed(2)),
                packets: pktsTotal,
                timeoutSec: Number(f.timeout || 0),
                raw: f.raw || ''
              };
            });
            Hive.store.updateRuntimeState(function (st) {
              st.flows = mapped;
              if (res.kernel_count !== undefined) st.system.statesActive = Number(res.kernel_count);
              if (res.conntrack_max !== undefined) st.system.statesMax = Number(res.conntrack_max);
            }, 'flows-refresh');
          }
          return clone(Hive.store.getState().flows || []);
        });
      },

      terminate: function (flow) {
        if (!flow) return Promise.resolve(null);
        var q =
          '?proto=' + encodeURIComponent(flow.rawProto || flow.protocol.toLowerCase()) +
          '&src=' + encodeURIComponent(flow.srcIp) +
          '&dst=' + encodeURIComponent(flow.dstIp);
        if (flow.srcPort && flow.srcPort !== '—' && flow.dstPort && flow.dstPort !== '—') {
          q += '&sport=' + encodeURIComponent(flow.srcPort) + '&dport=' + encodeURIComponent(flow.dstPort);
        }
        return Hive.api.request('/firewall/conntrack' + q, { method: 'DELETE' }).then(function () {
          return Hive.services.flows.list().then(function () { return flow; });
        });
      },

      flushAll: function () {
        return Hive.api.request('/firewall/conntrack', { method: 'DELETE' }).then(function () {
          return Hive.services.flows.list();
        });
      }
    },

    adblock: {
      getOverview: function () {
        return safeGet('/dns/querylog?limit=100').then(function (qlRes) {
          if (qlRes && Array.isArray(qlRes.data)) {
            Hive.store.updateRuntimeState(function (st) {
              st.adblock.queryLog = qlRes.data.map(function (q, idx) {
                var reason = String(q.reason || '');
                var isBlk = reason.indexOf('Filtered') === 0 || reason.indexOf('Blocked') !== -1;
                var isAlw = reason.indexOf('NotFilteredWhiteList') === 0;
                var tStr = q.time ? String(q.time).slice(11, 19) : '—';
                var domName = String((q.question && q.question.name) || '—').replace(/\.$/, '');
                return {
                  id: 'ql-' + idx,
                  time: tStr,
                  clientIp: q.client || '—',
                  clientName: q.client_info && q.client_info.name ? q.client_info.name : (q.client || 'LAN Client'),
                  domain: domName,
                  type: (q.question && q.question.type) || 'A',
                  action: isBlk ? 'blocked' : isAlw ? 'allowlisted' : 'allowed',
                  source: reason || 'Upstream',
                  latencyMs: Number(Number(q.elapsedMs || 0).toFixed(1))
                };
              });
            }, 'querylog-refresh');
          }
          return clone(Hive.store.getState().adblock);
        });
      },

      refreshQueryLog: function () {
        return Promise.all([
          safeGet('/dns/querylog?limit=100'),
          safeGet('/dns/stats'),
          safeGet('/dns/status')
        ]).then(function (arr) {
          var qlRes = arr[0];
          var dnsMetrics = arr[1];
          var dnsStatRes = arr[2];
          Hive.store.updateRuntimeState(function (st) {
            if (qlRes && Array.isArray(qlRes.data)) {
              st.adblock.queryLog = qlRes.data.map(function (q, idx) {
                var reason = String(q.reason || '');
                var isBlk = reason.indexOf('Filtered') === 0 || reason.indexOf('Blocked') !== -1;
                var isAlw = reason.indexOf('NotFilteredWhiteList') === 0;
                var tStr = q.time ? String(q.time).slice(11, 19) : '—';
                var domName = String((q.question && q.question.name) || '—').replace(/\.$/, '');
                return {
                  id: 'ql-' + idx,
                  time: tStr,
                  clientIp: q.client || '—',
                  clientName: q.client_info && q.client_info.name ? q.client_info.name : (q.client || 'LAN Client'),
                  domain: domName,
                  type: (q.question && q.question.type) || 'A',
                  action: isBlk ? 'blocked' : isAlw ? 'allowlisted' : 'allowed',
                  source: reason || 'Upstream',
                  latencyMs: Number(Number(q.elapsedMs || 0).toFixed(1))
                };
              });
            }
            if (dnsMetrics) {
              var totalQ = Number(dnsMetrics.num_dns_queries || 0);
              var blkQ = Number(dnsMetrics.num_blocked_filtering || 0);
              var avgRaw = Number(dnsMetrics.avg_processing_time || 0);
              st.adblock.queriesToday = totalQ;
              st.adblock.blockedToday = blkQ;
              st.adblock.blockedPercent = totalQ > 0 ? Number(((blkQ / totalQ) * 100).toFixed(1)) : 0;
              st.adblock.avgLatencyMs = Number((avgRaw < 2 ? avgRaw * 1000 : avgRaw).toFixed(1));
            }
            if (dnsStatRes) {
              st.adblock.running = Boolean(dnsStatRes.running);
            }
          }, 'querylog-refresh');
          return clone(Hive.store.getState().adblock);
        });
      },

      toggleEnabled: function (enabled) {
        Hive.store.stageMutation(
          { module: 'AdBlock' },
          function (state) {
            state.adblock.enabled = Boolean(enabled);
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve({ enabled: Boolean(enabled) });
      },

      toggleForceDns: function (enabled) {
        Hive.store.stageMutation(
          { module: 'AdBlock' },
          function (state) {
            state.adblock.forceDns = Boolean(enabled);
            state.firewallConfig.transparentDns = Boolean(enabled);
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve({ forceDns: Boolean(enabled) });
      },

      toggleFeed: function (id, enabled) {
        Hive.store.stageMutation(
          { module: 'AdBlock' },
          function (state) {
            var f = state.adblock.feeds.find(function (x) { return x.id === id; });
            if (f) f.enabled = Boolean(enabled);
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve({ id: id, enabled: Boolean(enabled) });
      },

      addFeed: function (payload) {
        return Hive.services.adblock.saveFeed(payload);
      },

      saveFeed: function (payload) {
        var isEdit = Boolean(payload.id);
        var id = payload.id || nextId('feed');
        var cleanName = String(payload.name || '').trim();
        var cleanUrl = String(payload.url || '').trim();
        var curFeeds = Hive.store.getState().adblock.feeds || [];
        var dup = curFeeds.some(function (f) {
          return f.id !== id && f.url.toLowerCase() === cleanUrl.toLowerCase();
        });
        if (dup) {
          return Promise.resolve({ ok: false, reason: 'A filter list with this URL is already configured.' });
        }
        Hive.store.stageMutation({ module: 'AdBlock' }, function (state) {
          if (isEdit) {
            var idx = state.adblock.feeds.findIndex(function (x) { return x.id === id; });
            if (idx !== -1) {
              state.adblock.feeds[idx] = Object.assign({}, state.adblock.feeds[idx], {
                name: cleanName,
                url: cleanUrl
              });
            }
          } else {
            state.adblock.feeds.push({
              id: id,
              name: cleanName,
              category: 'Custom',
              url: cleanUrl,
              domains: 0,
              lastUpdated: 'Pending Apply',
              builtin: false,
              enabled: true
            });
          }
        });
        return Promise.resolve({ ok: true, id: id });
      },

      deleteFeed: function (id) {
        Hive.store.stageMutation({ module: 'AdBlock' }, function (state) {
          state.adblock.feeds = state.adblock.feeds.filter(function (f) { return f.id !== id; });
        });
        return Promise.resolve({ ok: true, id: id });
      },

      refreshFeeds: function () {
        return Hive.api.request('/dns/filters/refresh', { method: 'POST', body: { whitelist: false } }).then(function (res) {
          return bootstrapAll().then(function () { return res; });
        });
      },

      addRule: function (listType, payload) {
        var domain = String(payload.domain || '').trim().toLowerCase().replace(/\.$/, '');
        var isAllow = listType === 'allow';
        var st = Hive.store.getState().adblock;
        var arr = isAllow ? st.allowlist : st.customBlocked;
        if (arr.some(function (r) { return r.domain.toLowerCase() === domain; })) {
          return Promise.resolve({ ok: false, reason: '"' + domain + '" already exists in this list.' });
        }
        var id = (isAllow ? 'alw-' : 'blk-') + domain.replace(/[^a-zA-Z0-9.-]/g, '_');
        Hive.store.stageMutation({ module: 'AdBlock' }, function (state) {
          var target = isAllow ? state.adblock.allowlist : state.adblock.customBlocked;
          target.unshift({
            id: id,
            domain: domain,
            reason: payload.reason || (isAllow ? 'Exception rule' : 'Custom block'),
            addedAt: 'Staged'
          });
        });
        return Promise.resolve({ ok: true, id: id, domain: domain });
      },

      deleteRule: function (listType, id) {
        var isAllow = listType === 'allow';
        Hive.store.stageMutation({ module: 'AdBlock' }, function (state) {
          if (isAllow) {
            state.adblock.allowlist = state.adblock.allowlist.filter(function (x) { return x.id !== id; });
          } else {
            state.adblock.customBlocked = state.adblock.customBlocked.filter(function (x) { return x.id !== id; });
          }
        });
        return Promise.resolve({ ok: true, id: id });
      },

      toggleBlockedService: function (serviceId, blocked) {
        Hive.store.stageMutation(
          { module: 'AdBlock' },
          function (state) {
            var cur = (state.adblock.blockedServices || []).slice();
            var idx = cur.indexOf(serviceId);
            if (blocked && idx === -1) cur.push(serviceId);
            if (!blocked && idx !== -1) cur.splice(idx, 1);
            cur.sort();
            state.adblock.blockedServices = cur;
          },
          { reason: 'inline-toggle' }
        );
        return Promise.resolve(true);
      }
    },

    settings: {
      getOverview: function () {
        var st = Hive.store.getState();
        return Promise.resolve({
          hostname: st.system.hostname,
          fqdn: st.system.fqdn,
          general: clone(st.general),
          daemons: clone(st.daemons),
          cron: clone(st.cron),
          sysctl: clone(st.sysctl)
        });
      },

      updateGeneral: function (patch) {
        var host = String(patch.hostname || 'netbee').trim();
        Hive.store.stageMutation({ module: 'Settings' }, function (state) {
          state.system.hostname = host;
          state.system.fqdn = host + '.lan';
          state.general.timezone = patch.timezone || 'UTC';
          state.general.ntpServers = Array.isArray(patch.ntpServers) ? patch.ntpServers.slice() : ['0.pool.ntp.org'];
          state.general.ntpServeLan = Boolean(patch.ntpServeLan);
        });
        return Promise.resolve({ hostname: host });
      },

      serviceAction: function (name, action) {
        return Hive.api
          .request('/system/services/' + encodeURIComponent(name) + '/' + encodeURIComponent(action), { method: 'POST' })
          .then(function (res) {
            return Hive.services.system.getSnapshot().then(function () { return res; });
          });
      },

      addCronJob: function (job) {
        return Hive.api.request('/services/cron', { method: 'POST', body: job }).then(function (res) {
          return bootstrapAll().then(function () { return res; });
        });
      },

      updateCronJob: function (id, job) {
        return Hive.api.request('/services/cron/' + encodeURIComponent(id), { method: 'PUT', body: job }).then(function (res) {
          return bootstrapAll().then(function () { return res; });
        });
      },

      deleteCronJob: function (id) {
        return Hive.api.request('/services/cron/' + encodeURIComponent(id), { method: 'DELETE' }).then(function (res) {
          return bootstrapAll().then(function () { return res; });
        });
      },

      saveSysctl: function (cfg) {
        return Hive.api.request('/system/sysctl', { method: 'PUT', body: cfg }).then(function (res) {
          return bootstrapAll().then(function () { return res; });
        });
      },

      reboot: function () {
        return Hive.api.request('/system/reboot', { method: 'POST' });
      },

      poweroff: function () {
        return Hive.api.request('/system/poweroff', { method: 'POST' });
      }
    },

    access: {
      getOverview: function () {
        return Promise.all([safeGet('/system/users'), safeGet('/services/ssh'), safeGet('/system/tls')]).then(function (arr) {
          Hive.store.updateRuntimeState(function (st) {
            if (arr[0] && Array.isArray(arr[0].users)) st.access.osUsers = arr[0].users;
            if (arr[1]) {
              var uKeys = arr[1].users_keys || { root: [], netbee: [] };
              var flat = [];
              ['root', 'netbee'].forEach(function (owner) {
                (uKeys[owner] || []).forEach(function (rawKey, idx) {
                  var parts = String(rawKey).trim().split(/\s+/);
                  flat.push({
                    id: owner + '-' + idx,
                    index: idx,
                    owner: owner,
                    type: parts[0] || 'ssh-ed25519',
                    keyBody: parts[1] || '',
                    label: parts.slice(2).join(' ') || (owner + ' key #' + (idx + 1)),
                    publicKey: rawKey
                  });
                });
              });
              st.access.ssh.usersKeys = uKeys;
              st.access.ssh.sshKeys = flat;
            }
            if (arr[2]) {
              st.access.tls = {
                present: Boolean(arr[2].present),
                subject: arr[2].subject || '—',
                issuer: arr[2].issuer || '—',
                notBefore: arr[2].not_before || '—',
                notAfter: arr[2].not_after || '—',
                dnsNames: Array.isArray(arr[2].dns_names) ? arr[2].dns_names : [],
                ipAddresses: Array.isArray(arr[2].ip_addresses) ? arr[2].ip_addresses : [],
                autoSelfSigned: Boolean(arr[2].auto_self_signed)
              };
            }
          }, 'access-refresh');
          return clone(Hive.store.getState().access);
        });
      },

      stageSshPolicy: function (patch) {
        Hive.store.stageMutation({ module: 'Access' }, function (st) {
          st.access.ssh.passwordAuth = Boolean(patch.passwordAuth);
          st.access.ssh.allowRootLogin = Boolean(patch.allowRootLogin);
          st.access.ssh.idleTimeout = Number(patch.idleTimeout || 0);
        });
        return Promise.resolve(true);
      },

      changeWebPassword: function (payload) {
        return Hive.api.request('/auth/password', {
          method: 'POST',
          body: {
            current_password: payload.currentPassword,
            new_password: payload.newPassword,
            sync_root_ssh: Boolean(payload.syncRootSsh),
            sync_netbee_ssh: Boolean(payload.syncNetbeeSsh)
          }
        });
      },

      setOsUserPassword: function (username, password) {
        return Hive.api.request('/system/users/' + encodeURIComponent(username) + '/password', {
          method: 'PUT',
          body: { password: password }
        });
      },

      addSshKey: function (user, publicKey) {
        return Hive.api
          .request('/services/ssh/keys', {
            method: 'POST',
            body: { user: user, public_key: String(publicKey || '').trim() }
          })
          .then(function (res) {
            return Hive.services.access.getOverview().then(function () { return res; });
          });
      },

      deleteSshKey: function (user, index) {
        return Hive.api
          .request('/services/ssh/keys/' + encodeURIComponent(index) + '?user=' + encodeURIComponent(user), {
            method: 'DELETE'
          })
          .then(function (res) {
            return Hive.services.access.getOverview().then(function () { return res; });
          });
      },

      saveTls: function (payload) {
        return Hive.api.request('/system/tls', {
          method: 'PUT',
          body: {
            cert_pem: payload.certPem,
            key_pem: payload.keyPem,
            reload: Boolean(payload.reload)
          }
        });
      },

      deleteTls: function () {
        return Hive.api.request('/system/tls', { method: 'DELETE' }).then(function (res) {
          return Hive.services.access.getOverview().then(function () { return res; });
        });
      }
    },

    firmware: {
      getOverview: function () {
        return Hive.services.system.getSnapshot().then(function (snap) {
          return {
            system: snap.system
          };
        });
      },

      downloadBackup: function () {
        return Hive.api.request('/system/backup', {
          method: 'GET',
          responseType: 'blob'
        });
      },

      restoreBackup: function (arrayBuffer) {
        return Hive.api
          .request('/system/restore', {
            method: 'POST',
            rawBody: true,
            contentType: 'application/gzip',
            body: arrayBuffer
          })
          .then(function (res) {
            return bootstrapAll().then(function () { return res; });
          });
      }
    },

    logs: {
      listService: function (lines, filter) {
        var q = '?lines=' + encodeURIComponent(lines || 300);
        if (filter) q += '&filter=' + encodeURIComponent(filter);
        return safeGet('/logs/system' + q).then(function (res) {
          var rawLines = (res && Array.isArray(res.lines)) ? res.lines : [];
          var mapped = rawLines.map(mapSyslogLine).reverse();
          Hive.store.updateRuntimeState(function (st) {
            st.auditLogs = mapped;
          }, 'syslog-refresh');
          return mapped;
        });
      },

      rotate: function () {
        return Hive.api.request('/logs/rotate', { method: 'POST' });
      },

      clear: function () {
        return Hive.api.request('/logs/clear', { method: 'POST' });
      },

      toServiceCsv: function (rows) {
        function escCsv(v) {
          var s = String(v === undefined || v === null ? '' : v);
          if (/^[=+\-@\t\r]/.test(s)) {
            s = "'" + s;
          }
          return '"' + s.replace(/"/g, '""') + '"';
        }
        var header = ['Timestamp', 'Severity', 'Process', 'Host', 'PID', 'Message'].join(',');
        var lines = (rows || []).map(function (r) {
          return [r.timestamp, r.severity, r.module, r.sourceIp, r.actor, r.summary].map(escCsv).join(',');
        });
        return [header].concat(lines).join('\n');
      },

      listKernel: function (lines) {
        var q = '?lines=' + encodeURIComponent(lines || 400);
        return safeGet('/logs/kernel' + q).then(function (res) {
          var rawLines = (res && Array.isArray(res.lines)) ? res.lines : [];
          var mapped = rawLines.map(mapDmesgLine).reverse();
          Hive.store.updateRuntimeState(function (st) {
            st.kernelLogs = mapped;
          }, 'dmesg-refresh');
          return mapped;
        });
      },

      toDmesgText: function (rows) {
        return (rows || [])
          .slice()
          .reverse()
          .map(function (r) {
            return r.raw || ('[' + r.bootTime + '] ' + r.subsystem + ': ' + r.message);
          })
          .join('\n');
      }
    },

    staging: {
      list: function () {
        return Hive.store.getStagedChanges();
      },
      count: function () {
        return Hive.store.getPendingCount();
      },
      apply: function () {
        return applyStagedToBackend();
      },
      discard: function () {
        return Promise.resolve(Hive.store.discardStaged());
      }
    }
  };
})(window);
