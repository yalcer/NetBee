/* ==========================================================================
   Hive — Live Router State Store & Structural Staged-Diff Engine
   Tracks committedState (live netbeed state) vs workingState (staged UI edits)
   and computes exact diffs for the Uncommitted Changes dock.
   ========================================================================== */
(function (window) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});
  var ALIAS_STORAGE_KEY = 'hive.aliases.v2';

  function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function pick(obj, keys) {
    var out = {};
    for (var i = 0; i < keys.length; i++) {
      out[keys[i]] = obj ? obj[keys[i]] : undefined;
    }
    return out;
  }

  function equalKeys(a, b, keys) {
    return JSON.stringify(pick(a, keys)) === JSON.stringify(pick(b, keys));
  }

  function loadStoredAliases() {
    try {
      var raw = window.localStorage.getItem(ALIAS_STORAGE_KEY);
      if (raw) {
        var parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') return parsed;
      }
    } catch (err) {
      // Ignore
    }
    return {
      RFC1918_PRIVATE: {
        type: 'network',
        description: 'Private IPv4 address spaces',
        members: ['192.168.10.0/24', '10.0.0.0/8', '172.16.0.0/12']
      },
      WEB_PORTS: {
        type: 'port',
        description: 'HTTP & HTTPS ports',
        members: ['80', '443']
      }
    };
  }

  function saveStoredAliases(aliases) {
    try {
      window.localStorage.setItem(ALIAS_STORAGE_KEY, JSON.stringify(aliases || {}));
    } catch (err) {
      // Ignore
    }
  }

  function computeDiffs(base, next, timestampCache) {
    var diffs = [];
    var now = Hive.format ? Hive.format.clockNow() : '';

    function push(key, module, action, summary, detail) {
      if (!timestampCache[key]) timestampCache[key] = now;
      diffs.push({
        id: key,
        module: module,
        action: action,
        summary: summary,
        detail: detail || '',
        timestamp: timestampCache[key]
      });
    }

    function diffCollection(opts) {
      var baseMap = {};
      var nextMap = {};
      (opts.baseList || []).forEach(function (item) { baseMap[item.id] = item; });
      (opts.nextList || []).forEach(function (item) { nextMap[item.id] = item; });

      (opts.nextList || []).forEach(function (item) {
        var prev = baseMap[item.id];
        if (!prev) {
          push(opts.prefix + ':add:' + item.id, opts.module, 'ADD', opts.onAddSummary(item), opts.onDetail(item));
        } else if (!equalKeys(prev, item, opts.keys)) {
          var nonEnableKeys = opts.keys.filter(function (k) { return k !== 'enabled'; });
          var onlyToggle = opts.keys.indexOf('enabled') !== -1 && prev.enabled !== item.enabled && equalKeys(prev, item, nonEnableKeys);
          var summary = onlyToggle && opts.onToggleSummary
            ? opts.onToggleSummary(item)
            : opts.onEditSummary(item, prev);
          push(opts.prefix + ':edit:' + item.id, opts.module, 'EDIT', summary, opts.onDetail(item));
        }
      });

      (opts.baseList || []).forEach(function (item) {
        if (!nextMap[item.id]) {
          push(opts.prefix + ':del:' + item.id, opts.module, 'DELETE', opts.onDelSummary(item), opts.onDetail(item));
        }
      });

      if (opts.checkOrder) {
        var baseShared = (opts.baseList || []).filter(function (x) { return Boolean(nextMap[x.id]); }).map(function (x) { return x.id; });
        var nextShared = (opts.nextList || []).filter(function (x) { return Boolean(baseMap[x.id]); }).map(function (x) { return x.id; });
        if (JSON.stringify(baseShared) !== JSON.stringify(nextShared)) {
          push(opts.prefix + ':reorder', opts.module, 'REORDER', opts.orderSummary || 'Reordered evaluation priority', opts.orderDetail || 'Rule order differs from committed state');
        }
      }
    }

    // 1. LAN & WAN & IPv6 Configuration
    if (!equalKeys(base.lanConfig, next.lanConfig, ['interface', 'ip', 'netmask'])) {
      push(
        'net:lan',
        'Interfaces',
        'EDIT',
        'Updated LAN (' + next.lanConfig.interface + ') IPv4 settings',
        next.lanConfig.ip + ' / ' + next.lanConfig.netmask
      );
    }

    if (!equalKeys(base.wanConfig, next.wanConfig, ['mode', 'interface', 'vlanId', 'pppoeUser', 'pppoePassword', 'macClone', 'mtu', 'ipv6Pd'])) {
      push(
        'net:wan',
        'Interfaces',
        'EDIT',
        'Updated WAN (' + next.wanConfig.interface + ') to ' + next.wanConfig.mode.toUpperCase(),
        'MTU ' + next.wanConfig.mtu + (next.wanConfig.mode === 'ont_vlan' ? ' · VLAN ' + next.wanConfig.vlanId : '')
      );
    }

    if (!equalKeys(base.ipv6Config, next.ipv6Config, ['radvdEnabled', 'ipv6Pd'])) {
      push(
        'net:ipv6',
        'Interfaces',
        'EDIT',
        'Updated IPv6 SLAAC / Prefix Delegation',
        'SLAAC (radvd): ' + (next.ipv6Config.radvdEnabled ? 'On' : 'Off') + ' · DHCPv6-PD: ' + (next.ipv6Config.ipv6Pd ? 'On' : 'Off')
      );
    }

    // 2. Firewall Global Toggles & Rules
    if (!equalKeys(base.firewallConfig, next.firewallConfig, ['transparentDns', 'exposeWireguard', 'wireguardPort', 'flowOffload'])) {
      push(
        'fw:toggles',
        'Firewall',
        'EDIT',
        'Updated global firewall offload & service toggles',
        'Flow Offload: ' + (next.firewallConfig.flowOffload ? 'On' : 'Off') + ' · Transparent DNS: ' + (next.firewallConfig.transparentDns ? 'On' : 'Off') + ' · WG WAN: ' + (next.firewallConfig.exposeWireguard ? 'Open' : 'Closed')
      );
    }

    diffCollection({
      prefix: 'fw',
      module: 'Firewall',
      baseList: base.firewallRules,
      nextList: next.firewallRules,
      keys: ['chain', 'inIface', 'outIface', 'action', 'protocol', 'source', 'destination', 'port', 'log', 'enabled', 'description'],
      checkOrder: true,
      orderSummary: 'Reordered firewall rule priority',
      orderDetail: 'Updated top-to-bottom nftables rule evaluation sequence',
      onAddSummary: function (r) { return 'Added ' + r.action.toUpperCase() + ' rule on ' + (r.chain || 'input').toUpperCase(); },
      onToggleSummary: function (r) { return (r.enabled ? 'Enabled' : 'Disabled') + ' firewall rule ' + r.id; },
      onEditSummary: function (r) { return 'Modified firewall rule ' + r.id; },
      onDelSummary: function (r) { return 'Deleted firewall rule ' + r.id; },
      onDetail: function (r) { return r.protocol + ' ' + r.source + ' -> ' + r.destination + ':' + (r.port || 'any'); }
    });

    // 3. Static Routes
    diffCollection({
      prefix: 'rt',
      module: 'Routing',
      baseList: base.staticRoutes,
      nextList: next.staticRoutes,
      keys: ['destination', 'gateway', 'iface', 'metric', 'enabled', 'description'],
      onAddSummary: function (r) { return 'Added static route ' + r.destination; },
      onToggleSummary: function (r) { return (r.enabled ? 'Enabled' : 'Disabled') + ' static route ' + r.destination; },
      onEditSummary: function (r) { return 'Updated static route ' + r.destination; },
      onDelSummary: function (r) { return 'Removed static route ' + r.destination; },
      onDetail: function (r) { return 'via ' + (r.gateway || 'direct') + ' dev ' + (r.iface || 'auto') + ' metric ' + (r.metric || 0); }
    });

    // 4. DHCP Scope & Static Reservations
    diffCollection({
      prefix: 'dhcp-sc',
      module: 'DHCP',
      baseList: base.dhcp.scopes,
      nextList: next.dhcp.scopes,
      keys: ['rangeStart', 'rangeEnd', 'leaseHours', 'enabled'],
      onAddSummary: function (s) { return 'Added DHCP scope ' + s.iface; },
      onToggleSummary: function (s) { return (s.enabled ? 'Enabled' : 'Disabled') + ' DHCP server on ' + s.iface; },
      onEditSummary: function (s) { return 'Updated DHCP pool on ' + s.iface; },
      onDelSummary: function (s) { return 'Removed DHCP scope ' + s.iface; },
      onDetail: function (s) { return s.rangeStart + ' – ' + s.rangeEnd + ' · ' + s.leaseHours + 'h'; }
    });

    diffCollection({
      prefix: 'dhcp-res',
      module: 'DHCP',
      baseList: base.dhcp.reservations,
      nextList: next.dhcp.reservations,
      keys: ['hostname', 'ip', 'mac'],
      onAddSummary: function (r) { return 'Added static DHCP lease ' + r.hostname; },
      onEditSummary: function (r) { return 'Updated static DHCP lease ' + r.hostname; },
      onDelSummary: function (r) { return 'Deleted static DHCP lease ' + r.hostname; },
      onDetail: function (r) { return r.mac + ' -> ' + r.ip; }
    });

    // 5. DNS Resolver Settings & Rewrites
    if (!equalKeys(base.dns, next.dns, ['resolvers', 'dnssecEnabled', 'cacheSize'])) {
      push(
        'dns:settings',
        'DNS',
        'EDIT',
        'Updated AdGuardHome upstream DNS settings',
        'Upstreams: ' + next.dns.resolvers.join(', ')
      );
    }

    diffCollection({
      prefix: 'dns-ov',
      module: 'DNS',
      baseList: base.dns.overrides,
      nextList: next.dns.overrides,
      keys: ['hostname', 'value'],
      onAddSummary: function (o) { return 'Added DNS rewrite ' + o.hostname; },
      onEditSummary: function (o) { return 'Updated DNS rewrite ' + o.hostname; },
      onDelSummary: function (o) { return 'Removed DNS rewrite ' + o.hostname; },
      onDetail: function (o) { return o.hostname + ' -> ' + o.value; }
    });

    // 6. NAT Port Forwards
    diffCollection({
      prefix: 'nat-pf',
      module: 'NAT',
      baseList: base.nat.portForwards,
      nextList: next.nat.portForwards,
      keys: ['protocol', 'extPort', 'targetIp', 'targetPort', 'sourceCidr', 'enabled', 'description'],
      onAddSummary: function (r) { return 'Added Port Forward ' + r.protocol + '/' + r.extPort; },
      onToggleSummary: function (r) { return (r.enabled ? 'Enabled' : 'Disabled') + ' Port Forward ' + r.protocol + '/' + r.extPort; },
      onEditSummary: function (r) { return 'Updated Port Forward ' + r.protocol + '/' + r.extPort; },
      onDelSummary: function (r) { return 'Deleted Port Forward ' + r.protocol + '/' + r.extPort; },
      onDetail: function (r) { return 'WAN:' + r.extPort + ' -> ' + r.targetIp + ':' + (r.targetPort || r.extPort) + (r.sourceCidr ? ' (from ' + r.sourceCidr + ')' : ''); }
    });

    // 7. WireGuard Server & Peer Edits
    if (!equalKeys(base.vpn.wireguard, next.vpn.wireguard, ['enabled', 'tunnelSubnet', 'listenPort', 'endpointHost', 'dns'])) {
      push(
        'wg:server',
        'VPN',
        'EDIT',
        'Updated WireGuard server (wg0) settings',
        (next.vpn.wireguard.enabled ? 'Enabled' : 'Disabled') + ' · ' + next.vpn.wireguard.tunnelSubnet + ' · UDP/' + next.vpn.wireguard.listenPort
      );
    }

    diffCollection({
      prefix: 'wg-peer',
      module: 'VPN',
      baseList: base.vpn.wireguard.peers,
      nextList: next.vpn.wireguard.peers,
      keys: ['name', 'allowedIps', 'enabled'],
      onAddSummary: function (p) { return 'Added WireGuard peer ' + p.name; },
      onToggleSummary: function (p) { return (p.enabled ? 'Enabled' : 'Disabled') + ' WireGuard peer ' + p.name; },
      onEditSummary: function (p) { return 'Updated WireGuard peer ' + p.name; },
      onDelSummary: function (p) { return 'Removed WireGuard peer ' + p.name; },
      onDetail: function (p) { return 'AllowedIPs: ' + p.allowedIps; }
    });

    // 8. SQM CAKE QoS
    if (base.sqm && next.sqm) {
      var sqmKeys = ['enabled', 'iface', 'downloadKbps', 'uploadKbps', 'overheadBytes'];
      if (!equalKeys(base.sqm, next.sqm, sqmKeys)) {
        var nonEnableSqm = sqmKeys.filter(function (k) { return k !== 'enabled'; });
        var onlySqmToggle = base.sqm.enabled !== next.sqm.enabled && equalKeys(base.sqm, next.sqm, nonEnableSqm);
        push(
          'sqm:config',
          'SQM',
          'EDIT',
          onlySqmToggle
            ? (next.sqm.enabled ? 'Enabled' : 'Disabled') + ' SQM CAKE QoS on ' + next.sqm.iface
            : 'Updated SQM CAKE QoS on ' + next.sqm.iface,
          '↓' + next.sqm.downloadKbps + ' / ↑' + next.sqm.uploadKbps + ' kbit/s · overhead +' + next.sqm.overheadBytes + 'B'
        );
      }
    }

    // 9. Ad/Tracker Block
    if (base.adblock && next.adblock) {
      if (!equalKeys(base.adblock, next.adblock, ['enabled', 'forceDns', 'blockedServices'])) {
        push(
          'adblock:policy',
          'AdBlock',
          'EDIT',
          'Updated Ad/Tracker Block protection & service blocks',
          'Protection: ' + (next.adblock.enabled ? 'On' : 'Off') + ' · Force Router DNS: ' + (next.adblock.forceDns ? 'On' : 'Off') + ' · Blocked Apps: ' + (next.adblock.blockedServices || []).length
        );
      }

      diffCollection({
        prefix: 'ab-feed',
        module: 'AdBlock',
        baseList: base.adblock.feeds,
        nextList: next.adblock.feeds,
        keys: ['name', 'url', 'enabled'],
        onAddSummary: function (f) { return 'Added blocklist feed ' + f.name; },
        onToggleSummary: function (f) { return (f.enabled ? 'Enabled' : 'Disabled') + ' blocklist ' + f.name; },
        onEditSummary: function (f) { return 'Updated blocklist ' + f.name; },
        onDelSummary: function (f) { return 'Removed blocklist ' + f.name; },
        onDetail: function (f) { return f.url; }
      });

      diffCollection({
        prefix: 'ab-blk',
        module: 'AdBlock',
        baseList: base.adblock.customBlocked,
        nextList: next.adblock.customBlocked,
        keys: ['domain'],
        onAddSummary: function (r) { return 'Blocked domain ' + r.domain; },
        onEditSummary: function (r) { return 'Updated blocked domain ' + r.domain; },
        onDelSummary: function (r) { return 'Removed custom block ' + r.domain; },
        onDetail: function () { return 'AdGuard custom rule'; }
      });

      diffCollection({
        prefix: 'ab-alw',
        module: 'AdBlock',
        baseList: base.adblock.allowlist,
        nextList: next.adblock.allowlist,
        keys: ['domain'],
        onAddSummary: function (r) { return 'Allowlisted domain ' + r.domain; },
        onEditSummary: function (r) { return 'Updated allowlist ' + r.domain; },
        onDelSummary: function (r) { return 'Removed allowlist entry ' + r.domain; },
        onDetail: function () { return 'AdGuard exception rule'; }
      });
    }

    // 10. General Hostname, Timezone & Chrony NTP
    if (base.general && next.general) {
      var hostChanged = base.system && next.system && base.system.hostname !== next.system.hostname;
      var genChanged = !equalKeys(base.general, next.general, ['timezone', 'ntpServers', 'ntpServeLan']);
      if (hostChanged || genChanged) {
        push(
          'sys:general',
          'Settings',
          'EDIT',
          'Updated hostname, timezone, or Chrony NTP settings',
          (next.system ? next.system.hostname : 'netbee') + ' · TZ ' + next.general.timezone
        );
      }
    }

    // 11. SSH Dropbear Policy
    if (base.access && next.access && base.access.ssh && next.access.ssh) {
      if (!equalKeys(base.access.ssh, next.access.ssh, ['passwordAuth', 'allowRootLogin', 'idleTimeout'])) {
        push(
          'access:ssh',
          'Access',
          'EDIT',
          'Updated Dropbear SSH security policy',
          'Password Auth: ' + (next.access.ssh.passwordAuth ? 'On' : 'Off') + ' · Root Login: ' + (next.access.ssh.allowRootLogin ? 'Allowed' : 'Disabled (-w)') + ' · Idle: ' + next.access.ssh.idleTimeout + 's'
        );
      }
    }

    var activeKeys = {};
    diffs.forEach(function (d) { activeKeys[d.id] = true; });
    Object.keys(timestampCache).forEach(function (k) {
      if (!activeKeys[k]) delete timestampCache[k];
    });

    return diffs;
  }

  var committedState = Hive.mockDb.createSeedState();
  committedState.aliases = loadStoredAliases();
  var workingState = deepClone(committedState);
  var diffTimestamps = {};
  var stagedChanges = [];

  function recomputeDiffs() {
    stagedChanges = computeDiffs(committedState, workingState, diffTimestamps);
  }

  function emit(reason) {
    var event = new CustomEvent('hive:statechange', {
      detail: {
        reason: reason || 'update',
        pendingCount: stagedChanges.length
      }
    });
    window.dispatchEvent(event);
  }

  function getState() {
    return workingState;
  }

  function getCommittedState() {
    return committedState;
  }

  function getStagedChanges() {
    return deepClone(stagedChanges);
  }

  function getPendingCount() {
    return stagedChanges.length;
  }

  function stageMutation(meta, mutator, options) {
    var next = deepClone(workingState);
    mutator(next);
    workingState = next;
    if (meta && meta.persistAliases) {
      committedState.aliases = deepClone(workingState.aliases);
      saveStoredAliases(workingState.aliases);
    }
    recomputeDiffs();
    emit((options && options.reason) || 'stage');
    return workingState;
  }

  /**
   * Hydrate committedState from live netbeed API responses.
   * If workingState has no uncommitted changes, replace workingState cleanly too;
   * if the user has uncommitted edits, update only runtime/non-dirty slices!
   */
  function hydrateFromBackend(updater, reason) {
    var wasClean = stagedChanges.length === 0;
    updater(committedState);
    committedState.aliases = loadStoredAliases();
    if (wasClean) {
      workingState = deepClone(committedState);
      diffTimestamps = {};
      stagedChanges = [];
    } else {
      // Always sync live telemetry, daemons, logs, leases, and runtime counters
      workingState.system = Object.assign({}, committedState.system, {
        hostname: workingState.system.hostname
      });
      workingState.daemons = deepClone(committedState.daemons);
      workingState.flows = deepClone(committedState.flows);
      workingState.neighbors = deepClone(committedState.neighbors);
      workingState.connectedRoutes = deepClone(committedState.connectedRoutes);
      workingState.cron = deepClone(committedState.cron);
      workingState.sysctl = deepClone(committedState.sysctl);
      workingState.dhcp.leases = deepClone(committedState.dhcp.leases);
      workingState.adblock.queryLog = deepClone(committedState.adblock.queryLog);
      workingState.adblock.queriesToday = committedState.adblock.queriesToday;
      workingState.adblock.blockedToday = committedState.adblock.blockedToday;
      workingState.adblock.blockedPercent = committedState.adblock.blockedPercent;
      workingState.adblock.avgLatencyMs = committedState.adblock.avgLatencyMs;
      workingState.access.osUsers = deepClone(committedState.access.osUsers);
      workingState.access.tls = deepClone(committedState.access.tls);
      workingState.access.ssh.sshKeys = deepClone(committedState.access.ssh.sshKeys);
      workingState.access.ssh.usersKeys = deepClone(committedState.access.ssh.usersKeys);
      recomputeDiffs();
    }
    emit(reason || 'hydrate');
  }

  function commitWorkingAsClean() {
    committedState = deepClone(workingState);
    diffTimestamps = {};
    stagedChanges = [];
    emit('apply');
  }

  function updateTelemetry(mutator) {
    mutator(workingState.system, workingState);
    mutator(committedState.system, committedState);
    emit('telemetry');
  }

  function updateRuntimeState(mutator, reason) {
    mutator(workingState);
    mutator(committedState);
    recomputeDiffs();
    emit(reason || 'runtime');
  }

  function recordAudit(entry) {
    var d = new Date();
    var ts = d.toISOString().replace('T', ' ').slice(0, 19);
    var rec = {
      id: 'evt-' + Date.now(),
      timestamp: ts,
      severity: entry.severity || 'info',
      actor: (Hive.auth && Hive.auth.getSession().username) || 'admin',
      sourceIp: window.location.hostname || '192.168.10.1',
      module: entry.module || 'System',
      summary: entry.summary || '',
      details: entry.details || {}
    };
    [workingState, committedState].forEach(function (st) {
      st.system.events.unshift({
        id: rec.id,
        severity: rec.severity === 'error' ? 'danger' : rec.severity,
        source: String(rec.module || 'system').toLowerCase(),
        message: rec.summary,
        time: Hive.format ? Hive.format.clockNow() : ''
      });
      if (st.system.events.length > 15) st.system.events.length = 15;
    });
    emit('audit');
    return rec;
  }

  function discardStaged() {
    var count = stagedChanges.length;
    workingState = deepClone(committedState);
    diffTimestamps = {};
    stagedChanges = [];
    emit('discard');
    return count;
  }

  Hive.store = {
    getState: getState,
    getCommittedState: getCommittedState,
    getStagedChanges: getStagedChanges,
    getPendingCount: getPendingCount,
    stageMutation: stageMutation,
    hydrateFromBackend: hydrateFromBackend,
    commitWorkingAsClean: commitWorkingAsClean,
    updateTelemetry: updateTelemetry,
    updateRuntimeState: updateRuntimeState,
    recordAudit: recordAudit,
    discardStaged: discardStaged
  };
})(window);
