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
    if (!equalKeys(base.lanConfig, next.lanConfig, ['interface', 'ip', 'netmask', 'mtu', 'pinMac'])) {
      push(
        'net:lan',
        'Interfaces',
        'EDIT',
        'Updated LAN (' + next.lanConfig.interface + ') settings',
        next.lanConfig.ip + ' / ' + next.lanConfig.netmask + ' · MTU ' + (next.lanConfig.mtu || 1500)
      );
    }

    if (!equalKeys(base.wanConfig, next.wanConfig, [
      'mode', 'interface', 'vlanEnabled', 'vlanId',
      'staticIp', 'staticNetmask', 'staticGateway',
      'pppoeUser', 'pppoePassword', 'peerDns', 'dnsServers',
      'macClone', 'pinMac', 'mtu', 'ipv6Pd'
    ])) {
      var wanVlanActive = Boolean(next.wanConfig.vlanEnabled || next.wanConfig.mode === 'ont_vlan');
      push(
        'net:wan',
        'Interfaces',
        'EDIT',
        'Updated WAN (' + next.wanConfig.interface + ') to ' + next.wanConfig.mode.toUpperCase(),
        'MTU ' + next.wanConfig.mtu + (wanVlanActive ? ' · VLAN ' + next.wanConfig.vlanId : '')
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

  function createInitialState() {
    if (Hive.mockDb && typeof Hive.mockDb.createSeedState === 'function') {
      return Hive.mockDb.createSeedState();
    }
    return {
      schemaVersion: 2,
      system: {
        hostname: 'netbee',
        fqdn: 'netbee.lan',
        model: 'Raspberry Pi 5',
        firmware: 'NetBee OS',
        kernel: 'Linux aarch64',
        arch: 'aarch64',
        board: 'rpi5',
        uptimeSeconds: 0,
        cpuPercent: 0,
        cpuCores: 4,
        cpuFreqMhz: null,
        cpuGovernor: '',
        cpuTempC: null,
        fanRpm: null,
        coolingState: null,
        undervoltage: false,
        rootfsExpanded: true,
        memUsedGb: 0,
        memTotalGb: 4,
        memUsedMb: 0,
        memTotalMb: 4096,
        loadAvg: [0, 0, 0],
        statesActive: 0,
        statesMax: 131072,
        disks: [],
        gateways: [],
        throughput: {
          '15m': [{ label: 'Now', rx: 0, tx: 0 }],
          '1h': [{ label: 'Now', rx: 0, tx: 0 }],
          '24h': [{ label: 'Now', rx: 0, tx: 0 }]
        },
        events: []
      },
      lanConfig: {
        interface: 'eth0',
        ip: '192.168.10.1',
        netmask: '255.255.255.0',
        mtu: 1500,
        pinMac: ''
      },
      wanConfig: {
        mode: 'dhcp',
        interface: 'eth1',
        vlanEnabled: false,
        vlanId: 35,
        staticIp: '',
        staticNetmask: '255.255.255.0',
        staticGateway: '',
        pppoeUser: '',
        pppoePassword: '',
        peerDns: true,
        dnsServers: [],
        macClone: '',
        pinMac: '',
        mtu: 1500,
        ipv6Pd: false,
        pppdRunning: false
      },
      ipv6Config: {
        radvdEnabled: false,
        radvdRunning: false,
        ipv6Pd: false
      },
      interfaces: [
        {
          id: 'if-eth0',
          device: 'eth0',
          type: 'physical',
          role: 'lan',
          removable: false,
          label: 'LAN Interface',
          zone: 'lan',
          mode: 'Static',
          ipv4: '192.168.10.1/24',
          netmask: '255.255.255.0',
          ipv6: '—',
          gateway: '—',
          mac: '—',
          mtu: 1500,
          speed: '1000Mb/s',
          duplex: 'Full',
          linkDetected: true,
          adminUp: true,
          enabled: true,
          status: 'up',
          rxMbps: 0,
          txMbps: 0,
          rxTotalGb: 0,
          txTotalGb: 0
        },
        {
          id: 'if-eth1',
          device: 'eth1',
          type: 'physical',
          role: 'wan',
          removable: false,
          label: 'WAN Interface',
          zone: 'wan',
          mode: 'DHCP',
          ipv4: '—',
          ipv6: '—',
          gateway: '—',
          mac: '—',
          mtu: 1500,
          vlanId: 35,
          speed: '1000Mb/s',
          duplex: 'Full',
          linkDetected: false,
          adminUp: true,
          enabled: true,
          status: 'down',
          rxMbps: 0,
          txMbps: 0,
          rxTotalGb: 0,
          txTotalGb: 0
        }
      ],
      staticRoutes: [],
      connectedRoutes: [],
      neighbors: [],
      firewallConfig: {
        transparentDns: false,
        exposeWireguard: false,
        wireguardPort: 51820,
        flowOffload: true,
        offloadActive: false
      },
      firewallRules: [],
      aliases: {},
      zonePolicies: {
        wan: 'drop',
        lan: 'allow',
        vpn: 'allow'
      },
      nat: {
        wanIface: 'eth1',
        portForwards: []
      },
      dhcp: {
        scopes: [
          {
            id: 'scope-lan',
            iface: 'eth0',
            zone: 'lan',
            subnet: '192.168.10.0/24',
            gatewayIp: '192.168.10.1',
            subnetMask: '255.255.255.0',
            rangeStart: '192.168.10.100',
            rangeEnd: '192.168.10.200',
            poolSize: 101,
            leaseHours: 24,
            dnsServer: '192.168.10.1',
            enabled: true
          }
        ],
        leases: [],
        reservations: []
      },
      dns: {
        resolvers: ['1.1.1.1', '9.9.9.9'],
        dotEnabled: false,
        dnssecEnabled: false,
        cacheSize: 4194304,
        overrides: []
      },
      sqm: {
        enabled: false,
        iface: 'eth1',
        downloadKbps: 95000,
        uploadKbps: 19000,
        qdisc: 'cake',
        script: 'netbee-sqm (sch_cake + ifb0)',
        linkLayer: 'ethernet',
        overheadBytes: 44,
        statusOutput: ''
      },
      vpn: {
        wireguard: {
          enabled: false,
          active: false,
          iface: 'wg0',
          listenPort: 51820,
          tunnelSubnet: '10.66.66.1/24',
          publicKey: '',
          endpointHost: '',
          dns: '192.168.10.1',
          peers: []
        }
      },
      adblock: {
        enabled: true,
        filteringEnabled: true,
        filteringInterval: 24,
        running: true,
        forceDns: false,
        queriesToday: 0,
        blockedToday: 0,
        blockedPercent: 0,
        avgLatencyMs: 0,
        feeds: [],
        customBlocked: [],
        allowlist: [],
        passthroughRules: [],
        blockedServices: [],
        blockedServicesSchedule: { time_zone: 'Local' },
        availableServices: [],
        queryLog: []
      },
      general: {
        domain: 'lan',
        timezone: 'UTC',
        availableTimezones: ['UTC', 'Europe/Istanbul'],
        ntpServers: ['0.pool.ntp.org', '1.pool.ntp.org'],
        ntpServeLan: true,
        ntpTracking: '',
        ntpSources: ''
      },
      daemons: [],
      cron: {
        crondRunning: true,
        systemJobs: [],
        jobs: [],
        supportedActions: []
      },
      sysctl: {
        conntrackMax: 131072,
        conntrackCount: 0,
        tcpSyncookies: true,
        rpFilter: 1,
        icmpEchoIgnoreBroadcasts: true,
        ipv4Forwarding: true,
        ipv6Forwarding: true
      },
      access: {
        osUsers: [],
        ssh: {
          passwordAuth: true,
          allowRootLogin: true,
          idleTimeout: 600,
          usersKeys: { root: [], netbee: [] },
          sshKeys: []
        },
        tls: {
          present: true,
          subject: 'CN=netbee.lan,O=NetBee OS',
          issuer: 'CN=netbee.lan,O=NetBee OS',
          notBefore: '',
          notAfter: '',
          dnsNames: ['netbee', 'netbee.lan', 'localhost'],
          ipAddresses: ['192.168.10.1'],
          autoSelfSigned: true
        }
      },
      flows: [],
      auditLogs: [],
      kernelLogs: []
    };
  }

  var committedState = createInitialState();
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

  function sameJson(a, b) {
    return JSON.stringify(a) === JSON.stringify(b);
  }

  /**
   * Hydrate committedState from live netbeed API responses.
   * Performs per-slice dirty checks against the previous committedState so
   * untouched slices and runtime interface telemetry always sync cleanly without
   * fabricating phantom diffs or overwriting user-staged edits.
   */
  function hydrateFromBackend(updater, reason) {
    var wasClean = stagedChanges.length === 0;
    var prev = wasClean ? null : deepClone(committedState);
    updater(committedState);
    committedState.aliases = loadStoredAliases();

    if (wasClean) {
      workingState = deepClone(committedState);
      diffTimestamps = {};
      stagedChanges = [];
      emit(reason || 'hydrate');
      return;
    }

    var lanKeys = ['interface', 'ip', 'netmask', 'mtu', 'pinMac'];
    var wanKeys = [
      'mode', 'interface', 'vlanEnabled', 'vlanId',
      'staticIp', 'staticNetmask', 'staticGateway',
      'pppoeUser', 'pppoePassword', 'peerDns', 'dnsServers',
      'macClone', 'pinMac', 'mtu', 'ipv6Pd'
    ];
    var lanClean = equalKeys(prev.lanConfig, workingState.lanConfig, lanKeys);
    var wanClean = equalKeys(prev.wanConfig, workingState.wanConfig, wanKeys);

    if (lanClean) {
      workingState.lanConfig = deepClone(committedState.lanConfig);
    }
    if (wanClean) {
      workingState.wanConfig = deepClone(committedState.wanConfig);
    } else {
      workingState.wanConfig.pppdRunning = committedState.wanConfig.pppdRunning;
    }

    if (equalKeys(prev.ipv6Config, workingState.ipv6Config, ['radvdEnabled', 'ipv6Pd'])) {
      workingState.ipv6Config = deepClone(committedState.ipv6Config);
    } else {
      workingState.ipv6Config.radvdRunning = committedState.ipv6Config.radvdRunning;
    }

    // Always sync live interface telemetry & link states while preserving staged LAN/WAN previews
    workingState.interfaces = deepClone(committedState.interfaces);
    if (!lanClean) {
      var lanItem = workingState.interfaces.find(function (i) { return i.device === workingState.lanConfig.interface; });
      if (lanItem) {
        lanItem.zone = 'lan';
        lanItem.mtu = workingState.lanConfig.mtu || lanItem.mtu;
      }
    }
    if (!wanClean) {
      var wanItem = workingState.interfaces.find(function (i) { return i.device === workingState.wanConfig.interface; });
      if (wanItem) {
        wanItem.zone = 'wan';
        wanItem.mtu = workingState.wanConfig.mtu || wanItem.mtu;
      }
    }

    if (equalKeys(prev.firewallConfig, workingState.firewallConfig, ['transparentDns', 'exposeWireguard', 'wireguardPort', 'flowOffload'])) {
      workingState.firewallConfig = deepClone(committedState.firewallConfig);
    } else {
      workingState.firewallConfig.offloadActive = committedState.firewallConfig.offloadActive;
    }
    if (sameJson(prev.firewallRules, workingState.firewallRules)) {
      workingState.firewallRules = deepClone(committedState.firewallRules);
    }
    if (sameJson(prev.staticRoutes, workingState.staticRoutes)) {
      workingState.staticRoutes = deepClone(committedState.staticRoutes);
    }
    if (sameJson(prev.dhcp.scopes, workingState.dhcp.scopes)) {
      workingState.dhcp.scopes = deepClone(committedState.dhcp.scopes);
    }
    if (sameJson(prev.dhcp.reservations, workingState.dhcp.reservations)) {
      workingState.dhcp.reservations = deepClone(committedState.dhcp.reservations);
    }
    if (equalKeys(prev.dns, workingState.dns, ['resolvers', 'dnssecEnabled', 'cacheSize'])) {
      workingState.dns.resolvers = deepClone(committedState.dns.resolvers);
      workingState.dns.dotEnabled = committedState.dns.dotEnabled;
      workingState.dns.dnssecEnabled = committedState.dns.dnssecEnabled;
      workingState.dns.cacheSize = committedState.dns.cacheSize;
    }
    if (sameJson(prev.dns.overrides, workingState.dns.overrides)) {
      workingState.dns.overrides = deepClone(committedState.dns.overrides);
    }
    if (sameJson(prev.nat.portForwards, workingState.nat.portForwards)) {
      workingState.nat.portForwards = deepClone(committedState.nat.portForwards);
    }
    workingState.nat.wanIface = workingState.wanConfig.interface || committedState.nat.wanIface;

    var wgKeys = ['enabled', 'tunnelSubnet', 'listenPort', 'endpointHost', 'dns'];
    if (equalKeys(prev.vpn.wireguard, workingState.vpn.wireguard, wgKeys)) {
      wgKeys.forEach(function (k) { workingState.vpn.wireguard[k] = committedState.vpn.wireguard[k]; });
    }
    workingState.vpn.wireguard.active = committedState.vpn.wireguard.active;
    workingState.vpn.wireguard.publicKey = committedState.vpn.wireguard.publicKey;
    if (sameJson(prev.vpn.wireguard.peers, workingState.vpn.wireguard.peers)) {
      workingState.vpn.wireguard.peers = deepClone(committedState.vpn.wireguard.peers);
    } else {
      var prevPeerIds = {};
      (prev.vpn.wireguard.peers || []).forEach(function (p) { prevPeerIds[p.id] = true; });
      (committedState.vpn.wireguard.peers || []).forEach(function (cp) {
        var wp = workingState.vpn.wireguard.peers.find(function (x) { return x.id === cp.id; });
        if (wp) {
          wp.lastHandshake = cp.lastHandshake;
          wp.rxGb = cp.rxGb;
          wp.txGb = cp.txGb;
          wp.endpoint = cp.endpoint;
          if (wp.enabled) wp.status = cp.status;
        } else if (!prevPeerIds[cp.id]) {
          workingState.vpn.wireguard.peers.push(deepClone(cp));
        }
      });
    }

    if (equalKeys(prev.sqm, workingState.sqm, ['enabled', 'iface', 'downloadKbps', 'uploadKbps', 'overheadBytes'])) {
      workingState.sqm = deepClone(committedState.sqm);
    } else if (workingState.sqm && committedState.sqm) {
      workingState.sqm.statusOutput = committedState.sqm.statusOutput;
    }

    if (equalKeys(prev.adblock, workingState.adblock, ['enabled', 'forceDns', 'blockedServices'])) {
      workingState.adblock.enabled = committedState.adblock.enabled;
      workingState.adblock.forceDns = committedState.adblock.forceDns;
      workingState.adblock.blockedServices = deepClone(committedState.adblock.blockedServices);
    }
    workingState.adblock.filteringEnabled = committedState.adblock.filteringEnabled;
    workingState.adblock.filteringInterval = committedState.adblock.filteringInterval;
    workingState.adblock.blockedServicesSchedule = deepClone(committedState.adblock.blockedServicesSchedule || { time_zone: 'Local' });
    if (sameJson(prev.adblock.feeds, workingState.adblock.feeds)) {
      workingState.adblock.feeds = deepClone(committedState.adblock.feeds);
    }
    if (
      sameJson(prev.adblock.customBlocked, workingState.adblock.customBlocked) &&
      sameJson(prev.adblock.allowlist, workingState.adblock.allowlist)
    ) {
      workingState.adblock.customBlocked = deepClone(committedState.adblock.customBlocked);
      workingState.adblock.allowlist = deepClone(committedState.adblock.allowlist);
      workingState.adblock.passthroughRules = deepClone(committedState.adblock.passthroughRules || []);
    }
    workingState.adblock.running = committedState.adblock.running;
    workingState.adblock.availableServices = deepClone(committedState.adblock.availableServices);
    workingState.adblock.queryLog = deepClone(committedState.adblock.queryLog);
    workingState.adblock.queriesToday = committedState.adblock.queriesToday;
    workingState.adblock.blockedToday = committedState.adblock.blockedToday;
    workingState.adblock.blockedPercent = committedState.adblock.blockedPercent;
    workingState.adblock.avgLatencyMs = committedState.adblock.avgLatencyMs;

    var keepHostname = prev.system.hostname !== workingState.system.hostname ? workingState.system.hostname : committedState.system.hostname;
    workingState.system = Object.assign({}, deepClone(committedState.system), {
      hostname: keepHostname,
      fqdn: keepHostname + '.lan'
    });
    if (equalKeys(prev.general, workingState.general, ['timezone', 'ntpServers', 'ntpServeLan'])) {
      workingState.general = deepClone(committedState.general);
    } else {
      workingState.general.availableTimezones = deepClone(committedState.general.availableTimezones);
      workingState.general.ntpTracking = committedState.general.ntpTracking;
      workingState.general.ntpSources = committedState.general.ntpSources;
    }

    if (equalKeys(prev.access.ssh, workingState.access.ssh, ['passwordAuth', 'allowRootLogin', 'idleTimeout'])) {
      workingState.access.ssh.passwordAuth = committedState.access.ssh.passwordAuth;
      workingState.access.ssh.allowRootLogin = committedState.access.ssh.allowRootLogin;
      workingState.access.ssh.idleTimeout = committedState.access.ssh.idleTimeout;
    }
    workingState.daemons = deepClone(committedState.daemons);
    workingState.flows = deepClone(committedState.flows);
    workingState.neighbors = deepClone(committedState.neighbors);
    workingState.connectedRoutes = deepClone(committedState.connectedRoutes);
    workingState.cron = deepClone(committedState.cron);
    workingState.sysctl = deepClone(committedState.sysctl);
    workingState.dhcp.leases = deepClone(committedState.dhcp.leases);
    workingState.access.osUsers = deepClone(committedState.access.osUsers);
    workingState.access.tls = deepClone(committedState.access.tls);
    workingState.access.ssh.sshKeys = deepClone(committedState.access.ssh.sshKeys);
    workingState.access.ssh.usersKeys = deepClone(committedState.access.ssh.usersKeys);
    workingState.aliases = deepClone(committedState.aliases);

    recomputeDiffs();
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

  var RUNTIME_ONLY_REASONS = {
    telemetry: true,
    audit: true,
    runtime: true,
    'flows-tick': true,
    'flows-refresh': true,
    'routing-refresh': true,
    'sqm-status': true,
    'vpn-refresh': true,
    'querylog-refresh': true,
    'access-refresh': true,
    'syslog-refresh': true,
    'dmesg-refresh': true,
    'kernel-log': true
  };

  function isRuntimeOnlyReason(reason) {
    return Boolean(reason && RUNTIME_ONLY_REASONS[reason]);
  }

  Hive.store = {
    getState: getState,
    getCommittedState: getCommittedState,
    getStagedChanges: getStagedChanges,
    getPendingCount: getPendingCount,
    isRuntimeOnlyReason: isRuntimeOnlyReason,
    stageMutation: stageMutation,
    hydrateFromBackend: hydrateFromBackend,
    commitWorkingAsClean: commitWorkingAsClean,
    updateTelemetry: updateTelemetry,
    updateRuntimeState: updateRuntimeState,
    recordAudit: recordAudit,
    discardStaged: discardStaged
  };
})(window);
