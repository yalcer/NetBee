/* ==========================================================================
   Hive — Baseline Initial State Schema for NetBee OS (Raspberry Pi 5)
   Provides clean empty/default structures prior to live netbeed hydration.
   eth0 = LAN (192.168.10.1/24), eth1 = WAN (DHCP / PPPoE / ONT VLAN).
   ========================================================================== */
(function (window) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  function createSeedState() {
    return {
      schemaVersion: 2,
      system: {
        hostname: 'netbee',
        fqdn: 'netbee.lan',
        model: 'Raspberry Pi 5',
        firmware: 'NetBee OS 0.1.0',
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
        netmask: '255.255.255.0'
      },
      wanConfig: {
        mode: 'dhcp',
        interface: 'eth1',
        vlanId: 35,
        pppoeUser: '',
        pppoePassword: '',
        macClone: '',
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
          removable: false,
          label: 'LAN Bridge / Switch Port',
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
          removable: false,
          label: 'WAN Upstream Port',
          zone: 'wan',
          mode: 'DHCP',
          ipv4: '—',
          ipv6: '—',
          gateway: '—',
          mac: '—',
          mtu: 1500,
          vlanId: 35,
          pppoeUser: '',
          pppoePassword: '',
          speed: '1000Mb/s',
          duplex: 'Full',
          linkDetected: false,
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
        running: true,
        forceDns: false,
        queriesToday: 0,
        blockedToday: 0,
        blockedPercent: 0,
        avgLatencyMs: 0,
        feeds: [],
        customBlocked: [],
        allowlist: [],
        blockedServices: [],
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

  Hive.mockDb = {
    createSeedState: createSeedState
  };
})(window);
