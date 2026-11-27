/* ==========================================================================
   Hive — Network Diagnostics (#/network/diagnostics)
   Live Ping, MTR Traceroute, nslookup, Bounded tcpdump & iperf3 Benchmark.
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  var state = {
    $root: null,
    mountToken: 0,
    interfaces: [],
    packets: [],
    iperfSrvStatus: { running: false, remaining_seconds: 0 },
    iperfPollTimer: null,
    stateListener: null
  };

  function formatMtrOutput(data, target) {
    if (!data || !data.report || !Array.isArray(data.report.hubs)) {
      return data && data.raw ? data.raw : JSON.stringify(data, null, 2);
    }
    var lines = [
      'MTR Report to ' + target,
      'Hop  Host                          Loss%   Snt   Last    Avg   Best   Wrst',
      '--------------------------------------------------------------------------'
    ];
    data.report.hubs.forEach(function (h) {
      var hop = String(h.count || '?').padStart(3, ' ');
      var host = String(h.host || '???').padEnd(28, ' ').slice(0, 28);
      var loss = (Number(h['Loss%'] || 0).toFixed(1) + '%').padStart(7, ' ');
      var snt = String(h.Snt || 0).padStart(5, ' ');
      var last = Number(h.Last || 0).toFixed(1).padStart(6, ' ');
      var avg = Number(h.Avg || 0).toFixed(1).padStart(6, ' ');
      var best = Number(h.Best || 0).toFixed(1).padStart(6, ' ');
      var wrst = Number(h.Wrst || 0).toFixed(1).padStart(6, ' ');
      lines.push(hop + '  ' + host + ' ' + loss + ' ' + snt + ' ' + last + ' ' + avg + ' ' + best + ' ' + wrst);
    });
    return lines.join('\n');
  }

  function formatIperfClientSummary(data) {
    if (!data || !data.end) {
      return (data && data.error) ? ('iperf3 error: ' + data.error) : JSON.stringify(data, null, 2);
    }
    var sent = data.end.sum_sent || {};
    var recv = data.end.sum_received || {};
    var sentMbps = ((Number(sent.bits_per_second) || 0) / 1e6).toFixed(2);
    var recvMbps = ((Number(recv.bits_per_second) || 0) / 1e6).toFixed(2);
    var retrans = sent.retransmits !== undefined ? sent.retransmits : 0;
    return [
      'iperf3 Benchmark Complete',
      '--------------------------------------------------',
      'Sender Rate   : ' + sentMbps + ' Mbps  (Retransmits: ' + retrans + ')',
      'Receiver Rate : ' + recvMbps + ' Mbps',
      'Duration      : ' + Number(sent.seconds || recv.seconds || 0).toFixed(1) + ' sec'
    ].join('\n');
  }

  function renderIperfServerPanel() {
    if (!state.$root) return;
    var st = state.iperfSrvStatus || { running: false };
    var esc = Hive.format.escapeHtml;
    var $box = state.$root.find('#q-iperf-srv-status');
    if (st.running) {
      $box.html(
        '<div class="q-kv-list" style="margin-bottom:12px;">' +
        '  <div class="q-kv-row"><span class="q-kv-label">Server State</span><span class="q-kv-value"><span class="ui label q-status-success">Listening (PID ' + esc(st.pid) + ')</span></span></div>' +
        '  <div class="q-kv-row"><span class="q-kv-label">Auto-Stop TTL</span><span class="q-kv-value q-mono">' + esc(st.remaining_seconds) + 's remaining</span></div>' +
        '  <div class="q-kv-row"><span class="q-kv-label">LAN Client Command</span><span class="q-kv-value q-mono">' + esc(st.client_command || ('iperf3 -c ' + st.bind_ip + ' -p ' + st.port)) + '</span></div>' +
        '</div>' +
        '<button type="button" class="ui negative small button" id="q-iperf-srv-stop-btn"><i data-lucide="square" class="q-icon q-icon-sm"></i><span>Stop Local Server</span></button>'
      );
    } else {
      $box.html(
        '<p class="q-text-muted" style="margin-bottom:12px;">Starts an unprivileged <code>iperf3 -s</code> listener on LAN &amp; WireGuard with temporary firewall rules that auto-expire when the timer ends.</p>' +
        '<button type="button" class="ui primary small button" id="q-iperf-srv-start-btn"><i data-lucide="play" class="q-icon q-icon-sm"></i><span>Start Temporary Server</span></button>'
      );
    }
    if (Hive.icons) Hive.icons.render();
  }

  function refreshIperfServer() {
    var token = state.mountToken;
    Hive.services.diagnostics
      .getIperfServer()
      .then(function (st) {
        if (!state.$root || token !== state.mountToken) return;
        state.iperfSrvStatus = st || { running: false };
        renderIperfServerPanel();
      })
      .catch(function () {});
  }

  function populateIfaceDropdowns() {
    var esc = Hive.format.escapeHtml;
    var opts = state.interfaces
      .map(function (i) {
        return '<div class="item" data-value="' + esc(i.device) + '"><span class="q-mono">' + esc(i.device) + '</span> — ' + esc(i.label) + '</div>';
      })
      .join('');
    var $dd = $('#q-cap-iface-dd');
    var cur = $dd.find('input[type="hidden"]').val() || 'eth0';
    $dd.find('.menu').html(opts);
    $dd.dropdown('refresh').dropdown('set selected', cur);
  }

  function renderPacketTable(summary) {
    if (!state.$root) return;
    var esc = Hive.format.escapeHtml;
    state.$root.find('#q-cap-count').text(state.packets.length + ' packets');
    if (summary) state.$root.find('#q-cap-summary').text(summary);

    var $tbody = state.$root.find('#q-cap-tbody');
    if (!state.packets.length) {
      $tbody.html('<tr><td style="text-align:center;padding:24px;color:var(--q-text-muted);">Select an interface and click "Capture Packets" to run bounded <code>tcpdump</code>.</td></tr>');
      return;
    }
    $tbody.html(
      state.packets
        .map(function (line) {
          return '<tr><td class="q-mono" style="font-size:12px;">' + esc(line) + '</td></tr>';
        })
        .join('')
    );
  }

  function mount($container) {
    state.mountToken += 1;
    var token = state.mountToken;
    state.$root = $container;
    state.packets = [];

    Hive.services.interfaces.list().then(function (ifaces) {
      if (!state.$root || token !== state.mountToken) return;
      state.interfaces = ifaces;

      var html =
        '<div class="q-page-header">' +
        '  <div>' +
        '    <h1 class="q-page-title">Network Diagnostics</h1>' +
        '    <p class="q-page-subtitle">Execute live ICMP ping, MTR path analysis, DNS <code>nslookup</code>, bounded <code>tcpdump</code> captures, and <code>iperf3</code> throughput benchmarks.</p>' +
        '  </div>' +
        '</div>' +

        '<div id="q-diag-tabs-ctx">' +
        '  <div class="q-zone-tabs-bar">' +
        '    <div class="ui secondary pointing menu" data-tab-context="#q-diag-tabs-ctx">' +
        '      <a class="item active" data-tab="ping">Ping &amp; MTR Traceroute</a>' +
        '      <a class="item" data-tab="dns">DNS Lookup (nslookup)</a>' +
        '      <a class="item" data-tab="capture">Packet Capture (tcpdump)</a>' +
        '      <a class="item" data-tab="iperf">Bandwidth Benchmark (iperf3)</a>' +
        '    </div>' +
        '  </div>' +

        // Tab 1: Ping & MTR
        '  <div class="ui tab active q-tab-plain" data-tab="ping">' +
        '    <div class="q-card">' +
        '      <form class="ui form" id="q-dg-ping-form" novalidate style="margin-bottom:var(--q-space-4);">' +
        '        <div class="three fields">' +
        '          <div class="field"><label>Diagnostic Tool</label><div class="ui fluid selection dropdown" id="q-dg-tool-dd"><input type="hidden" id="q-dg-tool" value="ping"><i class="dropdown icon"></i><div class="text">ICMP Ping</div><div class="menu"><div class="item" data-value="ping">ICMP Ping</div><div class="item" data-value="mtr">MTR Path Traceroute</div></div></div></div>' +
        '          <div class="field required"><label for="q-dg-target">Target IP / Hostname</label><input id="q-dg-target" type="text" class="q-mono" value="1.1.1.1" placeholder="1.1.1.1 or cloudflare.com"></div>' +
        '          <div class="field"><label for="q-dg-count">Packets / Cycles (1 – 10)</label><input id="q-dg-count" type="number" class="q-mono" value="4" min="1" max="10"></div>' +
        '        </div>' +
        '        <div style="display:flex;gap:8px;flex-wrap:wrap;">' +
        '          <button type="submit" class="ui primary small button" id="q-dg-run-btn"><i data-lucide="play" class="q-icon q-icon-sm"></i><span>Run Probe</span></button>' +
        '          <button type="button" class="ui secondary small button" id="q-dg-copy-btn"><i data-lucide="copy" class="q-icon q-icon-sm"></i><span>Copy Output</span></button>' +
        '        </div>' +
        '      </form>' +
        '      <div class="q-console">' +
        '        <div class="q-console-header"><span>netbeed diagnostics</span><span id="q-dg-console-status">ready</span></div>' +
        '        <pre class="q-console-body" id="q-dg-console">Select ICMP Ping or MTR Traceroute and click "Run Probe".</pre>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +

        // Tab 2: DNS Lookup
        '  <div class="ui tab q-tab-plain" data-tab="dns">' +
        '    <div class="q-card">' +
        '      <form class="ui form" id="q-dg-dns-form" novalidate style="margin-bottom:var(--q-space-4);">' +
        '        <div class="two fields">' +
        '          <div class="field required"><label for="q-dg-dns-host">Hostname / Domain</label><input id="q-dg-dns-host" type="text" class="q-mono" value="cloudflare.com" placeholder="example.com"></div>' +
        '          <div class="field"><label for="q-dg-dns-srv">DNS Server (Optional — leave blank for local AdGuardHome)</label><input id="q-dg-dns-srv" type="text" class="q-mono" placeholder="127.0.0.1 or 1.1.1.1"></div>' +
        '        </div>' +
        '        <button type="submit" class="ui primary small button" id="q-dg-dns-btn"><i data-lucide="search" class="q-icon q-icon-sm"></i><span>Run nslookup</span></button>' +
        '      </form>' +
        '      <div class="q-console">' +
        '        <div class="q-console-header"><span>nslookup</span><span id="q-dg-dns-st">ready</span></div>' +
        '        <pre class="q-console-body" id="q-dg-dns-out">Enter a domain name and run nslookup.</pre>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +

        // Tab 3: Bounded Packet Capture
        '  <div class="ui tab q-tab-plain" data-tab="capture">' +
        '    <div class="q-card" style="margin-bottom:var(--q-space-4);">' +
        '      <form class="ui form" id="q-cap-form" novalidate>' +
        '        <div class="four fields" style="align-items:end;margin-bottom:0;">' +
        '          <div class="field"><label>Interface</label><div class="ui fluid selection dropdown" id="q-cap-iface-dd"><input type="hidden" id="q-cap-iface" value="eth0"><i class="dropdown icon"></i><div class="text">eth0</div><div class="menu"></div></div></div>' +
        '          <div class="field"><label>Protocol Filter</label><div class="ui fluid selection dropdown" id="q-cap-proto-dd"><input type="hidden" id="q-cap-proto" value=""><i class="dropdown icon"></i><div class="text">ANY</div><div class="menu"><div class="item" data-value="">ANY</div><div class="item" data-value="tcp">TCP</div><div class="item" data-value="udp">UDP</div><div class="item" data-value="icmp">ICMP</div><div class="item" data-value="arp">ARP</div></div></div></div>' +
        '          <div class="field"><label for="q-cap-port">Port (Optional)</label><input id="q-cap-port" type="number" class="q-mono" min="1" max="65535" placeholder="e.g. 53 or 443"></div>' +
        '          <div class="field"><label for="q-cap-cnt">Max Packets (1–50)</label><input id="q-cap-cnt" type="number" class="q-mono" min="1" max="50" value="20"></div>' +
        '        </div>' +
        '        <div style="display:flex;gap:8px;margin-top:12px;">' +
        '          <button type="submit" class="ui primary small button" id="q-cap-run-btn"><i data-lucide="radio" class="q-icon q-icon-sm"></i><span>Capture Packets</span></button>' +
        '          <button type="button" class="ui secondary small button" id="q-cap-export-btn"><i data-lucide="download" class="q-icon q-icon-sm"></i><span>Export .txt</span></button>' +
        '        </div>' +
        '      </form>' +
        '    </div>' +
        '    <div class="q-toolbar"><div class="q-toolbar-left"><span class="q-mono q-text-muted" id="q-cap-summary">Idle</span></div><div class="q-toolbar-right"><span class="ui label q-mono" id="q-cap-count">0 packets</span></div></div>' +
        '    <div class="q-table-wrap"><table class="ui striped table"><thead><tr><th>Captured Frame Summary (tcpdump -nn)</th></tr></thead><tbody id="q-cap-tbody"></tbody></table></div>' +
        '  </div>' +

        // Tab 4: iperf3 Client & Local Temporary Server
        '  <div class="ui tab q-tab-plain" data-tab="iperf">' +
        '    <div class="q-backup-grid">' +
        '      <div class="q-card">' +
        '        <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="gauge" class="q-icon q-text-accent"></i><span>iperf3 Client Test</span></h2><p class="q-card-subtitle">Benchmark throughput against a remote or LAN iperf3 server.</p></div></div>' +
        '        <form class="ui form" id="q-iperf-cli-form" novalidate>' +
        '          <div class="two fields">' +
        '            <div class="field required"><label for="q-ipf-host">Remote iperf3 Host</label><input id="q-ipf-host" type="text" class="q-mono" placeholder="192.168.10.50"></div>' +
        '            <div class="field"><label for="q-ipf-port">Port</label><input id="q-ipf-port" type="number" class="q-mono" value="5201" min="1" max="65535"></div>' +
        '          </div>' +
        '          <div class="two fields" style="align-items:end;">' +
        '            <div class="field"><label for="q-ipf-dur">Duration (1–15s)</label><input id="q-ipf-dur" type="number" class="q-mono" value="5" min="1" max="15"></div>' +
        '            <div class="field"><div class="ui toggle checkbox"><input type="checkbox" id="q-ipf-rev"><label for="q-ipf-rev">Reverse Mode (<code>-R</code> Download)</label></div></div>' +
        '          </div>' +
        '          <button type="submit" class="ui primary small button" id="q-ipf-cli-btn"><i data-lucide="play" class="q-icon q-icon-sm"></i><span>Run Client Benchmark</span></button>' +
        '        </form>' +
        '        <pre class="q-code-block" id="q-ipf-cli-out" style="margin-top:var(--q-space-3);">Ready to run iperf3 client benchmark.</pre>' +
        '      </div>' +

        '      <div class="q-card">' +
        '        <div class="q-card-header"><div><h2 class="q-card-title"><i data-lucide="server" class="q-icon q-text-accent"></i><span>Local Temporary iperf3 Server</span></h2><p class="q-card-subtitle">Test LAN Wi-Fi/Ethernet or WireGuard speed directly to the router.</p></div></div>' +
        '        <div class="ui form" style="margin-bottom:var(--q-space-3);">' +
        '          <div class="two fields">' +
        '            <div class="field"><label for="q-ipf-srv-port">Listen Port (1024–65535)</label><input id="q-ipf-srv-port" type="number" class="q-mono" value="5201" min="1024" max="65535"></div>' +
        '            <div class="field"><label for="q-ipf-srv-ttl">Auto-Expire TTL (Seconds)</label><input id="q-ipf-srv-ttl" type="number" class="q-mono" value="300" min="10" max="3600"></div>' +
        '          </div>' +
        '        </div>' +
        '        <div id="q-iperf-srv-status"></div>' +
        '      </div>' +
        '    </div>' +
        '  </div>' +
        '</div>';

      $container.html(html);
      if (Hive.icons) Hive.icons.render();
      if (Hive.ui) Hive.ui.init($container);
      populateIfaceDropdowns();
      renderPacketTable('Idle');
      refreshIperfServer();

      state.iperfPollTimer = window.setInterval(function () {
        if (state.iperfSrvStatus && state.iperfSrvStatus.running) refreshIperfServer();
      }, 3000);
    });

    $container.on('submit.qDiag', '#q-dg-ping-form', function (e) {
      e.preventDefault();
      var tool = $('#q-dg-tool').val() || 'ping';
      var host = $.trim($('#q-dg-target').val());
      var count = Math.max(1, Math.min(10, Number($('#q-dg-count').val()) || 4));
      if (!host) return;
      var $btn = $('#q-dg-run-btn').addClass('loading disabled');
      var $out = $('#q-dg-console').addClass('q-console-running').text('Running ' + tool + ' against ' + host + ' ...');
      $('#q-dg-console-status').text('running...');

      var req = tool === 'mtr' ? Hive.services.diagnostics.mtr(host, count) : Hive.services.diagnostics.ping(host, count);
      req
        .then(function (res) {
          if (tool === 'mtr') {
            $out.text(formatMtrOutput(res, host));
            $('#q-dg-console-status').text('completed');
          } else {
            $out.text(res.output || 'No output');
            $('#q-dg-console-status').text(res.ok ? 'completed' : 'packet loss');
          }
        })
        .catch(function (err) {
          $out.text('Error: ' + err.message);
          $('#q-dg-console-status').text('error');
        })
        .then(function () {
          $btn.removeClass('loading disabled');
          $out.removeClass('q-console-running');
        });
    });

    $container.on('click.qDiag', '#q-dg-copy-btn', function () {
      var text = $('#q-dg-console').text();
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).catch(function () {});
      Hive.ui.notify({ title: 'Copied', message: 'Diagnostic output copied.', type: 'success', displayTime: 2000 });
    });

    $container.on('submit.qDiag', '#q-dg-dns-form', function (e) {
      e.preventDefault();
      var host = $.trim($('#q-dg-dns-host').val());
      var srv = $.trim($('#q-dg-dns-srv').val());
      if (!host) return;
      var $btn = $('#q-dg-dns-btn').addClass('loading disabled');
      $('#q-dg-dns-st').text('resolving...');
      Hive.services.diagnostics
        .dnsLookup(host, srv)
        .then(function (res) {
          $('#q-dg-dns-out').text(res.output || 'No output');
          $('#q-dg-dns-st').text(res.ok ? 'NOERROR' : 'failed');
        })
        .catch(function (err) {
          $('#q-dg-dns-out').text('Error: ' + err.message);
          $('#q-dg-dns-st').text('error');
        })
        .then(function () {
          $btn.removeClass('loading disabled');
        });
    });

    $container.on('submit.qDiag', '#q-cap-form', function (e) {
      e.preventDefault();
      var iface = $('#q-cap-iface').val() || 'eth0';
      var proto = $('#q-cap-proto').val() || '';
      var port = Number($('#q-cap-port').val() || 0);
      var cnt = Math.max(1, Math.min(50, Number($('#q-cap-cnt').val()) || 20));
      var $btn = $('#q-cap-run-btn').addClass('loading disabled');
      $('#q-cap-summary').text('Capturing up to ' + cnt + ' packets on ' + iface + ' (12s max timeout)...');

      Hive.services.diagnostics
        .capture({ interface: iface, proto: proto, port: port, count: cnt })
        .then(function (res) {
          state.packets = res.packets || [];
          renderPacketTable(res.summary || 'Capture complete');
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Capture Error', message: err.message, type: 'error' });
          $('#q-cap-summary').text('Capture failed');
        })
        .then(function () {
          $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qDiag', '#q-cap-export-btn', function () {
      if (!state.packets.length) return;
      Hive.ui.downloadBlob('netbee-capture.txt', state.packets.join('\n'), 'text/plain;charset=utf-8');
    });

    $container.on('submit.qDiag', '#q-iperf-cli-form', function (e) {
      e.preventDefault();
      var host = $.trim($('#q-ipf-host').val());
      var port = Number($('#q-ipf-port').val() || 5201);
      var dur = Math.max(1, Math.min(15, Number($('#q-ipf-dur').val()) || 5));
      var rev = $('#q-ipf-rev').is(':checked');
      if (!host) {
        Hive.ui.notify({ title: 'Host Required', message: 'Enter target iperf3 server IP/hostname.', type: 'warning' });
        return;
      }
      var $btn = $('#q-ipf-cli-btn').addClass('loading disabled');
      $('#q-ipf-cli-out').text('Running iperf3 -c ' + host + ' -p ' + port + ' -t ' + dur + (rev ? ' -R' : '') + ' ...');

      Hive.services.diagnostics
        .iperfClient({ host: host, port: port, duration: dur, reverse: rev })
        .then(function (res) {
          $('#q-ipf-cli-out').text(formatIperfClientSummary(res));
        })
        .catch(function (err) {
          $('#q-ipf-cli-out').text('Error: ' + err.message);
        })
        .then(function () {
          $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qDiag', '#q-iperf-srv-start-btn', function () {
      var port = Number($('#q-ipf-srv-port').val() || 5201);
      var ttl = Number($('#q-ipf-srv-ttl').val() || 300);
      var $btn = $(this).addClass('loading disabled');
      Hive.services.diagnostics
        .startIperfServer({ port: port, durationSeconds: ttl })
        .then(function (st) {
          state.iperfSrvStatus = st;
          renderIperfServerPanel();
          Hive.ui.notify({ title: 'iperf3 Server Started', message: 'Listening on port ' + port + ' for ' + ttl + 's.', type: 'success' });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Start Failed', message: err.message, type: 'error' });
          $btn.removeClass('loading disabled');
        });
    });

    $container.on('click.qDiag', '#q-iperf-srv-stop-btn', function () {
      var $btn = $(this).addClass('loading disabled');
      Hive.services.diagnostics
        .stopIperfServer()
        .then(function () {
          state.iperfSrvStatus = { running: false };
          renderIperfServerPanel();
          Hive.ui.notify({ title: 'iperf3 Server Stopped', message: 'Closed listener and removed temporary firewall rule.', type: 'info' });
        })
        .catch(function (err) {
          Hive.ui.notify({ title: 'Stop Failed', message: err.message, type: 'error' });
          $btn.removeClass('loading disabled');
        });
    });
  }

  function unmount() {
    state.mountToken += 1;
    if (state.iperfPollTimer) {
      window.clearInterval(state.iperfPollTimer);
      state.iperfPollTimer = null;
    }
    if (state.$root) {
      state.$root.off('.qDiag');
      state.$root = null;
    }
  }

  Hive.router.register('/network/diagnostics', {
    title: 'Diagnostics',
    group: 'Network',
    mount: mount,
    unmount: unmount
  });
})(window, window.jQuery);
