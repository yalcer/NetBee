/* ==========================================================================
   Hive — Pure-SVG Hive Telemetry Charts (Zero Dependencies)
   ========================================================================== */
(function (window, $) {
  'use strict';

  var Hive = (window.Hive = window.Hive || {});

  function buildPath(points) {
    if (!points.length) return '';
    return points
      .map(function (pt, idx) {
        return (idx === 0 ? 'M' : 'L') + pt.x.toFixed(1) + ',' + pt.y.toFixed(1);
      })
      .join(' ');
  }

  function buildArea(points, baselineY) {
    if (!points.length) return '';
    var line = buildPath(points);
    var last = points[points.length - 1];
    var first = points[0];
    return line + ' L' + last.x.toFixed(1) + ',' + baselineY.toFixed(1) + ' L' + first.x.toFixed(1) + ',' + baselineY.toFixed(1) + ' Z';
  }

  /**
   * Render an interactive dual-series RX/TX throughput SVG chart.
   * @param {jQuery} $container
   * @param {Array<{label:string, rx:number, tx:number}>} points
   */
  function renderThroughput($container, points) {
    if (!$container || !$container.length || !points || !points.length) return;

    var W = 680;
    var H = 210;
    var pad = { top: 14, right: 16, bottom: 26, left: 54 };
    var plotW = W - pad.left - pad.right;
    var plotH = H - pad.top - pad.bottom;

    var maxVal = 100;
    points.forEach(function (p) {
      if (p.rx > maxVal) maxVal = p.rx;
      if (p.tx > maxVal) maxVal = p.tx;
    });
    // Round max nicely upward
    var stepBase = maxVal > 500 ? 200 : maxVal > 200 ? 100 : 50;
    var yMax = Math.ceil((maxVal * 1.15) / stepBase) * stepBase;

    var stepX = points.length > 1 ? plotW / (points.length - 1) : plotW;
    var rxPts = [];
    var txPts = [];

    points.forEach(function (p, i) {
      var x = pad.left + i * stepX;
      var yRx = pad.top + plotH - (p.rx / yMax) * plotH;
      var yTx = pad.top + plotH - (p.tx / yMax) * plotH;
      rxPts.push({ x: x, y: yRx, raw: p });
      txPts.push({ x: x, y: yTx, raw: p });
    });

    var baselineY = pad.top + plotH;
    var gridHtml = '';
    var gridLines = 4;
    for (var g = 0; g <= gridLines; g++) {
      var frac = g / gridLines;
      var gy = pad.top + frac * plotH;
      var gVal = Math.round(yMax * (1 - frac));
      gridHtml += '<line class="q-chart-grid-line" x1="' + pad.left + '" y1="' + gy.toFixed(1) + '" x2="' + (W - pad.right) + '" y2="' + gy.toFixed(1) + '"></line>';
      gridHtml += '<text class="q-chart-axis-text" x="' + (pad.left - 8) + '" y="' + (gy + 3.5).toFixed(1) + '" text-anchor="end">' + gVal + 'M</text>';
    }

    var xLabelsHtml = '';
    var labelStep = Math.max(1, Math.floor((points.length - 1) / 5));
    var lastIdx = points.length - 1;
    points.forEach(function (p, idx) {
      var isLast = idx === lastIdx;
      var isRegular = idx % labelStep === 0 && (lastIdx - idx >= Math.max(2, Math.ceil(labelStep * 0.6)));
      if (isRegular || isLast) {
        var lx = pad.left + idx * stepX;
        var anchor = idx === 0 ? 'start' : isLast ? 'end' : 'middle';
        xLabelsHtml += '<text class="q-chart-axis-text" x="' + lx.toFixed(1) + '" y="' + (H - 6) + '" text-anchor="' + anchor + '">' + Hive.format.escapeHtml(p.label) + '</text>';
      }
    });

    var svg =
      '<div class="q-chart-wrap">' +
      '<svg class="q-chart-svg" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Network RX and TX throughput chart">' +
      gridHtml +
      xLabelsHtml +
      '<path class="q-chart-area-tx" d="' + buildArea(txPts, baselineY) + '"></path>' +
      '<path class="q-chart-area-rx" d="' + buildArea(rxPts, baselineY) + '"></path>' +
      '<path class="q-chart-line q-chart-line-tx" d="' + buildPath(txPts) + '"></path>' +
      '<path class="q-chart-line q-chart-line-rx" d="' + buildPath(rxPts) + '"></path>' +
      '<line class="q-chart-hover-line" x1="0" y1="' + pad.top + '" x2="0" y2="' + baselineY + '" style="display:none;"></line>' +
      '<circle class="q-chart-dot" data-dot="rx" r="4" fill="var(--q-primary)" style="display:none;"></circle>' +
      '<circle class="q-chart-dot" data-dot="tx" r="4" fill="var(--q-lan)" style="display:none;"></circle>' +
      '<rect class="q-chart-hit" x="' + pad.left + '" y="' + pad.top + '" width="' + plotW + '" height="' + plotH + '" fill="transparent"></rect>' +
      '</svg>' +
      '<div class="q-chart-tooltip" hidden></div>' +
      '</div>';

    $container.html(svg);

    var $wrap = $container.find('.q-chart-wrap');
    var $svg = $wrap.find('svg');
    var $line = $wrap.find('.q-chart-hover-line');
    var $dotRx = $wrap.find('[data-dot="rx"]');
    var $dotTx = $wrap.find('[data-dot="tx"]');
    var $tip = $wrap.find('.q-chart-tooltip');

    function updateAtClientX(clientX) {
      var rect = $svg[0].getBoundingClientRect();
      if (!rect.width) return;
      var svgX = ((clientX - rect.left) / rect.width) * W;
      var rel = Math.max(0, Math.min(plotW, svgX - pad.left));
      var idx = Math.round(rel / stepX);
      idx = Math.max(0, Math.min(points.length - 1, idx));

      var rxP = rxPts[idx];
      var txP = txPts[idx];
      var pt = points[idx];

      $line.attr({ x1: rxP.x, x2: rxP.x }).show();
      $dotRx.attr({ cx: rxP.x, cy: rxP.y }).show();
      $dotTx.attr({ cx: txP.x, cy: txP.y }).show();

      $tip
        .html(
          '<div class="q-chart-tooltip-time">' + Hive.format.escapeHtml(pt.label) + '</div>' +
          '<div class="q-chart-tooltip-row"><span><span class="q-legend-dot is-rx"></span> Download (RX)</span><strong class="q-mono">' + Hive.format.mbps(pt.rx) + '</strong></div>' +
          '<div class="q-chart-tooltip-row"><span><span class="q-legend-dot is-tx"></span> Upload (TX)</span><strong class="q-mono">' + Hive.format.mbps(pt.tx) + '</strong></div>'
        )
        .removeAttr('hidden');

      var pxX = (rxP.x / W) * rect.width;
      var tipW = $tip.outerWidth() || 170;
      var leftPos = pxX + 14;
      if (leftPos + tipW > rect.width - 6) {
        leftPos = Math.max(6, pxX - tipW - 14);
      }
      $tip.css('left', leftPos + 'px');
    }

    function clearHover() {
      $line.hide();
      $dotRx.hide();
      $dotTx.hide();
      $tip.attr('hidden', true);
    }

    $wrap.find('.q-chart-hit').on('mousemove', function (e) {
      updateAtClientX(e.clientX);
    });

    $wrap.find('.q-chart-hit').on('touchstart touchmove', function (e) {
      var touches = e.originalEvent && e.originalEvent.touches;
      if (touches && touches.length) {
        updateAtClientX(touches[0].clientX);
      }
    });

    $wrap.on('mouseleave touchend touchcancel', clearHover);
  }

  Hive.charts = {
    renderThroughput: renderThroughput
  };
})(window, window.jQuery);

