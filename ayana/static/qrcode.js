/* 自包含 QR 码生成器（字节模式，EC-L M）。无外部依赖。 */
(function (global) {
  "use strict";

  // GF(256) for Reed-Solomon
  var EXP = new Array(256), LOG = new Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP[i] = x; LOG[x] = i;
      x <<= 1; if (x & 0x100) x ^= 0x11d;
    }
    for (var j = 255; j < 256; j++) EXP[j] = EXP[j - 255];
  })();

  function gmul(a, b) {
    if (a === 0 || b === 0) return 0;
    return EXP[(LOG[a] + LOG[b]) % 255];
  }

  function rsGenPoly(n) {
    var g = [1];
    for (var i = 0; i < n; i++) {
      var ng = new Array(g.length + 1);
      for (var k = 0; k < ng.length; k++) ng[k] = 0;
      for (var j = 0; j < g.length; j++) {
        ng[j] ^= g[j];
        ng[j + 1] ^= gmul(g[j], EXP[i]);
      }
      g = ng;
    }
    return g;
  }

  function rsEncode(data, ecLen) {
    var gen = rsGenPoly(ecLen);
    var res = new Array(ecLen);
    for (var i = 0; i < ecLen; i++) res[i] = 0;
    for (var d = 0; d < data.length; d++) {
      var factor = data[d] ^ res[0];
      res.shift(); res.push(0);
      if (factor !== 0) {
        for (var j = 0; j < gen.length - 1; j++) {
          res[j] ^= gmul(gen[j + 1], factor);
        }
      }
    }
    return res;
  }

  // 容量表（版本 1-10，EC-M，字节模式）：[总码字, 每块纠错码字, 组1块数, 组1数据码字, 组2块数, 组2数据码字]
  var EC_M = {
    1:  [26, 10, 1, 16, 0, 0],
    2:  [44, 16, 1, 28, 0, 0],
    3:  [70, 26, 1, 44, 0, 0],
    4:  [100, 18, 2, 32, 0, 0],
    5:  [134, 24, 2, 43, 0, 0],
    6:  [172, 16, 4, 27, 0, 0],
    7:  [196, 18, 4, 31, 0, 0],
    8:  [242, 22, 2, 38, 2, 39],
    9:  [292, 22, 3, 36, 2, 37],
    10: [346, 26, 4, 43, 1, 44]
  };

  var ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]
  };

  function pickVersion(len) {
    for (var v = 1; v <= 10; v++) {
      var e = EC_M[v];
      var dataCw = e[2] * e[3] + e[4] * e[5];
      // mode 4bit + count 8bit + data + terminator
      var need = Math.ceil((4 + 8 + len * 8 + 4) / 8);
      if (need <= dataCw) return v;
    }
    return 10;
  }

  function buildCodewords(bytes, version) {
    var e = EC_M[version];
    var dataCw = e[2] * e[3] + e[4] * e[5];
    var bits = [];
    function push(val, n) {
      for (var i = n - 1; i >= 0; i--) bits.push((val >> i) & 1);
    }
    push(0x4, 4); // byte mode
    push(bytes.length, 8);
    for (var i = 0; i < bytes.length; i++) push(bytes[i], 8);
    // terminator
    var cap = dataCw * 8;
    for (var t = 0; t < 4 && bits.length < cap; t++) bits.push(0);
    while (bits.length % 8 !== 0) bits.push(0);
    var cw = [];
    for (var b = 0; b < bits.length; b += 8) {
      var v = 0;
      for (var k = 0; k < 8; k++) v = (v << 1) | bits[b + k];
      cw.push(v);
    }
    var pad = [0xec, 0x11];
    var p = 0;
    while (cw.length < dataCw) { cw.push(pad[p % 2]); p++; }

    // split blocks
    var blocks = [], ecs = [];
    var idx = 0, g = 0;
    for (; g < e[2]; g++) {
      blocks.push(cw.slice(idx, idx + e[3])); idx += e[3];
    }
    for (g = 0; g < e[4]; g++) {
      blocks.push(cw.slice(idx, idx + e[5])); idx += e[5];
    }
    for (g = 0; g < blocks.length; g++) {
      ecs.push(rsEncode(blocks[g], e[1]));
    }
    // interleave
    var out = [], maxD = 0;
    for (g = 0; g < blocks.length; g++) maxD = Math.max(maxD, blocks[g].length);
    for (var i2 = 0; i2 < maxD; i2++) {
      for (g = 0; g < blocks.length; g++) {
        if (i2 < blocks[g].length) out.push(blocks[g][i2]);
      }
    }
    for (i2 = 0; i2 < e[1]; i2++) {
      for (g = 0; g < ecs.length; g++) out.push(ecs[g][i2]);
    }
    return out;
  }

  function placeFunction(mod, size, version) {
    function set(x, y, v, fn) {
      if (x < 0 || y < 0 || x >= size || y >= size) return;
      mod[y][x] = v; fn[y][x] = true;
    }
    var fn = [];
    for (var y = 0; y < size; y++) {
      mod[y] = new Array(size); fn[y] = new Array(size);
      for (var x = 0; x < size; x++) { mod[y][x] = 0; fn[y][x] = false; }
    }
    // timing
    for (var i = 0; i < size; i++) {
      if (!fn[6][i]) set(i, 6, i % 2 === 0 ? 1 : 0, fn);
      if (!fn[i][6]) set(6, i, i % 2 === 0 ? 1 : 0, fn);
    }
    // finders
    function finder(ox, oy) {
      for (var dy = -1; dy <= 7; dy++) {
        for (var dx = -1; dx <= 7; dx++) {
          var x = ox + dx, y = oy + dy;
          if (x < 0 || y < 0 || x >= size || y >= size) continue;
          var dark = (dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6) &&
            (dx === 0 || dx === 6 || dy === 0 || dy === 6 ||
             (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4));
          set(x, y, dark ? 1 : 0, fn);
        }
      }
    }
    finder(0, 0); finder(size - 7, 0); finder(0, size - 7);
    // alignment
    var ap = ALIGN[version] || [];
    for (var a = 0; a < ap.length; a++) {
      for (var b = 0; b < ap.length; b++) {
        var ax = ap[a], ay = ap[b];
        if ((ax <= 8 && ay <= 8) || (ax >= size - 9 && ay <= 8) || (ax <= 8 && ay >= size - 9)) continue;
        for (var dy2 = -2; dy2 <= 2; dy2++) {
          for (var dx2 = -2; dx2 <= 2; dx2++) {
            var dark2 = Math.max(Math.abs(dx2), Math.abs(dy2)) !== 1;
            set(ax + dx2, ay + dy2, dark2 ? 1 : 0, fn);
          }
        }
      }
    }
    // reserve format
    for (var f = 0; f < 15; f++) {
      var p1 = f < 6 ? f : (f < 8 ? f + 1 : size - 15 + f);
      set(8, p1, 0, fn); set(p1, 8, 0, fn);
    }
    set(8, size - 8, 1, fn);
    // version info (v>=7)
    if (version >= 7) {
      for (var vi = 0; vi < 18; vi++) {
        var x2 = Math.floor(vi / 3), y2 = size - 11 + (vi % 3);
        set(x2, y2, 0, fn); set(y2, x2, 0, fn);
      }
    }
    return fn;
  }

  function placeData(mod, fn, size, data) {
    var bitIdx = 0;
    function nextBit() {
      if (bitIdx >= data.length * 8) return 0;
      var byte = data[bitIdx >> 3];
      return (byte >> (7 - (bitIdx & 7))) & 1;
    }
    var up = true;
    for (var col = size - 1; col >= 0; col -= 2) {
      if (col === 6) col = 5;
      for (var i = 0; i < size; i++) {
        var row = up ? size - 1 - i : i;
        for (var c = 0; c < 2; c++) {
          var x = col - c;
          if (fn[row][x]) continue;
          mod[row][x] = nextBit();
          bitIdx++;
        }
      }
      up = !up;
    }
  }

  function maskFn(m, x, y) {
    switch (m) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
      case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
      case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
      case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    }
    return false;
  }

  function applyMask(mod, fn, size, m) {
    for (var y = 0; y < size; y++) {
      for (var x = 0; x < size; x++) {
        if (!fn[y][x] && maskFn(m, x, y)) mod[y][x] ^= 1;
      }
    }
  }

  function formatBits(m) {
    // EC-M (00) + mask, BCH 15,5
    var data = (0x00 << 3) | m;
    var d = data << 10;
    for (var i = 4; i >= 0; i--) {
      if (d & (1 << (i + 10))) d ^= 0x537 << i;
    }
    return ((data << 10) | d) ^ 0x5412;
  }

  function placeFormat(mod, fn, size, m) {
    var bits = formatBits(m);
    function bit(i) { return (bits >> i) & 1; }
    // 副本1：左上
    for (var i = 0; i < 8; i++) {
      var y = i < 6 ? i : i + 1;
      if (y < size) mod[y][8] = bit(14 - i);
    }
    for (var j = 0; j < 7; j++) {
      mod[8][5 - j] = bit(j);
    }
    // 副本2
    for (var k = 0; k < 8; k++) {
      mod[8][size - 1 - k] = bit(k);
    }
    for (var p = 0; p < 7; p++) {
      mod[size - 7 + p][8] = bit(7 + p);
    }
    mod[size - 8][8] = 1;
  }

  function penalty(mod, size) {
    var p = 0, x, y, i, run, dark = 0;
    // rule 1
    for (y = 0; y < size; y++) {
      run = 1;
      for (x = 1; x < size; x++) {
        if (mod[y][x] === mod[y][x - 1]) run++;
        else { if (run >= 5) p += 3 + (run - 5); run = 1; }
      }
      if (run >= 5) p += 3 + (run - 5);
    }
    for (x = 0; x < size; x++) {
      run = 1;
      for (y = 1; y < size; y++) {
        if (mod[y][x] === mod[y - 1][x]) run++;
        else { if (run >= 5) p += 3 + (run - 5); run = 1; }
      }
      if (run >= 5) p += 3 + (run - 5);
    }
    // rule 2
    for (y = 0; y < size - 1; y++) {
      for (x = 0; x < size - 1; x++) {
        var s = mod[y][x] + mod[y][x + 1] + mod[y + 1][x] + mod[y + 1][x + 1];
        if (s === 0 || s === 4) p += 3;
      }
    }
    // rule 3 + 4
    for (y = 0; y < size; y++) {
      for (x = 0; x < size; x++) {
        if (mod[y][x]) dark++;
      }
    }
    var ratio = Math.abs(dark * 100 / (size * size) - 50) / 5;
    p += Math.floor(ratio) * 10;
    return p;
  }

  function encode(text) {
    var bytes = [];
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c < 128) bytes.push(c);
      else if (c < 2048) {
        bytes.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      } else {
        bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      }
    }
    var version = pickVersion(bytes.length);
    var size = 17 + version * 4;
    var data = buildCodewords(bytes, version);
    var best = null, bestP = Infinity;
    for (var m = 0; m < 8; m++) {
      var mod = [], fn = placeFunction(mod, size, version);
      placeData(mod, fn, size, data);
      applyMask(mod, fn, size, m);
      placeFormat(mod, fn, size, m);
      var p = penalty(mod, size);
      if (p < bestP) { bestP = p; best = mod; }
    }
    return { size: size, modules: best, version: version };
  }

  function toSvg(qr, scale) {
    scale = scale || 4;
    var n = qr.size, dim = n * scale + 16;
    var path = [];
    for (var y = 0; y < n; y++) {
      for (var x = 0; x < n; x++) {
        if (qr.modules[y][x]) {
          path.push("M" + (x * scale + 8) + " " + (y * scale + 8) + "h" + scale + "v" + scale + "h-" + scale + "z");
        }
      }
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + dim + '" height="' + dim +
      '" viewBox="0 0 ' + dim + ' ' + dim + '"><rect width="' + dim + '" height="' + dim +
      '" fill="#fff"/><path d="' + path.join("") + '" fill="#000"/></svg>';
  }

  global.QR = {
    encode: encode,
    toSvg: toSvg
  };
})(
  typeof window !== "undefined"
    ? window
    : typeof globalThis !== "undefined"
      ? globalThis
      : this
);
