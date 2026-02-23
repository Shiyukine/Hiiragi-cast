// ── Memory scanner ─────────────────────────────────────────────────────────────
// Scan memory for "-----BEGIN" markers, then read surrounding bytes
// to extract the enclosing JSON object.
// Run: frida -U -f com.softmedia.receiver.castapp -l hook_cert_json.js --no-pause
// Type  scan()  in REPL to re-scan at any time.

var seenAddrs = {};
var fileIndex = 0;
var outJson = {};

// Read up to maxLen bytes starting at addr as a JS string (byte values 0-255)
function readBytes(addr, maxLen) {
    try {
        var bytes = Memory.readByteArray(addr, maxLen);
        if (!bytes) return null;
        var arr = new Uint8Array(bytes);
        var result = '';
        var CHUNK = 8192;
        for (var i = 0; i < arr.length; i += CHUNK) {
            result += String.fromCharCode.apply(null, arr.subarray(i, i + CHUNK));
        }
        return result;
    } catch (e) { return null; }
}

// Given a large string and the offset where "-----BEGIN" was found,
// walk backwards to find the nearest '{' that could open a JSON object
function findOpenBrace(s, beginOffset) {
    for (var i = beginOffset; i >= 0; i--) {
        if (s[i] === '{') return i;
    }
    return -1;
}

// From openIdx, walk forward counting brace depth to find the matching '}'
// Returns the complete JSON substring, or null if not found within s
function extractJSON(s, openIdx) {
    var depth = 0, inStr = false, esc = false;
    for (var i = openIdx; i < s.length; i++) {
        var c = s[i];
        if (esc) { esc = false; continue; }
        if (c === '\\') { esc = true; continue; }
        if (c === '"') { inStr = !inStr; continue; }
        if (inStr) continue;
        if (c === '{') depth++;
        else if (c === '}') {
            depth--;
            if (depth === 0) return s.substring(openIdx, i + 1);
        }
    }
    return null;
}

function isInteresting(json) {
    return json.indexOf('-----BEGIN') !== -1 || json.indexOf('cpu') !== -1;
}

function scanMemory() {
    console.log('\n[*] Scanning for -----BEGIN markers in memory...');
    var found = 0;

    // "-----BEGIN" in hex
    var pattern = '2d 2d 2d 2d 2d 42 45 47 49 4e';
    var BACK = 16 * 1024;   // read 16 KB before the BEGIN marker
    var TOTAL = 64 * 1024;   // read 64 KB total (covers largest CKS JSON)

    ['rw-', 'r--'].forEach(function (prot) {
        Process.enumerateRanges(prot).forEach(function (range) {
            try {
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: function (addr) {
                        var key = addr.toString();
                        if (seenAddrs[key]) return;
                        seenAddrs[key] = true;

                        // Start reading BACK bytes before BEGIN, clamped to range start
                        var back = Math.min(BACK, addr.sub(range.base).toInt32());
                        var startAddr = addr.sub(back);
                        var readLen = Math.min(TOTAL, range.base.add(range.size).sub(startAddr).toInt32());

                        var chunk = readBytes(startAddr, readLen);
                        //if (!chunk) return;

                        // Find the nearest '{' before the BEGIN marker
                        var beginInChunk = back; // offset of "-----BEGIN" inside chunk
                        var openIdx = findOpenBrace(chunk, beginInChunk);
                        //if (openIdx === -1) return;

                        var json = extractJSON(chunk, openIdx);
                        if (!json) return;
                        json = json.trim();
                        if (!json || !isInteresting(json)) return;

                        found++;

                        // Try valid JSON parse & pretty-print
                        try {
                            var obj = JSON.parse(json);
                            console.log('\n[PARSED #' + found + ']');
                            console.log(JSON.stringify(obj, null, 2));
                            outJson = obj; // save last one for REPL access
                        } catch (e) {
                            console.log('[!] Not valid JSON: ' + e.message);
                        }
                    },
                    onComplete: function () { }
                });
            } catch (e) { }
        });
    });

    if (found === 0)
        console.log('[*] Nothing found yet. Start a cast session then type  scan()  again.');
    else
        console.log('\n[*] Done. Pull files: adb pull /data/local/tmp/cks_0.json');
}

global.scan = scanMemory;

setTimeout(function () { console.log('[*] 5s scan...'); scanMemory(); }, 5000);

console.log('[*] Loaded. Auto-scan at 5s. Type  scan()  anytime.\n');

function consoleDump() {
    for (var key in outJson) {
        if (outJson.hasOwnProperty(key)) {
            console.log(key + ': ' + outJson[key]);
        }
    }
}
