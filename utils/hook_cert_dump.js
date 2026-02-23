// Dump full PEM keys and certificates from memory
// Run: frida -U -f com.softmedia.receiver.lite -l hook_cert_dump.js

function dumpPEM(address) {
    // Read enough to get full PEM block (RSA 2048 key ~ 1700 chars, certs ~ 2000)
    var raw;
    try {
        raw = Memory.readUtf8String(address, 4096);
    } catch (e) {
        // If UTF8 fails, try reading as bytes
        try {
            raw = Memory.readCString(address);
        } catch (e2) {
            console.log('  [!] Could not read at ' + address);
            return null;
        }
    }
    if (!raw) return null;

    // Find the end marker
    var endIdx = raw.indexOf('-----END');
    if (endIdx === -1) {
        console.log('  [!] No END marker found, partial data');
        return raw.substring(0, 256);
    }
    // Find the newline after END marker
    var nlIdx = raw.indexOf('\n', endIdx);
    if (nlIdx === -1) nlIdx = raw.indexOf('\r', endIdx);
    if (nlIdx === -1) nlIdx = endIdx + 40; // fallback

    return raw.substring(0, nlIdx + 1);
}

var found = {};
var fileIndex = 0;

function scanForPEM() {
    console.log('\n[*] Scanning for PEM blocks in memory...\n');

    Process.enumerateRanges('r--').forEach(function (range) {
        try {
            Memory.scan(range.base, range.size,
                // "-----BEGIN" in hex
                '2d 2d 2d 2d 2d 42 45 47 49 4e',
                {
                    onMatch: function (address, size) {
                        var addrStr = address.toString();
                        if (found[addrStr]) return;
                        found[addrStr] = true;

                        var pem = dumpPEM(address);
                        if (!pem) return;

                        // Determine type
                        var type = 'UNKNOWN';
                        if (pem.indexOf('PRIVATE KEY') !== -1) type = 'PRIVATE_KEY';
                        else if (pem.indexOf('RSA PRIVATE KEY') !== -1) type = 'RSA_PRIVATE_KEY';
                        else if (pem.indexOf('CERTIFICATE') !== -1) type = 'CERTIFICATE';
                        else if (pem.indexOf('PUBLIC KEY') !== -1) type = 'PUBLIC_KEY';

                        console.log('='.repeat(60));
                        console.log('[' + type + '] at ' + address);
                        console.log('Length: ' + pem.length + ' chars');
                        console.log(pem);

                        // Save to file
                        var filename = '/data/local/tmp/pem_' + fileIndex + '_' + type + '.pem';
                        var f = new File(filename, 'w');
                        f.write(pem);
                        f.close();
                        console.log('[SAVED] ' + filename);
                        console.log('='.repeat(60) + '\n');
                        fileIndex++;
                    },
                    onComplete: function () { }
                }
            );
        } catch (e) {
            // Skip unreadable ranges
        }
    });

    console.log('\n[*] Scan complete. ' + fileIndex + ' PEM blocks saved to /data/local/tmp/');
}

// Also scan rw- ranges
function scanRW() {
    Process.enumerateRanges('rw-').forEach(function (range) {
        try {
            Memory.scan(range.base, range.size,
                '2d 2d 2d 2d 2d 42 45 47 49 4e',
                {
                    onMatch: function (address, size) {
                        var addrStr = address.toString();
                        if (found[addrStr]) return;
                        found[addrStr] = true;

                        var pem = dumpPEM(address);
                        if (!pem) return;

                        var type = 'UNKNOWN';
                        if (pem.indexOf('PRIVATE KEY') !== -1) type = 'PRIVATE_KEY';
                        else if (pem.indexOf('CERTIFICATE') !== -1) type = 'CERTIFICATE';
                        else if (pem.indexOf('PUBLIC KEY') !== -1) type = 'PUBLIC_KEY';

                        console.log('='.repeat(60));
                        console.log('[' + type + '] at ' + address);
                        console.log('Length: ' + pem.length + ' chars');
                        console.log(pem);

                        var filename = '/data/local/tmp/pem_' + fileIndex + '_' + type + '.pem';
                        var f = new File(filename, 'w');
                        f.write(pem);
                        f.close();
                        console.log('[SAVED] ' + filename);
                        console.log('='.repeat(60) + '\n');
                        fileIndex++;
                    },
                    onComplete: function () { }
                }
            );
        } catch (e) { }
    });
}

// Wait for the app to fully initialize, then scan
setTimeout(function () {
    console.log('[*] Waiting 5 seconds for app to load keys...');
}, 0);

setTimeout(function () {
    scanForPEM();
    scanRW();
    console.log('\n[*] All done! Pull files with:');
    console.log('    adb pull /data/local/tmp/pem_0_PRIVATE_KEY.pem');
    console.log('    adb pull /data/local/tmp/pem_1_CERTIFICATE.pem');
    console.log('    etc.');
}, 5000);
