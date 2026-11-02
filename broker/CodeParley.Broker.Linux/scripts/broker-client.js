'use strict';
// Minimal broker IPC client (operator/controller side). Connects to the broker's Unix socket, sends
// one JSON request line, prints the one JSON response line. Run as the controller account (its uid is
// what the broker authorizes via SO_PEERCRED).
//   node broker-client.js <socketPath> '<requestJson>'
const net = require('net');

const socketPath = process.argv[2];
const requestJson = process.argv[3];
if (!socketPath || !requestJson) { console.error('usage: broker-client.js <socketPath> <requestJson>'); process.exit(64); }
JSON.parse(requestJson); // validate before sending

const sock = net.connect(socketPath);
let buf = '';
const fail = (m) => { console.error(m); process.exit(1); };
sock.setTimeout(170000, () => fail('timeout waiting for the broker'));
sock.on('connect', () => sock.end(requestJson + '\n'));
sock.on('data', (d) => { buf += d; });
sock.on('error', (e) => fail('socket error: ' + e.message));
sock.on('end', () => {
  const line = buf.split('\n').find((l) => l.trim().length > 0) || '';
  try { process.stdout.write(JSON.stringify(JSON.parse(line)) + '\n'); }
  catch (_) { process.stdout.write(buf); }
  let ok = false;
  try { ok = JSON.parse(line).ok === true; } catch (_) { /* ignore */ }
  process.exit(ok ? 0 : 2);
});
