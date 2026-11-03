// Bootstrap only: retain the native HTTP server, but do not expose its temporary signup API.
'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const original = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  assert.equal(Number(args[0]), 3000, 'Unexpected bootstrap listener');
  assert(args.slice(1).every(value => typeof value === 'function'), 'Unexpected bootstrap listen arguments');
  return original.call(this, { port: 3000, host: '127.0.0.1' }, ...args.slice(1));
};
