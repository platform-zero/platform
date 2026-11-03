// HTTP account service only: periodic maintenance must not keep an already closed native
// server/database alive. Timers still execute while either real service handle is open.
// This is neither a forced successful exit, a queue drain nor a crash watchdog.
'use strict';
const original = global.setInterval;
global.setInterval = function (...args) {
  const timer = original(...args);
  timer.unref();
  return timer;
};
