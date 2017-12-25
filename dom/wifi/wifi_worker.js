/* -*- Mode: Java; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set shiftwidth=2 tabstop=2 autoindent cindent expandtab: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

importScripts("systemlibs.js", "libhardware_legacy.js");

var cbuf = ctypes.char.array(4096)();
var hwaddr = ctypes.uint8_t.array(6)();
var len = ctypes.size_t();
var ints = ctypes.int.array(8)();

let DEBUG = false;

let debug;
if (DEBUG) {
  debug = function (s) {
    dump("-*- WifiWorker component: " + s + "\n");
  };
} else {
  debug = function (s) {};
}

// TODO: consolidate with implementation in systemlibs.js
let libcutils = (function () {
  let library = ctypes.open("libcutils.so");

  return {
    property_get: library.declare("property_get", ctypes.default_abi, ctypes.int, ctypes.char.ptr, ctypes.char.ptr, ctypes.char.ptr),
    property_set: library.declare("property_set", ctypes.default_abi, ctypes.int, ctypes.char.ptr, ctypes.char.ptr)
  };
})();

self.onmessage = function(e) {
  var data = e.data;
  var id = data.id;
  var cmd = data.cmd;

  switch (cmd) {
  case "command":
    len.value = 4096;
    var ret = libhardware_legacy.command(data.request, cbuf, len.address());
    var reply = "";
    if (!ret) {
      // The return value from libhardware_legacy.command is not guaranteed to
      // be null-terminated. At the same time we want to make sure that we
      // don't return a response with a trailing newline, so handle both cases
      // here. Note that if we wrote 4096 characters to cbuf, we don't have to
      // null-terminate the buffer, as ctypes has the maximum size already.
      // Note also that len.value is an object. We can ignore the high 32 bits
      // because we know that the maximum that it can be is 4096.
      var reply_len = ctypes.UInt64.lo(len.value);
      if (reply_len !== 0) {
        if (cbuf[reply_len - 1] === 10)
          cbuf[--reply_len] = 0;
        else if (reply_len !== 4096)
          cbuf[reply_len] = 0;

        reply = cbuf.readStringReplaceMalformed();
      }

      // Else if reply_len was 0, use the empty reply, set above.
    }
    postMessage({ id: id, status: ret, reply: reply });
    break;
  case "wait_for_event":
    var ret = libhardware_legacy.wait_for_event(cbuf, 4096);
    var event = cbuf.readString().substr(0, ret.value);
    postMessage({ id: id, event: event });
    break;
  case "ifc_reset_connections":
    var ret = libnetutils.ifc_reset_connections(data.ifname,
                                                libnetutils.RESET_ALL_ADDRESSES);
    postMessage({ id: id, status: ret });
    break;
  case "ifc_enable":
  case "ifc_disable":
  case "ifc_remove_host_routes":
  case "ifc_remove_default_route":
  case "dhcp_stop":
  case "dhcp_release_lease":
    var ret = libnetutils[cmd](data.ifname);
    postMessage({ id: id, status: ret });
    break;
  case "ifc_get_default_route":
    var route = libnetutils.ifc_get_default_route(data.ifname);
    postMessage({ id: id, route: route });
    break;
  case "ifc_add_host_route":
  case "ifc_set_default_route":
    var ret = libnetutils[cmd](data.ifname, data.route);
    postMessage({ id: id, status: ret });
    break;
  case "ifc_configure":
    debug("WIFI: data: " + uneval(data) + "\n");
    var ret = libnetutils.ifc_configure(data.ifname, data.ipaddr, data.mask, data.gateway, data.dns1, data.dns2);
    postMessage({ id: id, status: ret });
    break;
  case "dhcp_get_errmsg":
    var error = libnetutils.get_dhcp_get_errmsg();
    postMessage({ id: id, error: error.readString() });
    break;
  case "dhcp_do_request":
  case "dhcp_do_request_renew":
    var out = libnetutils[cmd](data.ifname);
    out.id = id;
    out.status = out.ret;
    postMessage(out);
    break;
  case "property_get":
    var ret = libcutils.property_get(data.key, cbuf, data.defaultValue);
    postMessage({ id: id, status: ret, value: cbuf.readString() });
    break;
  case "property_set":
    var ret = libcutils.property_set(data.key, data.value);
    postMessage({ id: id, status: ret });
    break;
  case "close_supplicant_connection":
    libhardware_legacy.close_supplicant_connection();
    postMessage({ id: id, status: ret });
    break;
  default:
    var f = libhardware_legacy[cmd] || libnetutils[cmd];
    var ret = f();
    debug("WIFI: " + cmd + " returned: " + ret);
    postMessage({ id: id, status: ret });
    break;
  }
}
