"use strict";
// Structured clone of a several-thousand-deep value never returns in some engines; refuse
// before postMessage so the tree view fails closed instead of spinning on "Loading…".
var MAX_DEPTH = 2048;

function depthOf(value) {
  var max = 0;
  var stack = [[value, 1]];
  while (stack.length) {
    var item = stack.pop();
    var v = item[0], d = item[1];
    if (d > max) max = d;
    if (max > MAX_DEPTH) return max;
    if (v !== null && typeof v === "object") {
      if (Array.isArray(v)) {
        for (var i = 0; i < v.length; i++) stack.push([v[i], d + 1]);
      } else {
        var keys = Object.keys(v);
        for (var j = 0; j < keys.length; j++) stack.push([v[keys[j]], d + 1]);
      }
    }
  }
  return max;
}

self.onmessage = (event) => {
  try {
    var data = JSON.parse(event.data);
    if (depthOf(data) > MAX_DEPTH) {
      self.postMessage({ error: "JSON is nested more than " + MAX_DEPTH + " levels deep" });
      return;
    }
    self.postMessage({ data: data });
  } catch (error) {
    self.postMessage({ error: String(error.message || error) });
  }
};
