"use strict";
self.onmessage = (event) => {
  try {
    self.postMessage({ data: JSON.parse(event.data) });
  } catch (error) {
    self.postMessage({ error: String(error.message || error) });
  }
};
