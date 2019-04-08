// HACK: We need this extension to catch the network requests associated with
// popups or opening a link in a new tab. The remote debugger takes a while to
// detect a new target and attach, so without a pause on main frame navigation
// requests, it sometimes misses the first few network requests or misses its
// opportunity to set up breakpoints.
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    if (details.type == "main_frame" && details.initiator === undefined) {
      let start = Date.now();
      while (Date.now() - start < 500) {}
    }
    return {cancel: false};
  },
  {urls: ["<all_urls>"]},
  ["blocking"]
);
