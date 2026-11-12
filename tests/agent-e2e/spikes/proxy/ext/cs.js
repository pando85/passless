// MAIN-world content script marker (used by Q3 to see whether content scripts run in a given context).
document.documentElement.setAttribute('data-spike-cs', '1');
window.__spikeCS = location.href;
