const target = new URLSearchParams(location.search).get("u") || "";
let host = "";
try { host = new URL(target).hostname; } catch (e) {}
document.getElementById("site").textContent = host;

document.getElementById("back").addEventListener("click", () => {
  if (history.length > 1) history.back(); else location.replace("about:blank");
});

document.getElementById("go").addEventListener("click", async () => {
  if (!/^https?:\/\//i.test(target)) return;
  const { cfxAllowHosts = [] } = await chrome.storage.local.get("cfxAllowHosts");
  if (!cfxAllowHosts.includes(host)) cfxAllowHosts.push(host);
  await chrome.storage.local.set({ cfxAllowHosts });
  location.replace(target);
});