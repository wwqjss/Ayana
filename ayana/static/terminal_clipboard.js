/* Terminal clipboard is write-only. OSC52 offers text; a browser click copies it. */
(function (root) {
  const MAX_BYTES = 256 * 1024;
  function create(options = {}) {
    let pending = "", version = 0, disposed = false, armedUntil = 0, copying = false;
    const current = () => !disposed && (!options.isCurrent || options.isCurrent());
    const status = (text, error = false) => { if (current() && options.onStatus) options.onStatus(text, error); };
    const doc = options.document || root.document;
    const nav = options.navigator || root.navigator || {};
    const now = options.now || Date.now;
    function offer(text) {
      if (!current() || typeof text !== "string" || !text.length) return false;
      if (new TextEncoder().encode(text).length > MAX_BYTES) {
        status("内容超过复制上限，请分段选择复制。", true); return false;
      }
      pending = text; ++version;
      if (options.onOffer) options.onOffer(text, true);
      status("内容已就绪，请点击「复制到本机」。");
      return true;
    }
    function receiveOsc52(data) {
      // Never answer clipboard queries, and ignore attach/reconnect replays.
      if (!current() || !armedUntil || now() > armedUntil || typeof data !== "string") return true;
      const split = data.indexOf(";");
      if (split < 0 || !["", "c"].includes(data.slice(0, split))) return true;
      const encoded = data.slice(split + 1);
      if (!encoded || encoded === "?" || encoded.length > Math.ceil(MAX_BYTES / 3) * 4
          || encoded.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) return true;
      try {
        const bytes = Uint8Array.from(root.atob(encoded), (character) => character.charCodeAt(0));
        if (bytes.length > MAX_BYTES) return true;
        offer(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      } catch (_) { status("无法解析复制内容，请选择文本复制。", true); }
      return true;
    }
    async function copyPending() {
      if (!current() || !pending) return { ok: false, error: "no_copy_text" };
      if (copying) return { ok: false, error: "copy_in_progress" };
      copying = true;
      const text = pending, operation = version;
      const preview = options.preview ? options.preview() : null;
      const stillCurrent = () => current() && operation === version;
      try {
        const secure = options.secureContext === undefined ? root.isSecureContext === true : options.secureContext;
        if (secure && nav.clipboard && typeof nav.clipboard.writeText === "function") {
          await nav.clipboard.writeText(text);
        } else {
          // This branch must run synchronously inside the explicit click.
          if (!doc || typeof doc.execCommand !== "function") throw new Error("copy_not_supported");
          const area = preview || doc.createElement("textarea");
          const previous = doc.activeElement;
          area.value = text; area.readOnly = true;
          if (!preview) {
            area.style.position = "fixed"; area.style.opacity = "0";
            doc.body.appendChild(area);
          }
          area.focus(); area.select();
          if (typeof area.setSelectionRange === "function") area.setSelectionRange(0, text.length);
          let copied = false;
          try { copied = doc.execCommand("copy") === true; }
          finally { if (!preview) area.remove(); }
          if (!copied) throw new Error("copy_denied");
          if (previous && typeof previous.focus === "function") previous.focus();
        }
        if (!stillCurrent()) return { ok: false, stale: true };
        pending = ""; ++version;
        if (options.onOffer) options.onOffer("", false);
        status("已复制到本机剪贴板。");
        return { ok: true };
      } catch (_) {
        if (!stillCurrent()) return { ok: false, stale: true };
        status("浏览器未允许复制。内容已保留，可选中文本后按 Ctrl+C。", true);
        if (preview) { preview.focus(); preview.select(); }
        return { ok: false, error: "clipboard_write_failed" };
      } finally { copying = false; }
    }
    function clear() {
      pending = ""; ++version;
      if (current() && options.onOffer) options.onOffer("", false);
    }
    return {
      offer, receiveOsc52, copyPending, clear,
      arm: () => { if (current()) armedUntil = now() + 10000; },
      dispose: () => { clear(); disposed = true; armedUntil = 0; },
    };
  }
  root.AyanaTerminalClipboard = { create, MAX_BYTES };
  if (typeof module !== "undefined" && module.exports) module.exports = { create, MAX_BYTES };
})(typeof window !== "undefined" ? window : globalThis);
