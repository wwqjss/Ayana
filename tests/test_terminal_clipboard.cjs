/* Clipboard contract tests use in-memory browser doubles; never the OS clipboard. */
const assert = require("node:assert/strict");
const { create, MAX_BYTES } = require("../ayana/static/terminal_clipboard.js");
const tests = [];
const test = (name, run) => tests.push([name, run]);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
function fixture({ secure = false, write = async () => {}, legacy = true } = {}) {
  const offers = [], statuses = [], writes = [], commands = [];
  let reads = 0, active = true, clock = 1000, userGesture = false, legacyAllowed = legacy;
  const preview = { value: "", focus() { this.focused = true; }, select() { this.selected = true; }, setSelectionRange(start, end) { this.range = [start, end]; } };
  const previous = { focus() { this.restored = true; } };
  const navigator = { clipboard: {
    async writeText(text) { writes.push(text); return write(text); },
    readText() { ++reads; throw new Error("clipboard_read_forbidden"); },
    read() { ++reads; throw new Error("clipboard_read_forbidden"); },
  } };
  const document = { activeElement: previous, execCommand(command) {
    commands.push(command);
    if (!userGesture) throw new Error("trusted_click_required");
    return legacyAllowed;
  } };
  const bridge = create({ secureContext: secure, navigator, document, preview: () => preview,
    now: () => clock, isCurrent: () => active,
    onOffer(text, visible) { offers.push({ text, visible }); preview.value = text; },
    onStatus(text, error) { statuses.push({ text, error }); },
  });
  return { bridge, offers, statuses, writes, commands, preview, previous,
    readCount: () => reads, activateClick: () => { userGesture = true; },
    loseCurrent: () => { active = false; }, advance: seconds => { clock += seconds * 1000; },
    allowLegacy: value => { legacyAllowed = value; },
  };
}
const payload = text => "c;" + Buffer.from(text, "utf8").toString("base64");
const successful = fixture => fixture.statuses.some(row => row.text === "已复制到本机剪贴板。");

test("OSC52 from initial attach or reconnect cannot offer historical text", () => {
  const f = fixture(); f.bridge.receiveOsc52(payload("old terminal copy"));
  assert.equal(f.offers.length, 0); assert.equal(f.commands.length, 0); assert.equal(f.readCount(), 0);
});
test("live OSC52 offers exact Unicode text but never writes without a local click", () => {
  const f = fixture(); f.bridge.arm(); f.bridge.receiveOsc52(payload("中文\n<literal>&🙂"));
  assert.equal(f.offers.at(-1).text, "中文\n<literal>&🙂");
  assert.equal(f.commands.length, 0); assert.equal(f.writes.length, 0); assert.equal(successful(f), false);
});
test("clipboard queries and non-clipboard selections are consumed without a read", () => {
  const f = fixture(); f.bridge.arm();
  for (const text of ["c;?", ";?", "p;YWJj", "s;YWJj", "0;YWJj"]) assert.equal(f.bridge.receiveOsc52(text), true);
  assert.equal(f.offers.length, 0); assert.equal(f.readCount(), 0); assert.equal(f.commands.length, 0);
});
test("expired live-copy intent does not replay a delayed OSC52", () => {
  const f = fixture(); f.bridge.arm(); f.advance(11); f.bridge.receiveOsc52(payload("stale"));
  assert.equal(f.offers.length, 0);
});
test("malformed base64 and invalid UTF8 never become copy text", () => {
  const f = fixture(); f.bridge.arm();
  for (const text of ["c;%%%%", "c;YQ===", "c;YQ", "c;/w==", "c;", "c;YWJj;injected"]) f.bridge.receiveOsc52(text);
  assert.equal(f.offers.length, 0); assert.equal(f.writes.length, 0); assert.equal(f.readCount(), 0);
});
test("encoded and decoded clipboard limits reject oversized data", () => {
  const f = fixture(); f.bridge.arm();
  f.bridge.receiveOsc52(payload("x".repeat(MAX_BYTES + 1)));
  assert.equal(f.bridge.offer("字".repeat(MAX_BYTES / 2)), false);
  assert.equal(f.offers.length, 0); assert.equal(f.writes.length, 0);
});
test("HTTP copy succeeds only from explicit synchronous compatibility copy", async () => {
  const f = fixture(); f.bridge.offer("HTTP copied text");
  assert.equal(f.commands.length, 0); f.activateClick();
  const result = await f.bridge.copyPending();
  assert.equal(result.ok, true); assert.deepEqual(f.commands, ["copy"]); assert.equal(f.writes.length, 0);
  assert.equal(successful(f), true); assert.equal(f.previous.restored, true); assert.equal(f.readCount(), 0);
});
test("HTTP compatibility rejection keeps selectable text and never reports success", async () => {
  const f = fixture({ legacy: false }); f.bridge.offer("keep this text"); f.activateClick();
  const result = await f.bridge.copyPending();
  assert.equal(result.ok, false); assert.equal(successful(f), false); assert.equal(f.preview.value, "keep this text");
  assert.equal(f.preview.selected, true); f.allowLegacy(true);
  assert.equal((await f.bridge.copyPending()).ok, true);
});
test("HTTP asynchronous delivery cannot fake a successful user gesture", async () => {
  const f = fixture(); f.bridge.offer("remote result");
  const result = await f.bridge.copyPending();
  assert.equal(result.ok, false); assert.equal(successful(f), false); assert.equal(f.preview.value, "remote result");
});
test("HTTPS reports success only after browser write promise confirms", async () => {
  const pending = deferred(), f = fixture({ secure: true, write: () => pending.promise });
  f.bridge.offer("secure text"); const operation = f.bridge.copyPending();
  assert.deepEqual(f.writes, ["secure text"]); assert.equal(successful(f), false);
  pending.resolve(); assert.equal((await operation).ok, true); assert.equal(successful(f), true);
  assert.equal(f.commands.length, 0); assert.equal(f.readCount(), 0);
});
test("HTTPS permission failure keeps text without invoking an untrusted fallback", async () => {
  const f = fixture({ secure: true, write: async () => { throw new Error("NotAllowedError"); } });
  f.bridge.offer("retry text"); assert.equal((await f.bridge.copyPending()).ok, false);
  assert.equal(successful(f), false); assert.equal(f.preview.value, "retry text"); assert.equal(f.commands.length, 0);
});
test("duplicate clicks do not submit two browser writes", async () => {
  const pending = deferred(), f = fixture({ secure: true, write: () => pending.promise });
  f.bridge.offer("once"); const operation = f.bridge.copyPending();
  assert.equal((await f.bridge.copyPending()).error, "copy_in_progress"); assert.equal(f.writes.length, 1);
  pending.resolve(); await operation;
});
test("late browser success cannot clear a newer copy offer", async () => {
  const pending = deferred(), f = fixture({ secure: true, write: () => pending.promise });
  f.bridge.offer("first"); const operation = f.bridge.copyPending(); f.bridge.offer("new text");
  pending.resolve(); assert.equal((await operation).stale, true);
  assert.equal(f.preview.value, "new text"); assert.equal(successful(f), false);
});
test("dispose and a lost session suppress late browser status", async () => {
  for (const end of [f => f.bridge.dispose(), f => f.loseCurrent()]) {
    const pending = deferred(), f = fixture({ secure: true, write: () => pending.promise });
    f.bridge.offer("old session"); const operation = f.bridge.copyPending(); end(f); pending.resolve();
    assert.equal((await operation).stale, true); assert.equal(successful(f), false); assert.equal(f.readCount(), 0);
  }
});
test("cleared or disposed pending data cannot be copied again", async () => {
  const f = fixture(); f.bridge.offer("clear me"); f.bridge.clear();
  assert.equal((await f.bridge.copyPending()).ok, false); f.bridge.dispose(); f.bridge.arm();
  f.bridge.receiveOsc52(payload("late")); assert.equal(f.offers.at(-1).visible, false); assert.equal(f.commands.length, 0);
});

(async () => {
  for (const [name, run] of tests) { await run(); console.log("PASS " + name); }
  console.log(`${tests.length}/${tests.length} terminal clipboard tests passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
