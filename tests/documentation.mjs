// Exercise the shipped enhancement without a browser or third-party dependencies.
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('../site/docs.js', import.meta.url), 'utf8');
function setup(platform, hash = '', prefix = 'install') {
  const keys = ['windows', 'macos', 'debian-or-ubuntu'];
  const buttons = keys.map(key => ({
    id: `tab-${key}`, attrs: {}, events: {},
    setAttribute(name, value) { this.attrs[name] = value; },
    addEventListener(name, fn) { this.events[name] = fn; },
    focus() { this.focused = true; },
  }));
  const panels = keys.map(key => ({ id: `${prefix}-${key}`, dataset: { platform: key }, hidden: false, setAttribute() {} }));
  const targets = Object.fromEntries(keys.map((key, i) => [key, {
    closest() { return panels[i]; },
    scrollIntoView() { this.scrolled = true; },
  }]));
  targets['windows-service'] = targets.windows;
  const toc = keys.map(key => ({ hash: `#${key}` }));
  const tabs = { hidden: true, querySelectorAll() { return buttons; } };
  const context = {
    navigator: { platform, userAgent: platform }, location: { hash },
    matchMedia() { return { matches: false }; },
    document: {
      querySelector() { return tabs; },
      querySelectorAll(selector) { return selector === '.platform-panel' ? panels : toc; },
      getElementById(id) { return targets[id]; },
    },
    window: { events: {}, addEventListener(name, fn) { this.events[name] = fn; } },
  };
  runInNewContext(source, context);
  return { buttons, panels, tabs, toc, context, targets };
}
function selected(state) {
  const active = state.buttons.filter(button => button.attrs['aria-selected'] === 'true');
  assert.equal(active.length, 1);
  const key = active[0].id.slice(4);
  assert.equal(state.panels.filter(panel => !panel.hidden).length, 1);
  assert.equal(state.panels.find(panel => !panel.hidden).dataset.platform, key);
  assert.equal(active[0].tabIndex, 0);
  return key;
}

test('selects the detected operating system with a usable unknown-system fallback', () => {
  for (const [platform, expected] of [['Win32', 'windows'], ['MacIntel', 'macos'], ['Linux x86_64', 'debian-or-ubuntu'], ['', 'windows']]) {
    const state = setup(platform);
    assert.equal(selected(state), expected);
    assert.equal(state.tabs.hidden, false);
    assert.equal(state.toc.filter(link => !link.hidden).length, 1);
  }
});
test('manual selection and keyboard navigation update visibility and focus', () => {
  const state = setup('MacIntel');
  state.buttons[0].events.click();
  assert.equal(selected(state), 'windows');
  let prevented = false;
  state.buttons[0].events.keydown({ key: 'ArrowLeft', preventDefault() { prevented = true; } });
  assert.equal(selected(state), 'debian-or-ubuntu');
  assert.equal(state.buttons[2].focused, true);
  assert.equal(prevented, true);
  state.buttons[2].events.keydown({ key: 'Home', preventDefault() {} });
  assert.equal(selected(state), 'windows');
  state.buttons[0].events.keydown({ key: 'End', preventDefault() {} });
  assert.equal(selected(state), 'debian-or-ubuntu');
});
test('deep links override detection and hash changes reveal hidden instructions', () => {
  const state = setup('MacIntel', '#windows-service');
  assert.equal(selected(state), 'windows');
  assert.equal(state.targets.windows.scrolled, true);
  state.context.location.hash = '#macos';
  state.context.window.events.hashchange();
  assert.equal(selected(state), 'macos');
  assert.equal(state.targets.macos.scrolled, true);
});
test('malformed and unrelated anchors keep automatic platform selection working', () => {
  for (const hash of ['#%broken', '#build-from-source', '']) {
    assert.equal(selected(setup('MacIntel', hash)), 'macos');
  }
});

test('troubleshooting tabs switch every command group and keep shared guidance visible', () => {
  const state = setup('MacIntel', '', 'troubleshoot');
  const shared = { hidden: false, closest() { return null; } };
  state.targets['find-status-and-logs'] = shared;
  state.toc.push({ hash: '#find-status-and-logs' });
  for (const [index, key] of ['windows', 'macos', 'debian-or-ubuntu'].entries()) {
    state.buttons[index].events.click();
    assert.equal(selected(state), key);
    assert.equal(state.panels.find(panel => !panel.hidden).id, `troubleshoot-${key}`);
    assert.equal(state.toc.at(-1).hidden, false);
    assert.equal(shared.hidden, false);
  }
});
