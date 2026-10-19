// Exercise the shipped enhancement without a browser or third-party dependencies.
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('../site/docs.js', import.meta.url), 'utf8');
function setup(platform, hash = '', prefixes = ['install']) {
  const keys = ['windows', 'macos', 'debian-or-ubuntu'];
  const groups = prefixes.map(prefix => {
    const buttons = keys.map(key => ({
      id: `tab-${prefix}-${key}`, attrs: { 'aria-controls': `${prefix}-${key}` }, events: {},
      getAttribute(name) { return this.attrs[name]; },
      setAttribute(name, value) { this.attrs[name] = value; },
      addEventListener(name, fn) { this.events[name] = fn; },
      focus() { this.focused = true; },
    }));
    const panels = keys.map(key => ({
      id: `${prefix}-${key}`, dataset: { platform: key }, hidden: false, attrs: {},
      setAttribute(name, value) { this.attrs[name] = value; },
      closest(selector) { return selector === '.platform-panel' ? this : null; },
    }));
    const tabs = { hidden: true, querySelectorAll() { return buttons; } };
    return { prefix, buttons, panels, tabs };
  });
  const targets = {};
  for (const group of groups) {
    for (const [index, key] of keys.entries()) {
      const panel = group.panels[index];
      const target = {
        closest() { return panel; },
        scrollIntoView() { this.scrolled = true; },
      };
      const heading = group.prefix === 'remove'
        ? `${key === 'debian-or-ubuntu' ? 'debian-ubuntu' : key}-removal`
        : key;
      targets[panel.id] = panel;
      targets[heading] = target;
      if (group === groups[0]) targets[key] = target;
    }
  }
  targets['windows-service'] = targets.windows;
  const toc = groups.flatMap(group => keys.map(key => ({
    hash: `#${group.prefix === 'remove'
      ? `${key === 'debian-or-ubuntu' ? 'debian-ubuntu' : key}-removal`
      : key}`,
    hidden: false,
  })));
  const tabs = groups.map(group => group.tabs);
  const panels = groups.flatMap(group => group.panels);
  const context = {
    navigator: { platform, userAgent: platform }, location: { hash },
    matchMedia() { return { matches: false }; },
    document: {
      querySelectorAll(selector) {
        if (selector === '.platform-tabs') return tabs;
        if (selector === '.platform-panel') return panels;
        if (selector === '.shell-tabs') return [];
        return toc;
      },
      getElementById(id) { return targets[id] ?? null; },
    },
    window: {
      events: {},
      addEventListener(name, fn) { (this.events[name] ??= []).push(fn); },
    },
  };
  runInNewContext(source, context);
  return { groups, buttons: groups[0].buttons, panels: groups[0].panels, tabs, toc, context, targets };
}
function selected(state, prefix = state.groups[0].prefix) {
  const group = state.groups.find(item => item.prefix === prefix);
  const active = group.buttons.filter(button => button.attrs['aria-selected'] === 'true');
  assert.equal(active.length, 1);
  const key = active[0].getAttribute('aria-controls').slice(prefix.length + 1);
  assert.equal(group.panels.filter(panel => !panel.hidden).length, 1);
  const visible = group.panels.find(panel => !panel.hidden);
  assert.equal(visible.dataset.platform, key);
  assert.equal(visible.attrs.role, 'tabpanel');
  assert.equal(visible.attrs['aria-labelledby'], active[0].id);
  assert.equal(active[0].tabIndex, 0);
  return key;
}

test('selects the detected operating system with a usable unknown-system fallback', () => {
  for (const [platform, expected] of [['Win32', 'windows'], ['MacIntel', 'macos'], ['Linux x86_64', 'debian-or-ubuntu'], ['', 'windows']]) {
    const state = setup(platform);
    assert.equal(selected(state), expected);
    assert.equal(state.tabs[0].hidden, false);
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
  state.context.window.events.hashchange.forEach(listener => listener());
  assert.equal(selected(state), 'macos');
  assert.equal(state.targets.macos.scrolled, true);
});
test('installation and removal tabs keep their selections independent', () => {
  const state = setup('Win32', '', ['install', 'remove']);
  assert.equal(selected(state, 'install'), 'windows');
  assert.equal(selected(state, 'remove'), 'windows');
  state.groups.find(group => group.prefix === 'remove').buttons[1].events.click();
  assert.equal(selected(state, 'install'), 'windows');
  assert.equal(selected(state, 'remove'), 'macos');
});
test('deep links into removal instructions reveal the matching operating system tab', () => {
  const state = setup('Linux x86_64', '#windows-removal', ['install', 'remove']);
  assert.equal(selected(state, 'install'), 'windows');
  assert.equal(selected(state, 'remove'), 'windows');
  assert.equal(state.targets['windows-removal'].scrolled, true);
  state.context.location.hash = '#macos-removal';
  state.context.window.events.hashchange.forEach(listener => listener());
  assert.equal(selected(state, 'remove'), 'macos');
  assert.equal(state.targets['macos-removal'].scrolled, true);
});
test('malformed and unrelated anchors keep automatic platform selection working', () => {
  for (const hash of ['#%broken', '#build-from-source', '']) {
    assert.equal(selected(setup('MacIntel', hash)), 'macos');
  }
});

test('troubleshooting tabs switch every command group and keep shared guidance visible', () => {
  const state = setup('MacIntel', '', ['troubleshoot']);
  const shared = { hidden: false, closest() { return null; } };
  state.targets['find-status-and-logs'] = shared;
  state.toc.push({ hash: '#find-status-and-logs', hidden: false });
  for (const [index, key] of ['windows', 'macos', 'debian-or-ubuntu'].entries()) {
    state.buttons[index].events.click();
    assert.equal(selected(state), key);
    assert.equal(state.panels.find(panel => !panel.hidden).id, `troubleshoot-${key}`);
    assert.equal(state.toc.at(-1).hidden, false);
    assert.equal(shared.hidden, false);
  }
});
