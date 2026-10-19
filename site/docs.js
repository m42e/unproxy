// Navigation and reading remain available when JavaScript is disabled.
if (matchMedia('(max-width: 720px)').matches) {
  document.querySelector('.sidebar details').open = false;
}
if (navigator.clipboard && window.isSecureContext) {
  document.querySelectorAll('pre > code').forEach(code => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy';
    button.textContent = 'Copy';
    button.setAttribute('aria-label', 'Copy code to clipboard');
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(code.textContent);
        button.textContent = 'Copied';
      } catch {
        button.textContent = 'Select and copy';
      }
      setTimeout(() => { button.textContent = 'Copy'; }, 2000);
    });
    code.parentElement.append(button);
  });
}

// All platform instructions are readable until this enhancement is initialized.
document.querySelectorAll('.platform-tabs').forEach(platformTabs => {
  const buttons = [...platformTabs.querySelectorAll('[role=tab]')];
  const panels = buttons.map(button => document.getElementById(button.getAttribute('aria-controls')));
  function selectPlatform(id, focus = false) {
    buttons.forEach(button => {
      const panel = document.getElementById(button.getAttribute('aria-controls'));
      const selected = panel.dataset.platform === id;
      button.setAttribute('aria-selected', String(selected));
      button.tabIndex = selected ? 0 : -1;
      if (selected && focus) button.focus();
    });
    panels.forEach(panel => { panel.hidden = panel.dataset.platform !== id; });
    // Keep the page index in sync with the instructions currently visible.
    document.querySelectorAll('.toc a[href^="#"]').forEach(link => {
      const target = document.getElementById(link.hash.slice(1));
      const panel = target?.closest('.platform-panel');
      if (panels.includes(panel)) link.hidden = Boolean(panel.hidden);
    });
  }
  function platformForHash() {
    try {
      return document.getElementById(decodeURIComponent(location.hash.slice(1)))
        ?.closest('.platform-panel')?.dataset.platform;
    } catch { return undefined; }
  }
  buttons.forEach((button, index) => {
    const panel = panels[index];
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', button.id);
  });
  const system = `${navigator.platform} ${navigator.userAgent}`;
  const detected = /Windows|Win32|Win64/i.test(system) ? 'windows'
    : /Macintosh|MacIntel|Mac OS X/i.test(system) ? 'macos'
    : /Linux|X11/i.test(system) ? 'debian-or-ubuntu' : 'windows';
  buttons.forEach((button, index) => {
    button.addEventListener('click', () => selectPlatform(panels[index].dataset.platform));
    button.addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowRight') next = (index + 1) % buttons.length;
      if (event.key === 'ArrowLeft') next = (index + buttons.length - 1) % buttons.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = buttons.length - 1;
      if (next !== undefined) {
        event.preventDefault();
        selectPlatform(panels[next].dataset.platform, true);
      }
    });
  });
  selectPlatform(platformForHash() || detected);
  platformTabs.hidden = false;
  function revealHash() {
    const id = platformForHash();
    if (id) {
      selectPlatform(id);
      const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (panels.includes(target?.closest('.platform-panel'))) target?.scrollIntoView();
    }
  }
  window.addEventListener('hashchange', revealHash);
  revealHash();
});

// Shell choices stay in sync across shell instruction groups and page visits.
const shellTabGroups = [...document.querySelectorAll('.shell-tabs')].map(shellTabs => {
  const buttons = [...shellTabs.querySelectorAll('[role=tab]')];
  return {
    shellTabs,
    buttons,
    panels: buttons.map(button => document.getElementById(button.getAttribute('aria-controls'))),
  };
});
if (shellTabGroups.length) {
  const shellPanels = shellTabGroups.flatMap(group => group.panels);
  const supportedShells = new Set(shellPanels.map(panel => panel.dataset.shell));
  const storageKey = 'unproxy-docs-shell';
  let storedShell;
  try { storedShell = localStorage.getItem(storageKey); } catch { /* Storage can be disabled. */ }

  function shellForHash() {
    try {
      return document.getElementById(decodeURIComponent(location.hash.slice(1)))
        ?.closest('.shell-panel')?.dataset.shell;
    } catch { return undefined; }
  }
  function selectShell(id, focusGroup = null, focus = false, persist = false) {
    if (!supportedShells.has(id)) return;
    shellTabGroups.forEach(group => {
      group.buttons.forEach((button, index) => {
        const selected = group.panels[index].dataset.shell === id;
        button.setAttribute('aria-selected', String(selected));
        button.tabIndex = selected ? 0 : -1;
        if (selected && focus && group === focusGroup) button.focus();
      });
      group.panels.forEach(panel => { panel.hidden = panel.dataset.shell !== id; });
    });
    document.querySelectorAll('.toc a[href^="#"]').forEach(link => {
      const target = document.getElementById(link.hash.slice(1));
      const panel = target?.closest('.shell-panel');
      if (shellPanels.includes(panel)) link.hidden = panel.dataset.shell !== id;
    });
    if (persist) {
      try { localStorage.setItem(storageKey, id); } catch { /* Keep the choice for this page. */ }
    }
  }

  shellTabGroups.forEach(group => {
    group.buttons.forEach((button, index) => {
      button.addEventListener('click', () => {
        selectShell(group.panels[index].dataset.shell, null, false, true);
      });
      button.addEventListener('keydown', event => {
        let next;
        if (event.key === 'ArrowRight') next = (index + 1) % group.buttons.length;
        if (event.key === 'ArrowLeft') next = (index + group.buttons.length - 1) % group.buttons.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = group.buttons.length - 1;
        if (next !== undefined) {
          event.preventDefault();
          selectShell(group.panels[next].dataset.shell, group, true, true);
        }
      });
      group.panels[index].setAttribute('role', 'tabpanel');
      group.panels[index].setAttribute('aria-labelledby', button.id);
    });
  });

  const system = `${navigator.platform} ${navigator.userAgent}`;
  const detected = /Windows|Win32|Win64/i.test(system) ? 'powershell'
    : /Macintosh|MacIntel|Mac OS X/i.test(system) ? 'zsh'
    : /Linux|X11/i.test(system) ? 'bash' : 'bash';
  const initialShell = shellForHash() || (supportedShells.has(storedShell) ? storedShell : detected);
  selectShell(initialShell);
  shellTabGroups.forEach(group => { group.shellTabs.hidden = false; });
  function revealShellHash() {
    const shell = shellForHash();
    if (shell) {
      selectShell(shell);
      const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (shellPanels.includes(target?.closest('.shell-panel'))) target?.scrollIntoView();
    }
  }
  window.addEventListener('hashchange', revealShellHash);
  revealShellHash();
}
