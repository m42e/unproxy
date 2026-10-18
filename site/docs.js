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
