const tabs = [...document.querySelectorAll('[data-view]')];
const mobileTabs = window.matchMedia('(max-width: 800px)');

function updateTabOrientation() {
  document.querySelector('[role="tablist"]').setAttribute(
    'aria-orientation', mobileTabs.matches ? 'horizontal' : 'vertical'
  );
}

updateTabOrientation();
mobileTabs.addEventListener('change', updateTabOrientation);

function selectView(tab, moveFocus = false) {
  for (const candidate of tabs) {
    const selected = candidate === tab;
    candidate.setAttribute('aria-selected', String(selected));
    candidate.tabIndex = selected ? 0 : -1;
    document.getElementById(candidate.getAttribute('aria-controls')).hidden = !selected;
  }
  if (moveFocus) tab.focus();
}

for (const tab of tabs) {
  tab.addEventListener('click', () => selectView(tab));
  tab.addEventListener('keydown', event => {
    const index = tabs.indexOf(tab);
    let next;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index + tabs.length - 1) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next !== undefined) {
      event.preventDefault();
      selectView(tabs[next], true);
    }
  });
}

for (const button of document.querySelectorAll('[data-copy]')) {
  let reset;
  button.addEventListener('click', async () => {
    const source = document.getElementById(button.dataset.copy);
    const status = document.getElementById('copy-status');
    clearTimeout(reset);
    try {
      await navigator.clipboard.writeText(source.textContent.trim());
      button.textContent = 'Copied!';
      status.textContent = 'Installation commands copied to the clipboard.';
    } catch {
      const range = document.createRange();
      range.selectNodeContents(source);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = 'Press Ctrl/Cmd+C';
      status.textContent = 'Commands selected. Press Control C or Command C to copy.';
    }
    reset = setTimeout(() => { button.textContent = 'Copy commands'; }, 3500);
  });
}
