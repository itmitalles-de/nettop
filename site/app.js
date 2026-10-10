const root = document.documentElement;
// Keep existing visitor preferences across the product rename on the same origin.
const STORAGE = { theme: 'nettop-theme', lang: 'nettop-lang' };

function writeStored(key, value) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage may be unavailable; the choice then lasts for this page view only.
  }
}

// English is the source text in index.html; German replaces it at runtime.
const UI = {
  en: {
    title: 'nwtop — your network, in view',
    description: 'nwtop is a Linux terminal network monitor inspired by nvtop. Live interface graphs, process traffic and keyboard-first setup, in one compact view.',
    copyCommands: 'Copy commands',
    copied: 'Copied!',
    pressCopy: 'Press Ctrl/Cmd+C',
    copiedStatus: 'Installation commands copied to the clipboard.',
    selectedStatus: 'Commands selected. Press Control C or Command C to copy.',
    toLight: 'Switch to light theme',
    toDark: 'Switch to dark theme',
    lightOn: 'Light theme on.',
    darkOn: 'Dark theme on.',
    languageOn: 'English language on.',
    otherLanguage: { code: 'DE', lang: 'de', label: 'Auf Deutsch umschalten' },
  },
  de: {
    title: 'nwtop — dein Netzwerk im Blick',
    description: 'nwtop ist ein Netzwerkmonitor für das Linux-Terminal, inspiriert von nvtop. Live-Graphen der Schnittstellen, Traffic pro Prozess und Einrichtung per Tastatur, in einer kompakten Ansicht.',
    copyCommands: 'Befehle kopieren',
    copied: 'Kopiert!',
    pressCopy: 'Strg/Cmd+C drücken',
    copiedStatus: 'Installationsbefehle in die Zwischenablage kopiert.',
    selectedStatus: 'Befehle markiert. Zum Kopieren Strg+C oder Cmd+C drücken.',
    toLight: 'Zum hellen Design wechseln',
    toDark: 'Zum dunklen Design wechseln',
    lightOn: 'Helles Design aktiv.',
    darkOn: 'Dunkles Design aktiv.',
    languageOn: 'Deutsche Sprache aktiv.',
    otherLanguage: { code: 'EN', lang: 'en', label: 'Switch to English' },
  },
};

const DE = {
  skip: 'Zum Inhalt springen',
  homeLabel: 'nwtop Startseite',
  navLabel: 'Hauptnavigation',
  navInside: 'Blick in nwtop',
  navInstall: 'Installation',
  intro: '<span class="status-dot" aria-hidden="true"></span>Zu Hause in deinem Terminal.',
  heroTitle: 'Dein Netz.<br>Klar im Blick.',
  heroDescription: 'Sieh, was fließt. Finde, was ausgelastet ist. Ein Netzwerkmonitor für Linux mit Live-Graphen, Traffic pro Prozess und dem vertrauten Gefühl von htop und nvtop.',
  getNwtop: 'nwtop holen <span aria-hidden="true">↗</span>',
  closerLook: 'Genauer hinsehen',
  heroFacts: 'Gebaut in Rust <span aria-hidden="true">/</span> Gemacht für Linux <span aria-hidden="true">/</span> GPLv3-Lizenz',
  receive: '<i class="rx-dot" aria-hidden="true"></i>Empfangen',
  send: '<i class="tx-dot" aria-hidden="true"></i>Senden',
  compactView: 'Eine kompakte Ansicht.',
  heroAlt: 'Echte nwtop-Demo: grüner Empfangs- und gelber Sendeverlauf über der Tabelle mit Prozess-Traffic',
  demoCaption: 'Echte Terminalausgabe. Demodaten.',
  watchRun: 'Im Einsatz ansehen <span aria-hidden="true">▷</span>',
  capabilitiesLabel: 'Überwachungsfunktionen',
  signal1Title: 'Der Schnittstelle folgen.',
  signal1Text: 'RX und TX aus den Zählern des Linux-Kernels.',
  signal2Title: 'Den Prozess finden.',
  signal2Text: 'Mitgeschnittener Traffic, zugeordnet zu den Socket-Besitzern.',
  signal3Title: 'Auf der Tastatur bleiben.',
  signal3Text: 'Suchen, sortieren, wechseln. Die Hände bleiben, wo sie sind.',
  insideTitle: 'Fühlt sich vertraut an.<br>Passt in deinen Workflow.',
  insideText: 'Im geteilten Fenster oder im Vollbild: nwtop schafft Platz für den Traffic, der zählt, bis hinunter zu einem Terminal mit 36 × 16 Zeichen.',
  tablistLabel: 'nwtop-Ansichten erkunden',
  'tab-monitor-title': 'Der Monitor',
  'tab-monitor-text': 'Traffic oben. Prozesse darunter.',
  'tab-setup-title': 'Nach deinem Geschmack',
  'tab-setup-text': 'Farben, Graphen, Einheiten und mehr.',
  'tab-sort-title': 'Finde die Fleißigen',
  'tab-sort-text': 'Sortierung wählen. Den Bytes folgen.',
  explorerHint: 'Wähle eine Ansicht, um die echte Oberfläche zu sehen.',
  shortcut1: '<kbd>/</kbd> Tabelle durchsuchen',
  shortcut2: '<kbd>c</kbd> Verbindungen untersuchen',
  shortcut3: '<kbd>b</kbd> Bytes / Bits umschalten',
  shortcut4: '<kbd>F12</kbd> Einstellungen speichern',
  monitorAlt: 'nwtop-Monitor im DEMO-Modus mit Traffic-Graphen und Prozesszeilen',
  setupAlt: 'Echtes F2-Setup mit den Kategorien General, Interface, Chart und Processes',
  sortAlt: 'Echtes F6-Sortiermenü mit Auswahl nach Traffic, RX, TX, Gesamt, PID und Befehl',
  screenCaption: 'Native Terminalfarben. Dein Theme kommt mit.',
  installTitle: 'Einmal einrichten.<br>Dann einfach nwtop.',
  installText: 'Aus dem Quellcode bauen, in dein Benutzerverzeichnis installieren und dem optionalen Capture-Helfer die nötigen Rechte geben. Danach startest du <code>nwtop</code> als normaler Benutzer.',
  requirements: 'Du brauchst Linux und Rust 1.88+. Die Befehle hier gelten für Ubuntu 24.04 oder neuer.',
  adminSummary: 'Wofür sind Administratorrechte nötig?',
  adminText: 'Die Installation von libpcap und die Einrichtung des Capture-Helfers erfordern einmalig eine Authentifizierung als Administrator. Die Terminal-Oberfläche hat keine Capabilities und läuft ohne sudo. Die Schnittstellenzähler funktionieren auch ohne den Helfer.',
  captureLink: 'Lies, wie der Mitschnitt funktioniert',
  accessNote: 'Open Source unter der GNU GPLv3 oder neuer. Zum Klonen ist kein GitHub-Konto nötig.',
  installHeading: 'Aus dem Quellcode installieren',
  copyCommands: 'Befehle kopieren',
  commentRuntime: '# Capture-Laufzeit + Capability-Werkzeuge',
  commentNoSudo: '# Ab jetzt ohne sudo',
  noCaptureText: 'Schnittstellen-Monitoring ohne Einrichtung.',
  detailsTitle: 'Echte Zähler.<br>Klare Grenzen.',
  detailsText1: 'Schnittstellenraten stammen aus den RX/TX-Zählern von Linux. Prozessraten stammen aus mitgeschnittenen IP-Paketen, zugeordnet zu Socket-Inodes und PIDs. Warteschlangengrößen werden nie als Traffic ausgegeben.',
  detailsText2: 'Kurzlebige, geteilte oder unzugängliche Sockets können ohne Zuordnung bleiben. nwtop zeigt nicht verfügbare Raten und verworfene Pakete an, statt Zahlen zu erfinden.',
  measurementsLink: 'Die Messwerte verstehen',
  videoLabel: 'Echte nwtop-DEMO-Aufnahme mit Monitor, F2-Setup und F6-Sortierung',
  videoCaption: 'Monitor, F2-Setup und F6-Sortierung in einer echten Terminalaufnahme. Synthetischer DEMO-Traffic.',
  closingTitle: 'Ein kleines Fenster<br>in dein Netzwerk.',
  makeRoom: 'Platz für nwtop schaffen <span aria-hidden="true">↗</span>',
  topLabel: 'Zurück nach oben',
  madeBy: 'Gemacht von <a href="https://itmitalles.de">itmitalles</a>. Inspiriert von <a href="https://github.com/htop-dev/htop">htop</a> und <a href="https://github.com/Syllo/nvtop">nvtop</a>.',
  sourceDocs: 'Quellcode &amp; Dokumentation',
};

const textNodes = [...document.querySelectorAll('[data-i18n]')].map(element => ({
  element, key: element.dataset.i18n, en: element.innerHTML,
}));
const attrNodes = [...document.querySelectorAll('[data-i18n-attr]')].flatMap(element =>
  element.dataset.i18nAttr.split(';').map(pair => {
    const [attr, key] = pair.split(':');
    return { element, attr, key, en: element.getAttribute(attr) };
  })
);
const descriptionMeta = document.querySelector('meta[name="description"]');
const languageToggle = document.getElementById('language-toggle');
const themeToggle = document.getElementById('theme-toggle');
const statusRegion = document.getElementById('copy-status');
let currentLang = root.dataset.lang === 'de' ? 'de' : 'en';

const t = key => UI[currentLang][key];

function applyLanguage(lang) {
  currentLang = lang;
  root.lang = lang;
  root.dataset.lang = lang;
  for (const node of textNodes) {
    node.element.innerHTML = (lang === 'de' && DE[node.key]) || node.en;
  }
  for (const node of attrNodes) {
    node.element.setAttribute(node.attr, (lang === 'de' && DE[node.key]) || node.en);
  }
  document.title = t('title');
  descriptionMeta.setAttribute('content', t('description'));
  const other = t('otherLanguage');
  languageToggle.textContent = other.code;
  languageToggle.lang = other.lang;
  languageToggle.setAttribute('aria-label', other.label);
  languageToggle.title = other.label;
  updateThemeControl();
  root.classList.remove('i18n-pending');
}

languageToggle.addEventListener('click', () => {
  const lang = currentLang === 'de' ? 'en' : 'de';
  writeStored(STORAGE.lang, lang);
  applyLanguage(lang);
  statusRegion.textContent = t('languageOn');
});

const systemLight = window.matchMedia('(prefers-color-scheme: light)');
const themeMetas = [...document.querySelectorAll('meta[name="theme-color"]')].map(meta => ({
  meta, content: meta.getAttribute('content'),
}));
const THEME_COLORS = { dark: '#0b1725', light: '#f4f7f2' };

const systemTheme = () => (systemLight.matches ? 'light' : 'dark');
const effectiveTheme = () => root.dataset.theme || systemTheme();

function updateThemeControl() {
  const label = effectiveTheme() === 'dark' ? t('toLight') : t('toDark');
  themeToggle.setAttribute('aria-label', label);
  themeToggle.title = label;
  for (const { meta, content } of themeMetas) {
    meta.setAttribute('content', root.dataset.theme ? THEME_COLORS[root.dataset.theme] : content);
  }
}

// The toggle always flips the visible theme. Picking the system theme again
// removes the override, so the page keeps following the operating system.
themeToggle.addEventListener('click', () => {
  const theme = effectiveTheme() === 'dark' ? 'light' : 'dark';
  if (theme === systemTheme()) {
    delete root.dataset.theme;
    writeStored(STORAGE.theme, null);
  } else {
    root.dataset.theme = theme;
    writeStored(STORAGE.theme, theme);
  }
  updateThemeControl();
  statusRegion.textContent = theme === 'light' ? t('lightOn') : t('darkOn');
});
systemLight.addEventListener('change', updateThemeControl);

applyLanguage(currentLang);

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
      button.textContent = t('copied');
      status.textContent = t('copiedStatus');
    } catch {
      const range = document.createRange();
      range.selectNodeContents(source);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = t('pressCopy');
      status.textContent = t('selectedStatus');
    }
    reset = setTimeout(() => { button.textContent = t('copyCommands'); }, 3500);
  });
}
