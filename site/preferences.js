// Runs synchronously in <head> so the stored theme and language apply before first paint.
(function () {
  var root = document.documentElement;
  var theme = null;
  var lang = null;
  try {
    theme = localStorage.getItem('nettop-theme');
    lang = localStorage.getItem('nettop-lang');
  } catch (error) {
    // Storage can be unavailable (private mode, blocked site data); fall back to system preferences.
  }
  if (theme === 'light' || theme === 'dark') root.setAttribute('data-theme', theme);
  if (lang !== 'en' && lang !== 'de') {
    lang = 'en';
    var languages = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || 'en'];
    for (var i = 0; i < languages.length; i++) {
      var code = String(languages[i]).toLowerCase();
      if (code.indexOf('de') === 0) { lang = 'de'; break; }
      if (code.indexOf('en') === 0) break;
    }
  }
  root.classList.add('js');
  if (lang === 'de') {
    // Hide the English source text until app.js has translated it; never keep the page hidden for long.
    root.classList.add('i18n-pending');
    setTimeout(function () { root.classList.remove('i18n-pending'); }, 1500);
  }
  root.setAttribute('data-lang', lang);
}());
