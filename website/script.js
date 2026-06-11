const root = document.documentElement;
const themeToggle = document.querySelector('.theme-toggle');
const themeToggleText = document.querySelector('.theme-toggle-text');
const copyButtons = document.querySelectorAll('[data-copy-target]');

const getPreferredTheme = () => {
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light' || savedTheme === 'dark') return savedTheme;
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
};

const applyTheme = (theme) => {
  root.dataset.theme = theme;
  localStorage.setItem('theme', theme);

  if (!themeToggle) return;
  const isDark = theme === 'dark';
  themeToggle.setAttribute('aria-pressed', String(isDark));
  themeToggle.setAttribute('aria-label', `Switch to ${isDark ? 'light' : 'dark'} theme`);
  if (themeToggleText) themeToggleText.textContent = isDark ? 'Dark' : 'Light';
};

applyTheme(getPreferredTheme());

themeToggle?.addEventListener('click', () => {
  const nextTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(nextTheme);
});

copyButtons.forEach((button) => {
  const defaultText = button.textContent;
  button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;

    try {
      await navigator.clipboard.writeText(target.textContent.trim());
      button.textContent = 'Copied';
      setTimeout(() => {
        button.textContent = defaultText;
      }, 1400);
    } catch {
      button.textContent = 'Select command to copy';
      setTimeout(() => {
        button.textContent = defaultText;
      }, 1800);
    }
  });
});
