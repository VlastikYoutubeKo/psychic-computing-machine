// Deliberately tiny: the admin is server-rendered PHP forms, not an SPA.
// This only handles the couple of things that genuinely need the client.
document.addEventListener('click', function (e) {
  const copyBtn = e.target.closest('[data-copy]');
  if (copyBtn) {
    const text = copyBtn.getAttribute('data-copy');
    navigator.clipboard.writeText(text).then(function () {
      const original = copyBtn.textContent;
      copyBtn.textContent = 'Copied!';
      setTimeout(function () { copyBtn.textContent = original; }, 1200);
    });
  }
});

document.addEventListener('submit', function (e) {
  const form = e.target.closest('form[data-confirm]');
  if (form && !window.confirm(form.getAttribute('data-confirm'))) {
    e.preventDefault();
  }
});
