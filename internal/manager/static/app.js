document.addEventListener('submit', function (e) {
  var m = e.target.getAttribute('data-confirm');
  if (m && !window.confirm(m)) e.preventDefault();
});
document.addEventListener('change', function (e) {
  var t = e.target;
  if (t.hasAttribute && t.hasAttribute('data-autosubmit') && t.form) t.form.submit();
});
document.addEventListener('click', function (e) {
  var t = e.target.closest ? e.target.closest('[data-print]') : null;
  if (t) { e.preventDefault(); window.print(); }
});
// Stats: report type picks the form action; "custom" period shows the date fields; bar widths come from data attributes (CSP forbids inline styles)
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.bar-fill[data-pct]').forEach(function (el) { el.style.width = el.getAttribute('data-pct') + '%'; });
  var form = document.getElementById('rep');
  if (!form) return;
  var type = document.getElementById('rtype'), preset = document.getElementById('preset'), custom = document.getElementById('custom');
  function sync() { form.action = '/stats/report/' + type.value; custom.classList.toggle('hidden', preset.value !== 'custom'); }
  type.addEventListener('change', sync); preset.addEventListener('change', sync); sync();
  form.addEventListener('submit', function (e) {
    var b = e.submitter, f = form.querySelector('input[name=format]');
    if (!f) { f = document.createElement('input'); f.type = 'hidden'; f.name = 'format'; form.appendChild(f); }
    f.value = b && b.getAttribute('data-report') === 'csv' ? 'csv' : 'html';
    form.querySelectorAll('input[name=limit]').forEach(function (i) { if (!i.value) i.disabled = true; });
  });
});
