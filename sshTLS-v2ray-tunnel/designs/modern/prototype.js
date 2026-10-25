'use strict';
(() => {
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  let connected = false, busy = false, filter = 'all', selection = 'Amsterdam';
  const toast = (text) => {
    const el = $('.toast');
    el.textContent = text; el.classList.add('show');
    clearTimeout(toast.timer); toast.timer = setTimeout(() => el.classList.remove('show'), 4000);
  };
  const addLog = (text) => {
    const time = new Date().toLocaleTimeString('en-GB');
    $('#log-lines').textContent += `\n${time}  INFO  ${text}`;
  };
  const updateServers = () => {
    const query = ($('input[type=search]')?.value || '').toLowerCase();
    let count = 0;
    $$('.server').forEach(el => {
      el.hidden = !(filter === 'all' || el.dataset.protocol === filter) || !el.textContent.toLowerCase().includes(query);
      if (!el.hidden) count++;
    });
    $('.empty').hidden = count !== 0;
  };
  document.addEventListener('click', e => {
    const button = e.target.closest('button');
    if (!button) return;
    if (button.hasAttribute('data-connect')) {
      if (busy) return;
      busy = true;
      const next = !connected;
      $$('[data-connect]').forEach(el => el.disabled = true);
      $('[data-status]').textContent = next ? 'Connecting…' : 'Disconnecting…';
      setTimeout(() => {
        connected = next; busy = false;
        document.body.classList.toggle('connected', connected);
        $('[data-status]').textContent = connected ? 'Connected · Demo' : 'Ready to connect';
        $('[data-heading]').textContent = connected ? `Connected to ${selection}.` : 'Your private route is waiting.';
        $$('.connect-cta').forEach(el => {
          el.firstChild.textContent = connected ? 'Disconnect ' : 'Connect now ';
        });
        $$('[data-connect]').forEach(el => {
          el.disabled = false;
          if (!el.classList.contains('connect-cta')) el.setAttribute('aria-label', connected ? 'Disconnect simulated connection' : 'Connect to selected profile');
        });
        addLog(connected ? `Simulated connection established · ${selection} · TLS 1.3` : 'Simulated connection stopped');
        toast(connected ? 'Preview connection active. No VPN traffic is being routed.' : 'Preview connection disconnected.');
      }, 650);
    }
    if (button.hasAttribute('data-routing')) {
      const enabled = button.getAttribute('aria-checked') !== 'true';
      button.setAttribute('aria-checked', String(enabled));
      $('[data-routing-label]').textContent = enabled ? 'Full-device mode · Demo' : 'Proxy mode';
      addLog(enabled ? 'Routing preference: full device (preview only)' : 'Routing preference: local proxy (preview only)');
    }
    if (button.hasAttribute('data-server')) {
      if (busy || connected) { toast('Disconnect the preview before changing profiles.'); return; }
      selection = button.dataset.server;
      $$('.server').forEach(el => {
        const selected = el === button;
        el.classList.toggle('selected', selected); el.setAttribute('aria-pressed', String(selected));
      });
      $$('[data-location]').forEach(el => el.textContent = selection);
      const details = button.querySelector('.server-info small').textContent;
      const detailText = document.querySelector('.sun-connection>p:not(.sun-help)');
      if (detailText) {
        detailText.replaceChildren(button.querySelector('.flag').cloneNode(true), document.createTextNode(' ' + details));
      }
      const darkSelected = $('.dark-selected');
      if (darkSelected) {
        darkSelected.querySelector('.flag').replaceWith(button.querySelector('.flag').cloneNode(true));
        darkSelected.querySelector('.latency').replaceWith(button.querySelector('.latency').cloneNode(true));
      }
      addLog(`Selected profile: ${selection}`);
    }
    if (button.hasAttribute('data-filter')) {
      filter = button.dataset.filter;
      $$('.filters button').forEach(el => el.classList.toggle('active', el === button));
      updateServers();
    }
    if (button.hasAttribute('data-logs')) $('#logs-dialog').showModal();
    if (button.hasAttribute('data-add')) { $('#profile-form').reset(); $('#profile-dialog').showModal(); }
    if (button.hasAttribute('data-close')) button.closest('dialog').close();
    if (button.hasAttribute('data-focus-profiles')) {
      $('#profiles').scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block:'center'});
      $('input[type=search]').focus({preventScroll:true});
    }
    if (button.hasAttribute('data-choose')) {
      const id = button.dataset.choose;
      try { localStorage.setItem('tunnelnest-design-choice', id); } catch (_) {}
      toast(`Design 0${id} selected. Tell me “use design ${id}” in the chat to apply it.`);
      button.firstChild.textContent = 'Selected ';
    }
    if (button.hasAttribute('data-download')) {
      const url = URL.createObjectURL(new Blob([$('#log-lines').textContent], {type:'text/plain'}));
      const a = document.createElement('a'); a.href = url; a.download = 'tunnelnest-design-preview.log'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  });
  $('input[type=search]').addEventListener('input', updateServers);
  document.addEventListener('keydown', e => {
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && !$('dialog[open]')) {
      e.preventDefault(); $('input[type=search]').focus();
    }
  });
  $('#profile-form').addEventListener('submit', e => {
    e.preventDefault();
    const data = new FormData(e.target), name = String(data.get('name')).trim();
    if (!name) return;
    const prototype = $('.server');
    const el = prototype.cloneNode(true);
    el.hidden = false; el.classList.remove('selected'); el.setAttribute('aria-pressed','false');
    el.dataset.server = name; el.dataset.protocol = data.get('protocol');
    $('.server-info strong', el).textContent = name;
    $('.server-info small', el).textContent = data.get('protocol') === 'ssh' ? 'Custom profile · SSH + TLS' : 'Custom profile · VLESS';
    const flag = $('.flag', el); flag.className = 'flag'; flag.textContent = 'TN';
    $('.latency', el).textContent = '— ms';
    $('.server-list').insertBefore(el, $('.empty'));
    const total = $$('.server').length;
    $$('.count, .side-nav button span, .filters button[data-filter=all] span').forEach(el => el.textContent = String(total));
    filter = 'all'; $$('.filters button').forEach(el => el.classList.toggle('active', el.dataset.filter === 'all'));
    $('input[type=search]').value = '';
    updateServers(); $('#profile-dialog').close(); addLog(`Sample profile created: ${name}`);
    toast('Sample profile added to this preview.');
  });
})();
