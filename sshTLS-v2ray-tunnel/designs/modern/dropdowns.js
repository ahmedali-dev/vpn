'use strict';
// Native selects remain hidden form models; every visible control is a styled listbox.
(() => {
  const items = new Map();
  const close = item => {item.menu.hidden = true; item.trigger.setAttribute('aria-expanded','false'); item.wrap.classList.remove('menuOpen');};
  const closeAll = except => {
    for (const item of items.values()) {
      if (item === except) continue;
      item.menu.hidden = true;
      item.trigger.setAttribute('aria-expanded', 'false');
      item.wrap.classList.remove('menuOpen');
    }
  };
  function create(select) {
    if (items.has(select) || select.multiple) return;
    if (!select.id) select.id = 'tunnelnest-select-' + (items.size + 1);
    const parent = select.parentElement;
    const wrap = document.createElement('div'); wrap.className = 'customSelect';
    parent.insertBefore(wrap, select); wrap.append(select);
    select.hidden = true; select.tabIndex = -1; select.setAttribute('aria-hidden', 'true');
    const trigger = document.createElement('button'); trigger.type = 'button'; trigger.className = 'selectTrigger';
    trigger.id = select.id + '-trigger'; trigger.setAttribute('aria-haspopup', 'listbox'); trigger.setAttribute('aria-expanded', 'false');
    const value = document.createElement('span'); value.className = 'selectValue';
    const chevron = document.createElement('span'); chevron.className = 'selectChevron'; chevron.textContent = '⌄'; chevron.setAttribute('aria-hidden', 'true');
    trigger.append(value, chevron);
    const menu = document.createElement('div'); menu.className = 'selectMenu'; menu.id = select.id + '-menu'; menu.hidden = true;
    menu.setAttribute('role', 'listbox'); trigger.setAttribute('aria-controls', menu.id);
    const label = select.getAttribute('aria-label') || [...(select.labels || [])].map(el =>
      [...el.childNodes].filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent.trim()).join(' ')
    ).join(' ').trim() || 'Choose an option';
    menu.setAttribute('aria-label', label);
    const item = {select, wrap, trigger, value, menu, options: [], signature: '', search: '', lastKey: 0};
    items.set(select, item); wrap.append(trigger, menu);
    const enabled = () => item.options.filter(button => !button.disabled);
    const focusIndex = index => {
      const target = item.options[index];
      if (target && !target.disabled) { target.focus({preventScroll:true}); target.scrollIntoView({block:'nearest'}); }
    };
    const choose = index => {
      if (select.disabled || item.options[index]?.disabled) return;
      select.selectedIndex = index;
      select.dispatchEvent(new Event('input', {bubbles:true}));
      select.dispatchEvent(new Event('change', {bubbles:true}));
      sync(); closeAll(); trigger.focus();
    };
    function sync() {
      const options = [...select.options];
      const signature = JSON.stringify(options.map(option => [option.text, option.value, option.disabled, option.parentElement.disabled || false]));
      const previousFocus = item.options.indexOf(document.activeElement);
      if (signature !== item.signature) {
        item.signature = signature; item.options = []; menu.replaceChildren();
        options.forEach((option,index) => {
          const button = document.createElement('button'); button.type = 'button'; button.className = 'selectOption';
          button.id = select.id + '-option-' + index; button.setAttribute('role','option'); button.tabIndex = -1;
          button.disabled = option.disabled || !!option.parentElement.disabled;
          button.textContent = option.text; button.addEventListener('click', () => choose(index));
          item.options.push(button); menu.append(button);
        });
      }
      const selected = options[select.selectedIndex];
      value.textContent = selected?.text || (options.length ? 'Choose an option' : 'No options available');
      trigger.setAttribute('aria-label', label + ': ' + value.textContent);
      trigger.disabled = select.disabled || !enabled().length;
      item.options.forEach((button,index) => button.setAttribute('aria-selected', String(index === select.selectedIndex)));
      if (trigger.disabled) close(item);
      else if (!menu.hidden && previousFocus >= 0 && document.activeElement !== item.options[previousFocus]) focusIndex(Math.min(previousFocus, item.options.length - 1));
    }
    item.sync = sync;
    function open(position) {
      sync(); if (trigger.disabled) return;
      closeAll(item); menu.hidden = false; wrap.classList.add('menuOpen'); trigger.setAttribute('aria-expanded','true');
      const rect = trigger.getBoundingClientRect(), dialog = trigger.closest('dialog');
      const bounds = dialog ? dialog.getBoundingClientRect() : {top:0, bottom:innerHeight};
      const below = Math.min(innerHeight, bounds.bottom) - rect.bottom - 12, above = rect.top - Math.max(0,bounds.top) - 12;
      const upward = below < Math.min(240,menu.scrollHeight) && above > below;
      menu.classList.toggle('above',upward);
      menu.style.maxHeight = Math.max(65,Math.min(260,upward ? above : below)) + 'px';
      const available = enabled();
      const first = item.options.indexOf(available[0]), last = item.options.indexOf(available[available.length-1]);
      focusIndex(position === 'last' ? last : position === 'first' ? first : select.selectedIndex >= 0 && !item.options[select.selectedIndex].disabled ? select.selectedIndex : first);
    }
    trigger.addEventListener('click', () => menu.hidden ? open() : closeAll());
    wrap.addEventListener('keydown', event => {
      const available = enabled(), focused = available.indexOf(document.activeElement);
      if (event.key === 'Escape' && !menu.hidden) {
        event.preventDefault(); event.stopPropagation(); closeAll(); trigger.focus(); return;
      }
      if (event.key === 'Tab' && !menu.hidden) { closeAll(); trigger.focus(); return; }
      if (['ArrowDown','ArrowUp','Home','End'].includes(event.key)) {
        event.preventDefault();
        if (menu.hidden) { open(event.key === 'End' || event.key === 'ArrowUp' ? 'last' : event.key === 'Home' ? 'first' : undefined); return; }
        const index = event.key === 'Home' ? 0 : event.key === 'End' ? available.length - 1 : (focused + (event.key === 'ArrowDown' ? 1 : -1) + available.length) % available.length;
        available[index]?.focus(); return;
      }
      if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey && event.key !== ' ') {
        event.preventDefault();
        const now = Date.now(); item.search = now - item.lastKey > 700 ? event.key : item.search + event.key; item.lastKey = now;
        if (menu.hidden) open();
        const match = available.find(button => button.textContent.toLocaleLowerCase().startsWith(item.search.toLocaleLowerCase()));
        match?.focus();
      }
    });
    wrap.addEventListener('focusout', event => {if (event.relatedTarget && !wrap.contains(event.relatedTarget)) close(item);});
    select.addEventListener('change',sync);
    select.form?.addEventListener('reset', () => setTimeout(sync,0));
    new MutationObserver(sync).observe(select,{childList:true,subtree:true,characterData:true,attributes:true,attributeFilter:['disabled','label','selected','value']});
    sync();
  }
  const init = () => document.querySelectorAll('select').forEach(create);
  document.addEventListener('click',event => {if (!event.target.closest('.customSelect')) closeAll();});
  document.addEventListener('cancel',event => {
    const item = [...items.values()].find(item => !item.menu.hidden && event.target.contains(item.wrap));
    if (item) {event.preventDefault();closeAll();item.trigger.focus();}
  },true);
  window.addEventListener('resize',() => closeAll());
  globalThis.TunnelNestDropdowns = Object.freeze({init,refresh(){init();for(const item of items.values()) item.sync();},closeAll});
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',init,{once:true}); else init();
})();
