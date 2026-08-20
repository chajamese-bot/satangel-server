// =========================================================
// Shared page-transition + scroll-reveal system.
// Linked from every page. Handles:
//   1. Fade-in when a page first loads
//   2. Smooth fade-out before navigating to another page on this site
//   3. Elements with class="reveal" rising into view as they scroll in
// Respects prefers-reduced-motion throughout.
// =========================================================
(function(){
  const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---- 1. Fade in on load ----
  function fadeIn(){
    requestAnimationFrame(() => {
      requestAnimationFrame(() => document.body.classList.add('page-loaded'));
    });
  }
  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', fadeIn);
  }else{
    fadeIn();
  }

  // Re-show instantly if the page is restored from the back/forward cache
  window.addEventListener('pageshow', (e) => {
    if(e.persisted){
      document.body.classList.remove('page-leaving');
      document.body.classList.add('page-loaded');
    }
  });

  // ---- 2. Fade out before internal navigation ----
  function isInternalPageLink(a){
    if(!a || !a.getAttribute) return false;
    const href = a.getAttribute('href');
    if(!href) return false;
    if(href.startsWith('#')) return false;       // in-page anchor — let it scroll normally
    if(href.startsWith('mailto:')) return false;
    if(href.startsWith('tel:')) return false;
    if(href.startsWith('http://') || href.startsWith('https://')) return false; // external
    if(a.target === '_blank') return false;
    return href.endsWith('.html') || href === '/' || href === '';
  }

  document.addEventListener('click', (e) => {
    const a = e.target.closest('a');
    if(!isInternalPageLink(a)) return;
    const href = a.getAttribute('href');
    e.preventDefault();
    if(REDUCED){
      window.location.href = href;
      return;
    }
    document.body.classList.remove('page-loaded');
    document.body.classList.add('page-leaving');
    setTimeout(() => { window.location.href = href; }, 200);
  });

  // ---- 3. Scroll-reveal for elements with class="reveal" ----
  function initReveal(){
    const revealEls = document.querySelectorAll('.reveal');
    if(revealEls.length === 0) return;
    if(REDUCED){
      revealEls.forEach(el => el.classList.add('revealed'));
      return;
    }
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if(entry.isIntersecting){
          entry.target.classList.add('revealed');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15, rootMargin: '0px 0px -30px 0px' });
    revealEls.forEach(el => observer.observe(el));
  }
  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', initReveal);
  }else{
    initReveal();
  }
})();
