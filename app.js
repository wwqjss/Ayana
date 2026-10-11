/* TOC scrollspy */
(function () {
  const links = Array.from(document.querySelectorAll(".toc a[href^='#']"));
  const map = new Map();
  links.forEach((a) => {
    const id = a.getAttribute("href").slice(1);
    const el = document.getElementById(id);
    if (el) map.set(el, a);
  });
  if (!map.size) return;

  let active = null;
  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((e) => e.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      if (!visible.length) return;
      const link = map.get(visible[0].target);
      if (!link || link === active) return;
      if (active) active.classList.remove("active");
      link.classList.add("active");
      active = link;
    },
    { rootMargin: "-15% 0px -65% 0px", threshold: [0, 0.25, 0.5, 1] }
  );

  map.forEach((_, el) => observer.observe(el));
  // 首屏点亮第一个
  if (links[0]) {
    links[0].classList.add("active");
    active = links[0];
  }
})();
