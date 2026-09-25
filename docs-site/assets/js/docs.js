document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("#site-nav a").forEach((link) => {
    if (
      link.classList.contains("active") ||
      (link.hasAttribute("href") &&
        new URL(link.getAttribute("href"), location.href).pathname ===
          location.pathname)
    ) {
      link.classList.add("active");
      link.setAttribute("aria-current", "page");
    }
  });
  const outline = document.querySelector(".page-outline");
  if (outline) {
    const headings = document.querySelectorAll(".doc-body h2[id]");
    if (!headings.length) outline.hidden = true;
    const list = document.createElement("ul");
    headings.forEach((heading) => {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = "#" + heading.id;
      link.textContent = heading.textContent.trim();
      item.append(link);
      list.append(item);
    });
    outline.querySelector("nav").append(list);
  }
});
