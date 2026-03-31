// Shared nav — injected on every page via <script src="/nav.js"></script>
// Single source of truth for header + favicon
// All content is static/trusted — authored by us, not user input.
(function () {
  // Inject favicon if missing
  if (!document.querySelector('link[rel="icon"]')) {
    var fav = document.createElement("link");
    fav.rel = "icon";
    fav.href = "https://notme.bot/favicon.svg";
    fav.type = "image/svg+xml";
    document.head.appendChild(fav);
  }

  var nav = document.querySelector("nav");
  if (!nav) return;

  var currentHref = window.location.href.replace(/\/$/, "");

  // Clear existing nav content
  while (nav.firstChild) nav.removeChild(nav.firstChild);

  // Build logo
  var logo = document.createElement("a");
  logo.href = "https://notme.bot";
  logo.className = "logo";

  var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "logo-mark");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("fill", "none");
  svg.setAttribute("width", "32");
  svg.setAttribute("height", "32");

  var rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  rect.setAttribute("x", "4");
  rect.setAttribute("y", "4");
  rect.setAttribute("width", "24");
  rect.setAttribute("height", "24");
  rect.setAttribute("rx", "2");
  rect.setAttribute("stroke", "#F0D040");
  rect.setAttribute("stroke-width", "2.5");
  rect.setAttribute("fill", "none");
  svg.appendChild(rect);

  var line = document.createElementNS("http://www.w3.org/2000/svg", "line");
  line.setAttribute("x1", "10");
  line.setAttribute("y1", "10");
  line.setAttribute("x2", "22");
  line.setAttribute("y2", "22");
  line.setAttribute("stroke", "#E04030");
  line.setAttribute("stroke-width", "3");
  line.setAttribute("stroke-linecap", "round");
  svg.appendChild(line);

  logo.appendChild(svg);

  var logoText = document.createElement("span");
  logoText.className = "logo-text";
  logoText.textContent = "notme";
  logo.appendChild(logoText);

  nav.appendChild(logo);

  // Build links
  var linksDiv = document.createElement("div");
  linksDiv.className = "nav-links";

  var base = "https://notme.bot";
  var links = [
    { href: base + "/apas", text: "apas" },
    { href: base + "/architecture", text: "how_it_works" },
    { href: base + "/research", text: "research" },
    { href: "https://auth.notme.bot", text: "auth" },
    { href: "https://github.com/agentic-research/signet", text: "source" },
  ];

  for (var i = 0; i < links.length; i++) {
    var a = document.createElement("a");
    a.href = links[i].href;
    a.textContent = links[i].text;
    if (currentHref === links[i].href || currentHref.startsWith(links[i].href + "/")) a.className = "active";
    linksDiv.appendChild(a);
  }

  nav.appendChild(linksDiv);
})();
