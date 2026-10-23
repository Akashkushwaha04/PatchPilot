// Lightweight search page script for the static landing page.
const params = new URLSearchParams(window.location.search);
const query = params.get("q") || "";

const heading = document.getElementById("search-heading");
const strong = document.createElement("b");
strong.textContent = query;
heading.replaceChildren("Results for ", strong);

fetch("/api/products/search?q=" + encodeURIComponent(query))
  .then((r) => r.json())
  .then((items) => {
    const list = document.getElementById("results");
    list.textContent = items.length ? "" : "No products found.";
  });
