"use strict";
document.getElementById("add").addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = "/demo/landing.html";
  link.textContent = "https://campus.example";
  const paragraph = document.createElement("p");
  paragraph.appendChild(link);
  document.getElementById("dynamic").appendChild(paragraph);
});
document.getElementById("change").addEventListener("click", () => {
  document.getElementById("ordinary").textContent = "https://campus.example";
});
