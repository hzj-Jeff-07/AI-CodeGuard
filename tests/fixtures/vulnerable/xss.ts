// Vulnerable: XSS Reflected (CG-010)
function displayMessage(userInput: string) {
  document.getElementById('output')!.innerHTML = userInput;
}

function renderContent(html: string) {
  document.write(html);
}

function setContent(el: Element, data: string) {
  el.outerHTML = data;
}

// Vulnerable: DOM XSS (CG-011)
function processHash() {
  const hash = location.hash;
  document.getElementById('content')!.innerHTML = hash;
}
