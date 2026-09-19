(() => {
  const KEYWORDS = [
    "clean cash",
    "no kyc",
    "cashout",
    "mule",
    "washing",
    "обнал",
    "дроп",
    "залив",
    "вывод",
    "работа для студентов",
  ];

  const FLAG_CLASS = "fin-guardian-flag";
  const SKIP_TAGS = new Set([
    "SCRIPT",
    "STYLE",
    "NOSCRIPT",
    "TEXTAREA",
    "INPUT",
    "SELECT",
    "OPTION",
    "CODE",
    "PRE",
  ]);

  const keywordPattern = KEYWORDS
    .slice()
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp)
    .join("|");

  const MATCH_RE = new RegExp(
    `(${keywordPattern}|\\b0x[a-fA-F0-9]{40}\\b)`,
    "gi"
  );

  const WALLET_RE = /\b0x[a-fA-F0-9]{40}\b/i;

  function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function tooltipFor(match) {
    if (WALLET_RE.test(match)) {
      return "Fin-Guardian: flagged Ethereum wallet address";
    }
    return "Fin-Guardian: flagged financial-crime language";
  }

  function collectTextNodes(root) {
    const nodes = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (SKIP_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
        if (parent.closest(`.${FLAG_CLASS}`)) return NodeFilter.FILTER_REJECT;
        if (!node.nodeValue || !node.nodeValue.trim()) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    let current = walker.nextNode();
    while (current) {
      nodes.push(current);
      current = walker.nextNode();
    }
    return nodes;
  }

  function highlightTextNode(node) {
    const text = node.nodeValue;
    MATCH_RE.lastIndex = 0;
    if (!MATCH_RE.test(text)) return 0;

    MATCH_RE.lastIndex = 0;
    const fragment = document.createDocumentFragment();
    let lastIndex = 0;
    let count = 0;
    let found;

    while ((found = MATCH_RE.exec(text)) !== null) {
      if (found.index > lastIndex) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex, found.index)));
      }
      const mark = document.createElement("span");
      mark.className = FLAG_CLASS;
      mark.textContent = found[0];
      mark.title = tooltipFor(found[0]);
      mark.style.backgroundColor = "rgba(248, 113, 113, 0.35)";
      mark.style.boxShadow = "inset 0 -1px 0 rgba(239, 68, 68, 0.45)";
      mark.style.borderRadius = "2px";
      mark.style.padding = "0 1px";
      mark.style.color = "inherit";
      mark.style.display = "inline";
      fragment.appendChild(mark);
      count += 1;
      lastIndex = found.index + found[0].length;
    }

    if (lastIndex < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }

    node.parentNode.replaceChild(fragment, node);
    return count;
  }

  function scanPage() {
    if (!document.body) return 0;
    let total = 0;
    for (const node of collectTextNodes(document.body)) {
      if (!node.isConnected) continue;
      total += highlightTextNode(node);
    }
    return total;
  }

  function saveCount(count) {
    try {
      chrome.storage.local.set({ finGuardianMatches: count });
    } catch (_err) {
      // Extension context can be unavailable on some pages.
    }
  }

  const matchCount = scanPage();
  saveCount(matchCount);
})();
