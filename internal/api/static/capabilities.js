// capabilities.js — capability-aware UI helper
// Contract:
//   - Fetches /api/v1/system/capabilities once on DOMContentLoaded.
//   - For each tool in the JSON response, hides elements with data-requires-tool="<tool>" if tool is false.
//   - Supports comma-separated tool lists: element is hidden only if ALL listed tools are missing.
//   - Fails open: if fetch fails, do nothing (no elements hidden).
//   - No global exports — pure side effects via IIFE.
// How to use in index.html:
//   1. Add <script src="/static/capabilities.js" defer></script> just before </body>.
//   2. For any UI element that should appear only when its tool is available, add data-requires-tool="toolname".
//   3. Example: <button data-requires-tool="borg">Backup Now</button>

(async () => {
  if (document.readyState !== 'loading') {
    // DOM already loaded — proceed immediately
    await initCapabilities();
  } else {
    document.addEventListener('DOMContentLoaded', initCapabilities);
  }

  async function initCapabilities() {
    try {
      const res = await fetch('/api/v1/system/capabilities');
      if (!res.ok) {
        console.warn(`[capabilities] fetch failed: HTTP ${res.status}`);
        return;
      }

      const data = await res.json();
      if (typeof data !== 'object' || !data) return;

      const tools = Object.keys(data);
      const missingTools = tools.filter(tool => data[tool] === false);

      missingTools.forEach(tool => {
        const selector = `[data-requires-tool~="${tool}"]`;
        document.querySelectorAll(selector).forEach(el => {
          el.hidden = true;
          el.classList.add('tool-missing');
        });
      });

      // Handle comma-separated lists: hide if ALL listed tools are missing
      document.querySelectorAll('[data-requires-tool]').forEach(el => {
        const raw = el.getAttribute('data-requires-tool');
        if (!raw) return;
        const list = raw.split(',').map(t => t.trim()).filter(Boolean);
        const allMissing = list.every(tool => missingTools.includes(tool));
        if (allMissing) {
          el.hidden = true;
          el.classList.add('tool-missing');
        }
      });

    } catch (e) {
      console.warn(`[capabilities] fetch error:`, e);
    }
  }
})();
