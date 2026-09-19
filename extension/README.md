# Fin-Guardian Scam Detector (Chrome extension)

A Manifest V3 browser extension that highlights financial-crime language and Ethereum wallet addresses on the page you are viewing. It is a standalone JavaScript project and does not use the Python Fin-Guardian app.

## Load it in Chrome

1. Open Chrome and go to `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked**.
4. Select this `extension` folder (the folder that contains `manifest.json`).
5. Pin **Fin-Guardian Scam Detector** from the puzzle-piece menu if you want the icon always visible.

Open any web page, then click the extension icon. The popup shows how many indicators were found. Matching words and `0x` wallets are marked with a light red highlight. Hover a highlight to see why it was flagged.

## Icon

`icon.png` is a generated 128×128 placeholder. Replace it with a real product icon if you want a custom look, then click **Reload** on the extension card in `chrome://extensions`.

## Permissions

- `activeTab` and `scripting` — as requested for a page-based detector
- `storage` — required so the content script can save `finGuardianMatches` and the popup can read that count
