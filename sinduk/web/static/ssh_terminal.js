/**
 * ssh_terminal.js
 *
 * Augments the SSH terminal modal with:
 *   - Full-screen toggle  (button + F11 keyboard shortcut)
 *   - Font-size controls  (A− / A+ buttons, persisted to localStorage)
 *   - Copy output button  (copies raw terminal text to clipboard)
 *
 * Requires app.js to be loaded first (uses S, showToast, and the
 * openSSHModal / closeSSHModal / showSSHTerminal / hideSSHTerminal globals).
 *
 * No external dependencies.
 */

// ─── State ───────────────────────────────────────────────────────────────────

/** Default terminal font size in px. */
const TERM_FONT_DEFAULT = 13;

/** Minimum / maximum allowed font size in px. */
const TERM_FONT_MIN = 10;
const TERM_FONT_MAX = 22;

/** localStorage key for persisting font size. */
const TERM_FONT_KEY = 'sinduk.termFontSize';

// Attach to the shared state object created in app.js so other parts of
// the codebase can inspect these values if needed.
S.termFontSize = _loadFontSize();
S.sshFullscreen = false;

// ─── Font helpers ─────────────────────────────────────────────────────────────

/**
 * Read the persisted font size from localStorage.
 * Falls back to TERM_FONT_DEFAULT if nothing is stored or the stored value
 * is outside the valid range.
 *
 * @returns {number} Font size in px.
 */
function _loadFontSize() {
    try {
        const stored = Number.parseInt(localStorage.getItem(TERM_FONT_KEY) || localStorage.getItem('pacli.termFontSize'), 10);
        if (!Number.isNaN(stored) && stored >= TERM_FONT_MIN && stored <= TERM_FONT_MAX) {
            return stored;
        }
    } catch (e) {
        console.log('Failed to read terminal font size from localStorage, using default:', e);
    }
    return TERM_FONT_DEFAULT;
}

/**
 * Persist the current font size to localStorage.
 */
function _saveFontSize() {
    try {
        localStorage.setItem(TERM_FONT_KEY, String(S.termFontSize));
    } catch (e) {
        console.log('Failed to save terminal font size to localStorage: ', e);
    }
}

/**
 * Apply S.termFontSize to the relevant terminal DOM elements.
 * Safe to call before the terminal is rendered — missing elements are skipped.
 */
function _applyTerminalFont() {
    const size = S.termFontSize + 'px';
    const targets = [
        document.getElementById('ssh-output'),
        document.getElementById('ssh-cmd'),
        document.querySelector('.ssh-prompt'),
    ];
    targets.forEach((el) => {
        if (el) el.style.fontSize = size;
    });
}

/**
 * Increase or decrease the terminal font size by `delta` px,
 * clamped to [TERM_FONT_MIN, TERM_FONT_MAX].
 *
 * @param {number} delta - Positive to increase, negative to decrease.
 */
function adjustTerminalFont(delta) {
    S.termFontSize = Math.min(TERM_FONT_MAX, Math.max(TERM_FONT_MIN, S.termFontSize + delta));
    _applyTerminalFont();
    _saveFontSize();
}

// ─── Copy output ──────────────────────────────────────────────────────────────

/**
 * Copy the full plain-text content of the terminal output element to the
 * system clipboard.  Shows a toast notification on success or failure.
 */
async function copySSHOutput() {
    const output = document.getElementById('ssh-output');
    if (!output) return;
    const text = output.textContent || '';
    if (!text.trim()) {
        showToast('Terminal output is empty', 'error');
        return;
    }
    try {
        await navigator.clipboard.writeText(text);
        showToast('📋 Terminal output copied!');
    } catch {
        showToast('❌ Clipboard access denied', 'error');
    }
}

// ─── Fullscreen ───────────────────────────────────────────────────────────────

/**
 * Toggle the SSH modal between normal and fullscreen presentation.
 *
 * Fullscreen is implemented by:
 *   - Adding `.ssh-fullscreen` to `#ssh-modal`         → CSS takes over layout
 *   - Adding `.ssh-fullscreen-active` to `#ssh-backdrop` → removes padding
 * The icons in the button are swapped accordingly and the title/tooltip updated.
 */
function toggleSSHFullscreen() {
    const modal    = document.getElementById('ssh-modal');
    const backdrop = document.getElementById('ssh-backdrop');
    if (!modal || !backdrop) return;

    S.sshFullscreen = !S.sshFullscreen;

    modal.classList.toggle('ssh-fullscreen', S.sshFullscreen);
    backdrop.classList.toggle('ssh-fullscreen-active', S.sshFullscreen);

    _updateFullscreenButton();

    // Keep the command input focused when switching modes.
    const cmd = document.getElementById('ssh-cmd');
    if (cmd && !cmd.disabled) {
        // Small delay lets the CSS transition settle before measuring layout.
        setTimeout(() => cmd.focus(), 50);
    }
}

/**
 * Update the fullscreen button icon and tooltip to reflect the current state.
 */
function _updateFullscreenButton() {
    const btn          = document.getElementById('ssh-fullscreen-btn');
    const iconExpand   = document.getElementById('ssh-fs-icon-expand');
    const iconCompress = document.getElementById('ssh-fs-icon-compress');
    if (!btn) return;

    if (S.sshFullscreen) {
        if (iconExpand)   iconExpand.style.display   = 'none';
        if (iconCompress) iconCompress.style.display = 'block';
        btn.title      = 'Exit fullscreen (Esc / F11)';
        btn.setAttribute('aria-label', 'Exit fullscreen');
    } else {
        if (iconExpand)   iconExpand.style.display   = 'block';
        if (iconCompress) iconCompress.style.display = 'none';
        btn.title      = 'Fullscreen (F11)';
        btn.setAttribute('aria-label', 'Toggle fullscreen');
    }
}

/**
 * Exit fullscreen without toggling (idempotent).
 * Used by the close-modal flow.
 */
function _exitFullscreenIfActive() {
    if (S.sshFullscreen) {
        S.sshFullscreen = true; // toggleSSHFullscreen will flip it to false
        toggleSSHFullscreen();
    }
}

// ─── Font controls visibility ─────────────────────────────────────────────────

function _showFontControls() {
    const el = document.getElementById('ssh-font-controls');
    if (el) el.classList.remove('hidden');
}

function _hideFontControls() {
    const el = document.getElementById('ssh-font-controls');
    if (el) el.classList.add('hidden');
}

// ─── Monkey-patch app.js functions ───────────────────────────────────────────
// We wrap — not replace — so the original behaviour is always preserved.

(function patchAppFunctions() {
    /**
     * After the SSH modal opens, apply the persisted font size.
     * Re-enter fullscreen if the user had it active before closing.
     */
    const _origOpen = globalThis.openSSHModal;
    globalThis.openSSHModal = function openSSHModal() {
        _origOpen?.();
        _applyTerminalFont();
        // If the user re-opens the modal, start in normal (non-fullscreen) mode.
        if (S.sshFullscreen) {
            S.sshFullscreen = true;
            toggleSSHFullscreen(); // exits fullscreen
        }
    };

    /**
     * Before the SSH modal closes, silently exit fullscreen first so that the
     * modal animates out correctly.
     */
    const _origClose = globalThis.closeSSHModal;
    globalThis.closeSSHModal = function closeSSHModal() {
        _exitFullscreenIfActive();
        _origClose?.();
    };

    /**
     * When the terminal becomes visible (after a successful connection), show
     * the font controls and apply the current font size.
     */
    const _origShowTerminal = globalThis.showSSHTerminal;
    globalThis.showSSHTerminal = function showSSHTerminal(welcomeMsg) {
        _origShowTerminal?.(welcomeMsg);
        _showFontControls();
        _applyTerminalFont();
    };

    /**
     * When the terminal is hidden (after disconnect), hide the font controls.
     */
    const _origHideTerminal = globalThis.hideSSHTerminal;
    globalThis.hideSSHTerminal = function hideSSHTerminal() {
        _origHideTerminal?.();
        _hideFontControls();
    };
}());

// ─── Keyboard shortcuts ───────────────────────────────────────────────────────

document.addEventListener('keydown', function onSshKeydown(e) {
    const backdrop = document.getElementById('ssh-backdrop');
    if (!backdrop || backdrop.classList.contains('hidden')) return;

    if (e.key === 'F11') {
        e.preventDefault();
        toggleSSHFullscreen();
    }

    // Esc exits fullscreen before the main handler closes the modal.
    // The main handleGlobalKeydown in app.js will fire next and close the modal
    // only when NOT fullscreen, which is the desired behaviour.
    if (e.key === 'Escape' && S.sshFullscreen) {
        e.stopImmediatePropagation();
        toggleSSHFullscreen();
    }
}, true /* capture phase so we intercept before app.js */);
