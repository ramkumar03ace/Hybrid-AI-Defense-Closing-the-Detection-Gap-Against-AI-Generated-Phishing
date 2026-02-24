/* ============================================
   Hybrid AI Defense — Gmail Content Script
   Extracts email body & subject from Gmail DOM
   ============================================ */

(() => {
    'use strict';

    /**
     * Extract the currently open email body (text + HTML) from Gmail.
     * Gmail uses several selectors; we try them in priority order.
     */
    function extractEmailBody() {
        // Primary: Gmail's email body container
        const selectors = [
            'div.a3s.aiL',                    // Main email body (most common)
            'div.ii.gt div.a3s',              // Alternative wrapper
            'div[data-message-id] div.a3s',   // Newer Gmail
            'div.maincontent',                // Basic HTML Gmail
        ];

        for (const sel of selectors) {
            const elements = document.querySelectorAll(sel);
            if (elements.length > 0) {
                // Get the last (most recently opened) email body
                const el = elements[elements.length - 1];
                return { text: el.innerText.trim(), html: el.innerHTML };
            }
        }

        // Fallback: try to get any visible email text from the reading pane
        const readingPane = document.querySelector('div[role="listitem"] div.gs');
        if (readingPane) {
            return { text: readingPane.innerText.trim(), html: readingPane.innerHTML };
        }

        return null;
    }

    /**
     * Extract the email subject line from Gmail.
     */
    function extractSubject() {
        const selectors = [
            'h2.hP',                           // Standard subject heading
            'div.ha h2',                       // Alternative subject container
            'span[data-thread-perm-id]',       // Thread subject
            'input[name="subject"]',           // Compose mode
        ];

        for (const sel of selectors) {
            const el = document.querySelector(sel);
            if (el) {
                return (el.value || el.innerText || '').trim();
            }
        }

        return '';
    }

    // Listen for messages from the popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'extract_email') {
            const result = extractEmailBody();
            const subject = extractSubject();

            if (result) {
                sendResponse({
                    success: true,
                    subject: subject,
                    body: result.text,
                    body_html: result.html,
                });
            } else {
                sendResponse({
                    success: false,
                    error: 'No email found. Please open an email in Gmail first.',
                });
            }
        }

        // Return true to indicate we'll respond asynchronously if needed
        return true;
    });

    console.log('[Hybrid AI Defense] Content script loaded on Gmail.');
})();
