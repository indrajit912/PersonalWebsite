/**
 * Reusable PDF Viewer Modal Component
 * 
 * Supports:
 * - Dynamic view URL, download URL, and title configuration
 * - Inline PDF embedding with fallback
 * - Backdrop click to close
 * - Escape key dismissal
 * - Mobile responsive adaptations
 * - Memory cleanup upon modal close
 */

(function () {
    'use strict';

    function getModalElements() {
        return {
            modal: document.getElementById('pdfViewerModal'),
            backdrop: document.getElementById('pdfModalBackdrop'),
            dialog: document.querySelector('.pdf-modal-dialog'),
            title: document.getElementById('pdfModalTitle'),
            downloadBtn: document.getElementById('pdfModalDownloadBtn'),
            newTabBtn: document.getElementById('pdfModalNewTabBtn'),
            closeBtn: document.getElementById('pdfModalCloseBtn'),
            frame: document.getElementById('pdfModalFrame'),
            loading: document.getElementById('pdfModalLoading'),
            fallback: document.getElementById('pdfModalFallback'),
            fallbackDownload: document.getElementById('pdfFallbackDownloadBtn'),
            fallbackOpen: document.getElementById('pdfFallbackOpenBtn')
        };
    }

    /**
     * Opens the PDF viewer modal.
     * @param {string} viewUrl - The URL to display inline inside the iframe.
     * @param {string} downloadUrl - The URL to trigger direct attachment download.
     * @param {string} title - The document title displayed in the modal header.
     */
    window.openPdfModal = function (viewUrl, downloadUrl, title) {
        const els = getModalElements();
        if (!els.modal) return;

        const effectiveViewUrl = viewUrl || '';
        const effectiveDownloadUrl = downloadUrl || effectiveViewUrl;
        const effectiveTitle = title || 'Curriculum Vitae';

        if (els.title) els.title.textContent = effectiveTitle;
        if (els.downloadBtn) els.downloadBtn.href = effectiveDownloadUrl;
        if (els.newTabBtn) els.newTabBtn.href = effectiveViewUrl;
        if (els.fallbackDownload) els.fallbackDownload.href = effectiveDownloadUrl;
        if (els.fallbackOpen) els.fallbackOpen.href = effectiveViewUrl;

        // Reset state
        if (els.loading) els.loading.style.display = 'flex';
        if (els.fallback) els.fallback.style.display = 'none';

        // Set iframe source
        if (els.frame) {
            els.frame.style.display = 'block';

            // Hide loading spinner once the iframe has finished loading
            const onFrameLoaded = function () {
                if (els.loading) els.loading.style.display = 'none';
                els.frame.removeEventListener('load', onFrameLoaded);
            };

            els.frame.addEventListener('load', onFrameLoaded);
            els.frame.src = effectiveViewUrl;
        }

        // Show modal & prevent background scrolling
        els.modal.classList.add('active');
        els.modal.setAttribute('aria-hidden', 'false');
        document.body.classList.add('pdf-modal-open');

        // Focus the close button for accessibility
        if (els.closeBtn) {
            setTimeout(function () {
                els.closeBtn.focus();
            }, 100);
        }
    };

    /**
     * Closes the PDF viewer modal and cleans up active resources.
     */
    window.closePdfModal = function () {
        const els = getModalElements();
        if (!els.modal || !els.modal.classList.contains('active')) return;

        els.modal.classList.remove('active');
        els.modal.setAttribute('aria-hidden', 'true');
        document.body.classList.remove('pdf-modal-open');

        // Reset iframe src to free up memory
        if (els.frame) {
            els.frame.src = 'about:blank';
        }
    };

    // Attach event listeners upon DOM readiness
    document.addEventListener('DOMContentLoaded', function () {
        const els = getModalElements();
        if (!els.modal) return;

        // Close button click
        if (els.closeBtn) {
            els.closeBtn.addEventListener('click', function (e) {
                e.preventDefault();
                closePdfModal();
            });
        }

        // Backdrop click
        if (els.backdrop) {
            els.backdrop.addEventListener('click', closePdfModal);
        }

        // Escape key to close
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && els.modal.classList.contains('active')) {
                closePdfModal();
            }
        });

        // Click outside the dialog
        els.modal.addEventListener('click', function (e) {
            if (e.target === els.modal) {
                closePdfModal();
            }
        });

        // Global event delegation for any element with data-pdf-modal attribute
        document.addEventListener('click', function (e) {
            const trigger = e.target.closest('[data-pdf-modal]');
            if (trigger) {
                e.preventDefault();
                const viewUrl = trigger.getAttribute('data-pdf-view') || trigger.getAttribute('href');
                const downloadUrl = trigger.getAttribute('data-pdf-download') || viewUrl;
                const title = trigger.getAttribute('data-pdf-title') || trigger.textContent.trim() || 'Curriculum Vitae';
                openPdfModal(viewUrl, downloadUrl, title);
            }
        });
    });
})();
