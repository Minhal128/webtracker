document.addEventListener('DOMContentLoaded', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const originalUrl = decodeURIComponent(urlParams.get('url'));
    const domain = decodeURIComponent(urlParams.get('domain'));

    document.getElementById('domain').textContent = domain;
    document.getElementById('url').textContent = originalUrl;

    document.getElementById('proceed-btn').addEventListener('click', function() {
        chrome.runtime.sendMessage({
            action: 'proceed',
            domain: domain,
            originalUrl: originalUrl
        });
    });
});