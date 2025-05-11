const scannedDomains = new Set();

// Listen for tab updates to check for suspicious pages and show warnings
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "loading" && tab.url) {
        try {
            const url = new URL(tab.url);
            const domain = url.hostname;
            // Suspicious TLDs and URL shorteners
            const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf'];
            const urlShorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'rebrand.ly', 'ow.ly'];
            const isSuspiciousTLD = suspiciousTLDs.some(tld => domain.endsWith(tld));
            const isUrlShortener = urlShorteners.some(shortener => domain.includes(shortener));
            const isSuspiciousKeyword = tab.url.includes('phishing') || (tab.url.includes('login') && tab.url.includes('verify'));
            const isHttp = tab.url.startsWith('http:');
            // Use chrome.storage.session for allow override
            const allowKey = `allow_${domain}`;
            
            // Check if chrome.storage.session exists
            if (chrome.storage && chrome.storage.session) {
                chrome.storage.session.get([allowKey], (result) => {
                    if ((isSuspiciousTLD || isSuspiciousKeyword || isHttp || isUrlShortener) && !result[allowKey]) {
                        // Show warning page
                        const warningUrl = chrome.runtime.getURL('warning.html') + 
                            `?url=${encodeURIComponent(tab.url)}&domain=${encodeURIComponent(domain)}`;
                        chrome.tabs.update(tabId, { url: warningUrl });
                    }
                });
            } else if (isSuspiciousTLD || isSuspiciousKeyword || isHttp || isUrlShortener) {
                // Fallback behavior without storage
                const warningUrl = chrome.runtime.getURL('warning.html') + 
                    `?url=${encodeURIComponent(tab.url)}&domain=${encodeURIComponent(domain)}`;
                chrome.tabs.update(tabId, { url: warningUrl });
            }
        } catch (e) {
            console.error("Error checking URL:", e);
        }
    }
});

// Listen for tab updates to perform security scan and generate report
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.status === "complete" && tab.active) {
        try {
            if (!tab.url || 
                tab.url.startsWith('chrome://') || 
                tab.url.startsWith('edge://') || 
                tab.url.startsWith('about:') || 
                tab.url.startsWith('chrome-extension://')) {
                return;
            }
            const url = new URL(tab.url);
            const domain = url.hostname;
            if (scannedDomains.has(domain)) {
                return;
            }
            scannedDomains.add(domain);
            performBasicChecks(tab.url, domain)
                .then(results => {
                    const message = `Browser opened at ${new Date().toLocaleString()}\n\n` +
                                    `Domain: ${domain}\n` +
                                    `URL: ${tab.url}\n` +
                                    `Basic Security Check: ${results.basicCheck}\n` +
                                    `Domain Analysis: ${results.domainAnalysis}`;
                    const htmlContent = `
                        <html>
                            <head>
                                <title>WebTracker Security Report</title>
                                <style>
                                    body { font-family: Arial, sans-serif; margin: 20px; }
                                    h1 { color: blue; }
                                    .result { border-left: 4px solid green; padding: 10px; margin: 20px 0; }
                                    pre { white-space: pre-wrap; }
                                </style>
                            </head>
                            <body>
                                <h1>Security Scan Result</h1>
                                <div class="result">
                                    <pre>${message}</pre>
                                </div>
                            </body>
                        </html>
                    `;
                    const encodedHtml = encodeURIComponent(htmlContent);
                    const dataUrl = `data:text/html,${encodedHtml}`;
                    chrome.tabs.create({url: dataUrl});
                })
                .catch(error => {
                    chrome.tabs.create({
                        url: `data:text/html,<html><body><h1>WebTracker Error</h1><p>Error scanning ${domain}: ${error.message}</p></body></html>`
                    });
                });
        } catch (error) {
            console.error("Error processing tab:", error);
        }
    }
});

// Basic security checks
async function performBasicChecks(url, domain) {
    const results = {
        basicCheck: "No obvious security issues detected",
        domainAnalysis: "Basic domain check passed",
        severity: "safe"
    };
    // Check for suspicious keywords in URL
    if (url.includes('phishing') || (url.includes('login') && url.includes('verify'))) {
        results.basicCheck = "Warning: URL contains potentially suspicious keywords";
        results.severity = "warning";
    }
    // Check for unencrypted connection
    if (url.startsWith('http:')) {
        results.basicCheck = "Warning: This site is using an unencrypted HTTP connection";
        results.severity = "warning";
    }
    // Check for suspicious TLDs
    const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
        results.domainAnalysis = "Warning: Domain uses a TLD often associated with free domains";
        results.severity = "warning";
    }
    // Check for URL shorteners
    const urlShorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'rebrand.ly', 'ow.ly'];
    if (urlShorteners.some(shortener => domain.includes(shortener))) {
        results.domainAnalysis = "Warning: This is a shortened URL which may hide the actual destination";
        results.severity = "warning";
    }
    return results;
}

// Message listener for both content scripts and proceed action
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getTabUrl" && sender.tab) {
        try {
            const url = new URL(sender.tab.url);
            sendResponse({
                domain: url.hostname
            });
        } catch (error) {
            sendResponse({
                domain: "Unknown"
            });
        }
    } else if (request.action === "proceed") {
        const allowKey = `allow_${request.domain}`;
        if (chrome.storage && chrome.storage.session) {
            chrome.storage.session.set({ [allowKey]: true }, () => {
                chrome.tabs.update(sender.tab.id, { url: request.originalUrl });
            });
        } else {
            // Proceed directly without storage
            chrome.tabs.update(sender.tab.id, { url: request.originalUrl });
        }
    }
    return true;
});
chrome.runtime.onInstalled.addListener(() => {
    scannedDomains.clear();
});