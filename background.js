const RAPIDAPI_KEY = '97faecfa63msh9641c3808ad1da3p13cad8jsnccdc2cdf2fb3'; 

const scannedDomains = new Set();

chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        console.log("Intercepted request to: ", details.url);
    },
    { urls: ["<all_urls>"] }
);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getTabUrl" && sender.tab) {
        try {
            const url = new URL(sender.tab.url);
            sendResponse({
                url: sender.tab.url,
                domain: url.hostname
            });
        } catch (error) {
            sendResponse({
                url: "Invalid URL",
                domain: "Unknown"
            });
        }
    }
    return true;
});

console.log("Extension initialized. Clearing scanned domains.");
scannedDomains.clear();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    console.log(`Tab updated: ${tabId}, status: ${changeInfo.status}, URL: ${tab.url}`);
    
    if (changeInfo.status === "complete" && tab.active) {
        try {
            if (!tab.url || 
                tab.url.startsWith('chrome://') || 
                tab.url.startsWith('edge://') || 
                tab.url.startsWith('about:') || 
                tab.url.startsWith('chrome-extension://')) {
                console.log(`Skipping internal URL: ${tab.url}`);
                return;
            }
            
            const url = new URL(tab.url);
            const domain = url.hostname;
            console.log(`Processing URL: ${tab.url} with domain: ${domain}`);
            
            if (scannedDomains.has(domain)) {
                console.log(`Domain ${domain} already scanned, skipping`);
                return;
            }
            
            scannedDomains.add(domain);
            console.log(`Scanning new domain: ${domain}`);
            
            performBasicChecks(tab.url, domain)
                .then(results => {
                    console.log("Security check results:", results);
                    
                    const message = `Browser opened at ${new Date().toLocaleString()}\n\n` +
                                    `Domain: ${domain}\n` +
                                    `URL: ${tab.url}\n` +
                                    `Basic Security Check: ${results.basicCheck}\n` +
                                    `Domain Analysis: ${results.domainAnalysis}`;
                    
                    console.log("Creating results tab with message:", message);
                    
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
                    
                    try {
                        const encodedHtml = encodeURIComponent(htmlContent);
                        const dataUrl = `data:text/html,${encodedHtml}`;
                        
                        chrome.tabs.create({url: dataUrl}, (newTab) => {
                            if (chrome.runtime.lastError) {
                                console.error("Error creating tab:", chrome.runtime.lastError);
                            } else {
                                console.log("Results tab created with ID:", newTab.id);
                            }
                        });
                    } catch (urlError) {
                        console.error("Error creating URL:", urlError);
                        chrome.tabs.create({
                            url: `data:text/html,<html><body><h1>WebTracker Results</h1><p>${encodeURIComponent(message)}</p></body></html>`
                        });
                    }
                })
                .catch(error => {
                    console.error("Error in performBasicChecks:", error);
                    chrome.tabs.create({
                        url: `data:text/html,<html><body><h1>WebTracker Error</h1><p>Error scanning ${domain}: ${error.message}</p></body></html>`
                    });
                });
        } catch (error) {
            console.error("Error processing tab:", error);
        }
    }
});

async function performBasicChecks(url, domain) {
    const results = {
        basicCheck: "No obvious security issues detected",
        domainAnalysis: "Basic domain check passed",
        severity: "safe"
    };
    
    if (url.includes('phishing') || url.includes('login') && url.includes('verify')) {
        results.basicCheck = "Warning: URL contains potentially suspicious keywords";
        results.severity = "warning";
    }
    
    if (url.startsWith('http:')) {
        results.basicCheck = "Warning: This site is using an unencrypted HTTP connection";
        results.severity = "warning";
    }
    
    const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
        results.domainAnalysis = "Warning: Domain uses a TLD often associated with free domains";
        results.severity = "warning";
    }
    
    return results;
}

chrome.runtime.onInstalled.addListener(() => {
    console.log("Extension installed or updated. Clearing scanned domains.");
    scannedDomains.clear();
});