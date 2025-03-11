// content.js
function getCurrentTabUrl(callback) {
    try {
        chrome.runtime.sendMessage({ action: "getTabUrl" }, (response) => {
            if (chrome.runtime.lastError) {
                console.error("Error getting tab URL:", chrome.runtime.lastError);
                callback({ url: "Error", domain: "Error" });
                return;
            }
            
            if (!response) {
                console.error("No response from background script");
                callback({ url: "No response", domain: "No response" });
                return;
            }
            
            callback(response);
        });
    } catch (error) {
        console.error("Error in getCurrentTabUrl:", error);
        callback({ url: "Error", domain: "Error" });
    }
}

// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function() {
    try {
        const urlElement = document.getElementById("url");
        const domainElement = document.getElementById("domain");
        const timeElement = document.getElementById("time");
        
        // Only try to get URL if at least one of these elements exists
        if (urlElement || domainElement || timeElement) {
            getCurrentTabUrl((response) => {
                if (urlElement) {
                    urlElement.textContent = response.url || "Unknown URL";
                }
                if (domainElement) {
                    domainElement.textContent = response.domain || "Unknown domain";
                }
                if (timeElement) {
                    timeElement.textContent = new Date().toLocaleString();
                }
            });
        } else {
            console.log("No target elements found in page - content script running on regular web page");
        }
    } catch (error) {
        console.error("Error in DOMContentLoaded handler:", error);
    }
});