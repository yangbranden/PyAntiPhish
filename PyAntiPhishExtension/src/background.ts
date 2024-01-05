let active = false;
let test = "https://twitter.com/";
let blockedURL: string | undefined = undefined;
let whitelisted: string[] = [];
const apiEndpointURL = "https://mwo0rju1el.execute-api.us-east-1.amazonaws.com/pyantiphish/url_analyzer"

function blockPage(url?: string | undefined) {
    console.log("Blocking page");
    blockedURL = url;
    window.location.href = chrome.runtime.getURL('./block.html');
}

function urlAnalyzer(url: string) {
    console.log("Calling API...")

    window.fetch(apiEndpointURL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
    }).then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        console.log('Response from Lambda:', response);
        return response.json();
    }).then(data => {
        console.log('Response from server:', data);
    }).catch(error => {
        console.error('Error during fetch:', error);
    });
}

function changeBGColor(color: string, test?: any): void {
    console.log(color);
    console.log(test);
    document.body.style.backgroundColor = color;
}

// TODO: This should have a popup window showing analysis status
chrome.action.onClicked.addListener((tab) => {
    active = !active;
    const color = active ? 'orange' : 'gray';
    chrome.scripting.executeScript({
        target: {tabId: tab.id ?? -1},
        func: urlAnalyzer,
        args: ["https://www.google.com"]
    }).then();
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // TODO: URL analyzer + VirusTotal should go here
    if (changeInfo.url && !tab.url?.startsWith('chrome-extension://') && !tab.url?.startsWith('chrome://') && tab.url?.includes(test) && !whitelisted.includes(tab.url)) {
        chrome.scripting.executeScript({
            target: {tabId: tab.id ?? -1},
            func: blockPage,
            args: [tab.url]
        });
    }

    // TODO: HTML DOM analyzer should go here
    // if (changeInfo.status == 'complete' && !tab.url?.startsWith('chrome-extension://') && !tab.url?.startsWith('chrome://') && tab.url?.includes(test)) {
    //     chrome.scripting.executeScript({
    //         target: {tabId: tab.id ? tab.id : -1},
    //         files: ["block.js"]
    //     });
    // }
});

// When the user clicks on "Proceed with caution", whitelist it for the current session
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "whitelist") {
        console.log("Whitelisting " + request.url + " for the current session");
        whitelisted.push(request.url);
    }
})