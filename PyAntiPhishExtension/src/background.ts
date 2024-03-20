let active = false;
// let test = "https://twitter.com/";
let whitelisted: string[] = [];
const apiEndpointURL = "https://mwo0rju1el.execute-api.us-east-1.amazonaws.com/pyantiphish/url_analyzer";

async function urlAnalyzer(url?: string | undefined) {
    console.log("URL:", url, "Calling API...");

    try {
        const response = await window.fetch(apiEndpointURL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Origin': url ?? ""
            },
            body: JSON.stringify({ url: url })
        });
        
        if (response.status != 200) {
            throw new Error("Bad API response");
        }

        const data = await response.json();
    
        console.log("AWS Lambda returned:", data);
        
        const body = JSON.parse(data['body']);
        console.log("Parsed JSON:", body);

        const model_LR_pred = body['model_LR']['prediction'];
        const model_SVM_pred = body['model_SVM']['prediction'];
        const model_KNN_pred = body['model_KNN']['prediction'];
        const model_RF_pred = body['model_RF']['prediction'];
        console.log("model_LR:", model_LR_pred)
        console.log("model_SVM:", model_SVM_pred)
        console.log("model_KNN:", model_KNN_pred)
        console.log("model_RF:", model_RF_pred)
        chrome.storage.sync.set({model_LR_pred: model_LR_pred});
        chrome.storage.sync.set({model_SVM_pred: model_SVM_pred});
        chrome.storage.sync.set({model_KNN_pred: model_KNN_pred});
        chrome.storage.sync.set({model_RF_pred: model_RF_pred});

        // Can select which model to use here:
        // if (model_LR_pred === 'phishing') {
        // if (model_SVM_pred === 'phishing') {
        // if (model_KNN_pred === 'phishing') {
        if (model_RF_pred === 'phishing') {
            chrome.storage.sync.set({url: url});
            window.location.href = chrome.runtime.getURL('./block.html');
        }

        // OR you can use this "count" system, which is kinda like VT? but not really...? yeah not really.
        // var count = 0;
        // if (model_LR_pred === 'phishing') count += 1;
        // if (model_SVM_pred === 'phishing') count += 1;
        // if (model_KNN_pred === 'phishing') count += 1;
        // if (model_RF_pred === 'phishing') count += 1;
        // if (count >= 3) {
        //     chrome.storage.sync.set({url: url});
        //     window.location.href = chrome.runtime.getURL('./block.html');
        // }
        return body;
    } catch (e) {
        console.error(e);
    }
}

// Show popup window showing analysis status
chrome.action.onClicked.addListener((tab) => {
    active = !active;
    chrome.scripting.executeScript({
        target: {tabId: tab.id ?? -1},
        func: urlAnalyzer,
        args: [tab.url]
    }).then();
});

// Listener for URL analyzer
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url && tab.url && !tab.url.startsWith('chrome-extension://') && !tab.url.startsWith('chrome://') && !whitelisted.includes(tab.url)) { // && tab.url.includes(test)
        chrome.scripting.executeScript({
            target: {tabId: tab.id ?? -1},
            func: urlAnalyzer,
            args: [tab.url]
        });
    }
});

// When the user clicks on "Proceed with caution", whitelist it for the current session
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "whitelist") {
        console.log("Whitelisting " + request.url + " for the current session");
        whitelisted.push(request.url);
    }
})