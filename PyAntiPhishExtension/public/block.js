let url = "https://twitter.com/"

function goBack() {
    console.log("Clicked goBack");
    // window.history.back(); // this is inconsistent; use go(-1)
    window.history.go(-1);
}

function seeDetails() {
    console.log("Clicked seeDetails");
    console.log(url);
    detailsContainer.hidden = !detailsContainer.hidden;
}

function seeReport() {
    window.location.href = chrome.runtime.getURL('./details.html');
}

function proceed() {
    chrome.runtime.sendMessage({ action: "whitelist", url: url });
    window.location.href = url;
}

function initPage() {
    let goBackButton = document.getElementById("goBack");
    let seeDetailsButton = document.getElementById("seeDetails");
    let seeReportButton = document.getElementById("seeReport");
    let proceedButton = document.getElementById("proceedButton");
    let detailsText = document.getElementById("detailsText");
    
    goBackButton.addEventListener("click", goBack);
    seeDetailsButton.addEventListener("click", seeDetails);
    seeReportButton.addEventListener("click", seeReport);
    proceedButton.addEventListener("click", proceed);
    detailsText.innerHTML = "<a href=\"#\">" + url + "</a> was classified as phishing. Click the below \"See full report\" button to see why, or if you are sure that the site is not malicious, you may proceed with caution.";
}

initPage();