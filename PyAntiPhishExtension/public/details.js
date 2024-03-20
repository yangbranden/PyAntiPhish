function initPage() {
    // Get the values from chrome storage
    chrome.storage.sync.get(null, function(data) {
        if (chrome.runtime.lastError) {
            console.error("Error retrieving data: " + chrome.runtime.lastError.message);
        } else {
            // Update URL
            console.log("Contents of Chrome Storage:", data);
            // Update LR
            let logisticRegression = document.getElementById("logisticRegression").getElementsByClassName("entryStatus");
            logisticRegression[0].innerHTML = data.model_LR_pred.charAt(0).toUpperCase() + data.model_LR_pred.slice(1); // the slice thing is just to capitalize the string
            // Update SVM
            let supportVectorMachine = document.getElementById("supportVectorMachine").getElementsByClassName("entryStatus");
            supportVectorMachine[0].innerHTML = data.model_SVM_pred.charAt(0).toUpperCase() + data.model_SVM_pred.slice(1);
            // Update KNN
            let kNearestNeighbors = document.getElementById("kNearestNeighbors").getElementsByClassName("entryStatus");
            kNearestNeighbors[0].innerHTML = data.model_KNN_pred.charAt(0).toUpperCase() + data.model_KNN_pred.slice(1);
            // Update RF
            let randomForest = document.getElementById("randomForest").getElementsByClassName("entryStatus");
            randomForest[0].innerHTML = data.model_RF_pred.charAt(0).toUpperCase() + data.model_RF_pred.slice(1);
        }
    });
}

initPage();