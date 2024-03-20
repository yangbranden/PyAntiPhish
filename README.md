# PyAntiPhish

This is the repository for my ASU Barrett Honors Thesis project, which I completed\* from Fall 2023 - Spring 2024.

If you would like the full breakdown of my project in report form, you can find it here: [to be added]

\*There is still lots of room for future improvement, but the idea behind this project is a Chromium-based browser extension that aims to block phishing websites using Machine Learning classifiers (specifically a select few from `scikit-learn`). Although it does technically work, it is a bit scuffed (but hey, I tried my best, and that's what matters right...?)

The classifiers that I trained and tested out are:
- Logistic Regression
- Support Vector Machine (linear kernel)
- K-Nearest Neighbors
- Random Forest

Regarding the usage of AWS in this project, I had to do a couple workarounds because I couldn't figure out how to use Python directly in a browser setting. Basically how it works right now is that it calls an API that I made and hosted on AWS Lambda (AWS Gateway API) which calls the Python code.

## Installing the Extension
So if you want to try out the extension locally, you need to do a couple of things:
1. Install npm and compile (transpile?) the code so that it will give you the `dist` folder (see the README.md in the `PyAntiPhishExtension` folder, which is where all the extension-related stuff is)  
2. Go to Chrome (or your other Chromium-based browser) and go to the extensions page
3. Swap to "Developer mode"
4. Load unpacked and select the `dist` folder; you should see the 'PyAntiPhish' extension added to your browser

Now if you navigate to any website, it should be properly blocking a ton of stuff that it probably shouldn't be because I suck at machine learning! I'm gonna take some grad-level classes on ML and figure out how to properly do this stuff hopefully lol. Then I'll come back and fix this project (or I won't because I'll be doing cooler stuff hehe).

## URL datasets
These are the URL datasets that I used for training the sklearn models in this project:
```
https://www.kaggle.com/datasets/samahsadiq/benign-and-malicious-urls
https://www.kaggle.com/datasets/siddharthkumar25/malicious-and-benign-urls
https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
https://phishtank.org/developer_info.php
```

## Collecting HTML DOM data
So one thing that I was planning on doing was collecting HTML content data, but turns out it's kinda scuffed also because I run Windows natively and Defender doesn't like me downloading tons of malicious .html files, so it just automatically deletes them (and I'm not comfortable disabling my antivirus lol). So basically I used a VirtualBox VM to try and collect data, but turns out that it's also not that easy because ASU internet blocks a lot of phishing pages (I actually work in the SOC so I know for a fact they block URLs), so I also had to get a VPN.

After that, I did this on my VM:
```
wget http://data.phishtank.com/data/online-valid.csv
python getrawdom.py
```

But turns out a lot of phishing pages will just return no content if you're not a real person or are a bot, which this `getrawdom.py` script is considered to be; so for now I gave up, but I did read a couple other research papers on the topic, and there are workarounds for this (which I did not get the time to experiment around with).

One method is to just collect a ton of website contents, and then remove the ones that are blank/meaningless. But that's a lot of manual labor, so the other approach I saw was using something like Selenium rendering to open the website in an automated manner, which allows you to collect the HTML content much more consistently.

For now though, this remains an area of future improvement (like many things in this project).

## List of Future Improvements
There's a lot that's lacking, at least from what I originally said were my goals for this project:
- HTML DOM Analyzer: I wanted to also train some ML models using the HTML contents of phishing websites. As you can see above though, I couldn't figure that out; this is something I will plan to do for the future. 
- Improving UI of the extension: Right now the extension doesn't really have much of a UI, it's just a thing that calls an API in the background and then blocks pages; I wanted to add a little popup. Actually just before writing this I made a little "Hello World" popup, but ideally this would have some stats or information about the API or something. 
- Neural Networks: I also wanted to explore using more complex Neural Networks, which scikit-learn doesn't support. I even installed NVIDIA drivers for CUDA on my GPU, thinking I'd be using them. Never got around to that.

Overall though, I think that I'm happy with the current state of this project; even though it is a bit lacking from what I originally planned to do, I feel like I learned a lot from doing it, and I enjoyed working on it.
