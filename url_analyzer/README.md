# PyAntiPhish URL Analyzer

## Uploading to AWS Lambda
Making AWS Lambda package:
1. Create an Amazon Linux EC2 instance (just using Cloud9 environment is probably the easiest, it will make an EC2 instance for you)
And then install python 3.11 on the EC2/Cloud9 AL environment:
```
sudo dnf install python3.11 -y
sudo dnf install python3.11-pip -y
```

2. Compile the required Python 3.11 modules on an Amazon Linux EC2 instance
```
mkdir package/
pip install --target ./package scikit-learn tldextract fuzzywuzzy python-Levenshtein
```

3. Compress/remove unnecessary files from the modules so that the package zip is small enough for lambda
```
find ./package -type f -name "*.so" | xargs -r strip
find ./package -type f -name "*.pyc" | xargs -r rm
find ./package -type d -name "__pycache__" | xargs -r rm -r
find ./package -type d -name "*.dist-info" | xargs -r rm -r
find ./package -type d -name "tests" | xargs -r rm -r

cd package
zip -r ../package.zip .
```

4. Download the `package.zip` file and then add in the code:
```
zip package.zip url_analyzer.py
zip package.zip url_model_KNN.pickle
zip package.zip url_model_LR.pickle
zip package.zip url_model_RF.pickle
zip package.zip url_model_SVM.pickle
```