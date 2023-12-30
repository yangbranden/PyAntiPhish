# PyAntiPhish URL Analyzer

## Uploading to AWS Lambda
Making AWS Lambda package
```
mkdir package/
pip install --target ./package scikit-learn tldextract fuzzywuzzy python-Levenshtein

# This is so that the package is small enough for lambda
find ./package -type f -name "*.so" | xargs -r strip
find ./package -type f -name "*.pyc" | xargs -r rm
find ./package -type d -name "__pycache__" | xargs -r rm -r
find ./package -type d -name "*.dist-info" | xargs -r rm -r
find ./package -type d -name "tests" | xargs -r rm -r

cd package
zip -r ../package.zip .

cd ..
zip package.zip url_analyzer.py
zip package.zip url_model_KNN.pickle
zip package.zip url_model_LR.pickle
zip package.zip url_model_RF.pickle
zip package.zip url_model_SVM.pickle
```