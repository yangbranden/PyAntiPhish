PACKAGES_DIR = package/
ZIP_DIR = package.zip

package: url_analyzer.py url_model_KNN.pickle url_model_LR.pickle url_model_RF.pickle url_model_SVM.pickle
	mkdir $(PACKAGES_DIR)
	pip install --target $(PACKAGES_DIR) tldextract fuzzywuzzy python-Levenshtein scikit-learn
	find $(PACKAGES_DIR) -type f -name "*.so" | xargs -r strip
	find $(PACKAGES_DIR) -type f -name "*.pyc" | xargs -r rm
	find $(PACKAGES_DIR) -type d -name "__pycache__" | xargs -r rm -r
	find $(PACKAGES_DIR) -type d -name "*.dist-info" | xargs -r rm -r
	find $(PACKAGES_DIR) -type d -name "tests" | xargs -r rm -r
	zip -r $(ZIP_DIR) $(PACKAGES_DIR)
	zip $(ZIP_DIR) url_analyzer.py
	zip $(ZIP_DIR) url_model_KNN.pickle
	zip $(ZIP_DIR) url_model_LR.pickle
	zip $(ZIP_DIR) url_model_RF.pickle
	zip $(ZIP_DIR) url_model_SVM.pickle

clean:
	rm -rf $(PACKAGES_DIR)
	rm $(ZIP_DIR)