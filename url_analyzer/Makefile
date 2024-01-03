PACKAGES_DIR = package/
ZIP_FILE = package.zip

package:
	mkdir package/
	pip install --target package/ -r requirements.txt
	find package/ -type f -name "*.so" | xargs -r strip
	find package/ -type f -name "*.pyc" | xargs -r rm
	find package/ -type d -name "__pycache__" | xargs -r rm -r
	find package/ -type d -name "tests" | xargs -r rm -r
	cd package/ && zip -r ../package.zip .

add_code: url_analyzer.py url_model_KNN.pickle url_model_LR.pickle url_model_RF.pickle url_model_SVM.pickle
	zip $(ZIP_FILE) url_analyzer.py
	zip $(ZIP_FILE) url_model_KNN.pickle
	zip $(ZIP_FILE) url_model_LR.pickle
	zip $(ZIP_FILE) url_model_RF.pickle
	zip $(ZIP_FILE) url_model_SVM.pickle

clean:
	rm -rf $(PACKAGES_DIR)
	rm $(ZIP_FILE)