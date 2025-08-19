# AI Memory Forensics

This repository demonstrates the use of **Artificial Intelligence (AI) for malware detection in memory forensics**.  
We leverage a reduced set of features extracted from memory dumps to train and evaluate machine learning models.

---

## 🔹 Key Components
1. **Feature Extraction (Modified VolMemLyzer)**  
   - Based on [VolMemLyzer](https://github.com/ahlashkari/VolMemLyzer) (GPL v3).  
   - Used only as a **feature extractor**.  
   - We customized it to extract a selected subset of features relevant for AI classification.  

2. **Datasets (CSV)**  
   - Memory dumps are processed to generate structured `.csv` files containing numeric features.  
   - These datasets are the input for training AI models.  
   - Example features include:
     - `pslist_nproc`, `dlllist_ndlls`, `handles_nhandles`,  
       `ldrmodules_not_in_load`, `malfind_ninjections`, `svcscan_nservices`,  
       `callbacks_ncallbacks`, etc.  

3. **AI Models**  
   - Two ML classifiers are provided:  
     - **RandomForest**  
     - **XGBoost**  
   - Models are trained on extracted features to classify benign vs malicious behavior.  

---

## 🔹 Workflow
1. **Extract features** from memory dump using the modified VolMemLyzer.  
2. **Convert features** into structured `.csv` dataset.  
3. **Train models** (RandomForest, XGBoost) on the dataset.  
4. **Evaluate models** for malware detection performance.  
5. **Apply model** on new memory dump features for classification.  
