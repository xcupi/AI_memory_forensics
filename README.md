# Memory Forensics with Modified VolMemLyzer + Machine Learning

This repository provides a workflow for **malware detection using memory forensics**.  
It combines a **modified version of VolMemLyzer** for feature extraction with **machine learning models** for classification.

---

## 🔹 Contents
1. **Modified VolMemLyzer**  
   - Based on [VolMemLyzer](https://github.com/ahlashkari/VolMemLyzer) (GPL v3).  
   - Reduced feature set focusing on process, handle, module, service, and injection features.  
   - Still licensed under **GPL v3**.  

2. **Extracted Features (CSV)**  
   - Memory dumps were analyzed using the modified VolMemLyzer.  
   - Resulting features are stored in `.csv` format for easier use in ML workflows.  
   - Includes fields such as:
     - `pslist_nproc`, `dlllist_ndlls`, `handles_nhandles`, `ldrmodules_not_in_load`,  
       `malfind_ninjections`, `svcscan_nservices`, `callbacks_ncallbacks`, etc.  

3. **AI Models**  
   - Machine learning classifiers trained on extracted features:  
     - **RandomForest**  
     - **XGBoost**  
   - Models aim to detect potential malicious activity in memory snapshots.  

---

## 🔹 Workflow
1. Use **Modified VolMemLyzer** to extract reduced features from memory dumps.  
2. Store extracted features in `.csv` datasets.  
3. Train & evaluate ML models (RandomForest, XGBoost).  
