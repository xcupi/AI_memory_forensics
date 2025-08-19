# MyVolMemLyzer (Reduced Feature Version)

This project is a **modified version of [VolMemLyzer](https://github.com/ahlashkari/VolMemLyzer)**, originally created by A. H. Lashkari and contributors.  
The original project is licensed under **GNU GPL v3**, and this derivative work continues under the same license.  

### 🔹 Modifications
This version is simplified to focus on a subset of features, including:
- pslist_nproc, pslist_nppid, pslist_avg_threads, pslist_nprocs64bit
- dlllist_ndlls, dlllist_avg_dlls_per_proc
- handles_nhandles, handles_avg_handles_per_proc, handles_nport, handles_nfile,
  handles_nevent, handles_ndesktop, handles_nkey, handles_nthread,
  handles_ndirectory, handles_nsemaphore, handles_ntimer, handles_nsection,
  handles_nmutant
- ldrmodules_not_in_load, ldrmodules_not_in_init, ldrmodules_not_in_mem,
  ldrmodules_not_in_load_avg, ldrmodules_not_in_init_avg, ldrmodules_not_in_mem_avg
- malfind_ninjections, malfind_commitCharge, malfind_protection, malfind_uniqueInjections
- modules_nmodules
- svcscan_nservices, svcscan_kernel_drivers, svcscan_fs_drivers
- callbacks_ncallbacks

### 🔹 License
This project is licensed under the [GNU General Public License v3](./LICENSE).
