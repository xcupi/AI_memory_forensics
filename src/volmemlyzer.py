import argparse
import csv
import functools
import json
import subprocess
import tempfile
import os
import pandas as pd

def extract_winInfo_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = bool(json.loads(df.loc[3].at["Value"].lower()))          
        b = df.loc[8].at["Value"]                                
        c = int(df.loc[11].at["Value"])                              
        d = bool(json.loads(df.loc[4].at["Value"].lower()))         
    except:
        a = None
        b = None
        c = None
        d = None
    return{
        'info.Is64': a,
        'info.winBuild': b,
        'info.npro': c,
        'info.IsPAE': d
    }
def extract_pslist_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = df.PPID.size                                          
        b = df.PPID.nunique()                                 
        c = df.Threads.mean()                  
        d = len(df[df["Wow64"]=="True"])                    
    except:
        a = None
        b = None
        c = None
        d = None
    return{
        'pslist_nproc': a,
        'pslist_nppid': b,
        'pslist_avg_threads': c,
        'pslist_nprocs64bit': d,
    }
def extract_dlllist_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = df.PID.size                                          
        b = df.PID.size/df.PID.unique().size             
    except:
        a = None
        b = None
    return{
        'dlllist_ndlls': a,
        'dlllist_avg_dlls_per_proc': b,
    }
def extract_handles_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = df.HandleValue.size                                
        b = df.HandleValue.size/df.PID.unique().size       
        c = len(df[df["Type"]=="Port"])                      
        d = len(df[df["Type"]=="File"])                      
        e = len(df[df["Type"]=="Event"])                     
        f = len(df[df["Type"]=="Desktop"])                    
        g = len(df[df["Type"]=="Key"])                         
        h = len(df[df["Type"]=="Thread"])                  
        i = len(df[df["Type"]=="Directory"])                   
        j = len(df[df["Type"]=="Semaphore"])                
        k = len(df[df["Type"]=="Timer"])                     
        l = len(df[df["Type"]=="Section"])                    
        m = len(df[df["Type"]=="Mutant"])                   
    except:
        a = None
        b = None
        c = None
        d = None
        e = None
        f = None        
        g = None
        h = None
        i = None
        j = None
        k = None
        l = None
        m = None                                                                           
    return{
        'handles_nhandles': a,
        'handles_avg_handles_per_proc': b,
        'handles_nport': c,
        'handles_nfile': d,
        'handles_nevent': e,
        'handles_ndesktop': f,
        'handles_nkey': g,
        'handles_nthread': h,
        'handles_ndirectory': i,
        'handles_nsemaphore': j,
        'handles_ntimer': k,
        'handles_nsection': l,
        'handles_nmutant': m,         
    }
def extract_ldrmodules_features(jsondump):
    df = pd.read_json(jsondump)
    return {
        'ldrmodules_not_in_load': len(df[df["InLoad"]==False]),                 
        'ldrmodules_not_in_init': len(df[df["InInit"]==False]),                 
        'ldrmodules_not_in_mem': len(df[df["InMem"]==False]),                   
        'ldrmodules_not_in_load_avg': len(df[df["InLoad"]==False])/df.Base.size,
        'ldrmodules_not_in_init_avg': len(df[df["InInit"]==False])/df.Base.size,
        'ldrmodules_not_in_mem_avg': len(df[df["InMem"]==False])/df.Base.size,  
    }
def extract_malfind_features(jsondump):
    df = pd.read_json(jsondump)
    return {                                                                        
    'malfind_ninjections': df.CommitCharge.size,                              
	'malfind_commitCharge': df.CommitCharge.sum(),                                                          
	'malfind_protection': len(df[df["Protection"]=="PAGE_EXECUTE_READWRITE"]),
	'malfind_uniqueInjections': df.PID.unique().size,                         
    }
def extract_modules_features(jsondump):
    df = pd.read_json(jsondump)
    return {
        'modules_nmodules': df.Base.size,                                          
    }
def extract_svcscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'svcscan_nservices': len(df),
        'svcscan_kernel_drivers': len(df[df["Type"]=="SERVICE_KERNEL_DRIVER"]),
        'svcscan_fs_drivers': len(df[df["Type"]=="SERVICE_FILE_SYSTEM_DRIVER"]),
    }
def extract_callbacks_features(jsondump):
    df = pd.read_json(jsondump)
    return {
        'callbacks_ncallbacks': df.Callback.size,                                                             
    }
VOL_MODULES = {
    'pslist': extract_pslist_features,
    'dlllist': extract_dlllist_features,
    'handles': extract_handles_features,
    'ldrmodules': extract_ldrmodules_features,
    'malfind': extract_malfind_features,
    'modules': extract_modules_features,
    'svcscan': extract_svcscan_features,
    'callbacks': extract_callbacks_features
}
def invoke_volatility3(vol_py_path, memdump_path, module, output_to):
    with open(output_to,'w') as f:
        subprocess.run(['python3',vol_py_path, '-f', memdump_path, '-r=json', 'windows.'+module],stdout=f,text=True, check=True)
def write_dict_to_csv(filename, dictionary,memdump_path):
    fieldnames = list(dictionary.keys())
    file_exists = os.path.isfile(filename)  
    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(dictionary)
def extract_all_features_from_memdump(memdump_path, CSVoutput_path, volatility_path):
    features = {}
    print('=> Outputting to', CSVoutput_path)
    with tempfile.TemporaryDirectory() as workdir:
        vol = functools.partial(invoke_volatility3, volatility_path, memdump_path)
        for module, extractor in VOL_MODULES.items():
            print('=> Executing Volatility module', repr(module))
            output_file_path = os.path.join(workdir, module)
            vol(module, output_file_path)
            with open(output_file_path, 'r') as output:
                features.update(extractor(output))    
    features_mem = {'mem.name_extn': str(memdump_path).rsplit('/', 1)[-1]}
    features_mem.update(features)
    file_path = os.path.join(CSVoutput_path, 'output.csv')
    write_dict_to_csv(file_path,features_mem,memdump_path)
    print('=> All done')
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-f','--memdump',default=None, help='Path to folder/directory which has all memdumps',required = True)
    p.add_argument('-o', '--output', default=None, help='Path to the folder where to output the CSV',required = True)
    p.add_argument('-V', '--volatility', default=None, help='Path to the vol.py file in Volatility folder including the extension .py',required = True)
    return p, p.parse_args()
if __name__ == '__main__':
    p, args = parse_args()
    print(args.memdump)
    folderpath = str(args.memdump)
    print(folderpath)
    for filename in os.listdir(folderpath):
        print(filename)
        file_path = os.path.join(folderpath, filename)
        print(file_path)
        if (file_path).endswith('.raw') or (file_path).endswith('.mem') or (file_path).endswith('.lime') or (file_path).endswith('.vmem') or (file_path).endswith('.mddramimage'):
            extract_all_features_from_memdump((file_path), args.output, args.volatility)