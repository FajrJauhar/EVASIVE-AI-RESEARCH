import json
import pefile
parsed ={}
with open('MessageBox.exe_features.json','r',encoding = 'utf-8') as file:
    data = json.load(file)
    parsed.update(data)
    
def load_parse_data():
    mutationtarget={ 
                 "injectrichheader" : False, 
                 "fixtimestamps" : False, 
                 "hideriskimports" : False,
                 "addversioninfo" : False,
                 "addoverlaypadding" : False,
                 "reduceentropy" : False 
                 }
                 
                 
     for section in parsed["sections"]:
        sectionname = section.get("Name")
        entropy = section.get("Entropy",0.0)
        highentropy = []
        
        if entropy > 7.0:
            highentropy.append((sectionname,entropy))
            #print(f"Section Name: {section_name}, Entropy: {entropy}") 
        if highentropy:
            mutationtargets["reduceentropy"] = True

    richheader = parsed.get("RichHeader") or parsed.get("richheader")
    if not richheader:
        mutationtarget["injectrichheader"] = True
        print("Rich header Not found")
    else:    
        print("Rich Header Present")
        
    fileheader = parsed.get("FILE_HEADER",{})
    timestamp_raw = fileheader.get("TimeDateStamp",{}).get("value")
    if timestamp_raw is None:
        mutationtarget["fixtimestamp": True]
        print("TimeDataStamp Not Found!")
    else:
        print(f"Time Stamp Present")
        
    importdata=parsed.get("imports",{})
    riskyapicount = importdata.get("risky_api_count",0)
    print(f"\nRisky api Count: {riskyapicount}")

    importlist = importdata.get("import_list",[])
    riskyapi = [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx",
        "OpenProcess", "CreateProcess",
        "NtUnmapViewOfSection", "SetThreadContext",
        "MiniDumpWriteDump",
        "WinExec", "ShellExecute",
        "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
        "GetProcAddress",
        "QueueUserAPC",
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtCreateProcess", "NtCreateProcessEx"
    ]
    foundriskyapi=[]
    for imp in importlist:
        funcname = imp.get("Function","")
        if funcname in riskyapi:
            foundriskyapi.append(funcname)
    print(f"Risky API Found in Imports: {len(foundriskyapi)}")
    if foundriskyapi:
        print("List of Risky API")
        for api in foundriskyapi:
            print(f" - {api}")
    else:
        print("No Risky API's Found")
    if riskyapicount > 0:
        mutationtarget["hideriskimports"] = True
        
    fileinfo = parsed.get("file_info",{})
    filesize= fileinfo.get("file_size")
    if filesize < 2 * 1024 * 1024:
        mutationtarget ["addoverlaypadding"] = True
        print("File Size Absent")
    else:
        print("File Size Present")

    #Resource Presence
    resources = parsed.get("resources",{})
    hasresourceinfo = resources.get("has_version_info",False)
    if not hasresourceinfo :
        mutationtarget["addversioninfo"]=True
        print(f"[!] File Size: {file_size / 1024:.1f} KB (< 2MB) → Will pad")
    else:
        print(f"[+] File Size: {file_size / (1024*1024):.2f} MB"
        
    
load_parse_data()
