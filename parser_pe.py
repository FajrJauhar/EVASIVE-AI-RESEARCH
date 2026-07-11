"""
PE Parser for ML Feature Extraction
---------------------------------
This script extracts features from Windows PE files that are relevant to
Machine Learning-based Antivirus (like Windows Defender's ML model).

Author: Evasion AI Research
Purpose: Extract ML features from PE files for genetic algorithm optimization

Features extracted:
1. Header fields (timestamp, characteristics, subsystem, etc.)
2. Section information (names, sizes, characteristics, entropy)
3. Import table (DLLs, APIs, risky API detection)
4. Export table (for DLLs)
5. Rich Header (MSVC toolchain fingerprint)
6. Resources (version info, icons, manifests)
7. Entropy metrics (per-section and overall)
8. File-level metrics (size, overlay)
9. Suspicious string patterns
"""

import pefile
import math
import struct
import hashlib
import os
from collections import Counter
from typing import Dict, List, Tuple, Optional, Any

class PEFeatureExtractor:
    """
    Extract features from PE files for ML-based detection analysis.
    
    Usage:
        extractor = PEFeatureExtractor('malware.exe')
        features = extractor.extract_all()
        print(features)
        feature_vector = extractor.to_feature_vector()
    """
    
    def __init__(self, filepath: str):
        """
        Initialize the PE parser with a file path.
        
        Args:
            filepath: Path to the PE file to analyze
        """
        self.filepath = filepath
        self.pe = None
        self.raw_data = None
        self.features = {}
        
        # Load the PE file
        try:
            self.pe = pefile.PE(filepath)
            with open(filepath, 'rb') as f:
                self.raw_data = f.read()
            print(f"[+] Successfully loaded: {filepath}")
            print(f"[+] File size: {len(self.raw_data)} bytes")
        except Exception as e:
            print(f"[-] Error loading PE: {e}")
            raise
    
    # ========================================================================
    # EXTRACTION METHODS
    # ========================================================================
    
    def extract_all(self) -> Dict:
        """
        Extract all features and return as a dictionary.
        This is the main method you'll call.
        """
        print("\n[*] Extracting PE features...")
        
        self._extract_header_features()
        self._extract_section_features()
        self._extract_import_features()
        self._extract_export_features()
        self._extract_rich_header()
        self._extract_resource_features()
        self._extract_file_features()
        self._extract_string_features()
        self._extract_entropy_features()
        
        print(f"[+] Extracted {len(self.features)} feature groups")
        return self.features
    
    # ========================================================================
    # 1. HEADER FEATURES
    # ========================================================================
    
    def _extract_header_features(self):
        """
        Extract IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER64 fields.
        These are the basic PE metadata fields.
        """
        fh = self.pe.FILE_HEADER
        oh = self.pe.OPTIONAL_HEADER
        
        self.features['header'] = {
            # IMAGE_FILE_HEADER
            'Machine': fh.Machine,                    # CPU architecture (0x8664 = x64)
            'NumberOfSections': fh.NumberOfSections,  # How many sections
            'TimeDateStamp': fh.TimeDateStamp,        # Compilation timestamp
            'Characteristics': fh.Characteristics,    # File flags (EXE, DLL, etc.)
            
            # IMAGE_OPTIONAL_HEADER64
            'Magic': oh.Magic,                        # PE32 (0x010B) or PE32+ (0x020B)
            'AddressOfEntryPoint': oh.AddressOfEntryPoint,  # Entry point RVA
            'ImageBase': oh.ImageBase,                # Preferred load address
            'SectionAlignment': oh.SectionAlignment,  # Memory alignment (usually 0x1000)
            'FileAlignment': oh.FileAlignment,        # Disk alignment (usually 0x200)
            'SizeOfImage': oh.SizeOfImage,            # Total memory size
            'SizeOfHeaders': oh.SizeOfHeaders,        # Size of all headers
            'CheckSum': oh.CheckSum,                  # Optional checksum
            'Subsystem': oh.Subsystem,                # GUI (2), Console (3), etc.
            'DllCharacteristics': oh.DllCharacteristics,  # ASLR, DEP, CFG flags
            'SizeOfStackReserve': oh.SizeOfStackReserve,
            'SizeOfStackCommit': oh.SizeOfStackCommit,
            'SizeOfHeapReserve': oh.SizeOfHeapReserve,
            'SizeOfHeapCommit': oh.SizeOfHeapCommit,
        }
        
        # Add boolean flags for security features
        self.features['security_flags'] = {
            'ASLR': bool(oh.DllCharacteristics & 0x0040),  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            'DEP': bool(oh.DllCharacteristics & 0x0100),   # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            'CFG': bool(oh.DllCharacteristics & 0x4000),   # IMAGE_DLLCHARACTERISTICS_GUARD_CF
            'HighEntropyVA': bool(oh.DllCharacteristics & 0x0020),
            'IsDLL': bool(fh.Characteristics & 0x2000),
            'IsExecutable': bool(fh.Characteristics & 0x0002),
        }
        
        # Timestamp plausibility check (used by ML models)
        timestamp = fh.TimeDateStamp
        if timestamp == 0:
            self.features['timestamp_plausibility'] = 'Zero'
        elif timestamp > 0x66B00000:  # After 2024-01-01
            self.features['timestamp_plausibility'] = 'Future'
        elif timestamp < 0x4A000000:  # Before 2009
            self.features['timestamp_plausibility'] = 'Past'
        else:
            self.features['timestamp_plausibility'] = 'Plausible'
    
    # ========================================================================
    # 2. SECTION FEATURES
    # ========================================================================
    
    def _extract_section_features(self):
        """
        Extract information about each section in the PE.
        Sections are like .text (code), .data, .rdata, etc.
        """
        sections = []
        section_entropies = []
        
        for section in self.pe.sections:
            # Get section name
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            
            # Get raw data and compute entropy
            data = section.get_data()
            entropy = self._compute_entropy(data)
            section_entropies.append(entropy)
            
            section_info = {
                'Name': name,
                'VirtualAddress': section.VirtualAddress,
                'VirtualSize': section.Misc_VirtualSize,
                'SizeOfRawData': section.SizeOfRawData,
                'PointerToRawData': section.PointerToRawData,
                'Characteristics': section.Characteristics,
                'Entropy': entropy,
                
                # Permission flags
                'IsExecutable': bool(section.Characteristics & 0x20000000),
                'IsWritable': bool(section.Characteristics & 0x80000000),
                'IsReadable': bool(section.Characteristics & 0x40000000),
                'IsRWX': bool(
                    (section.Characteristics & 0x20000000) and
                    (section.Characteristics & 0x80000000) and
                    (section.Characteristics & 0x40000000)
                ),
            }
            sections.append(section_info)
        
        self.features['sections'] = sections
        self.features['section_stats'] = {
            'count': len(sections),
            'entropy_max': max(section_entropies) if section_entropies else 0,
            'entropy_avg': sum(section_entropies) / len(section_entropies) if section_entropies else 0,
            'has_rwx': any(s['IsRWX'] for s in sections),
            'has_writable_executable': any(s['IsWritable'] and s['IsExecutable'] for s in sections),
        }
    
    # ========================================================================
    # 3. IMPORT TABLE FEATURES
    # ========================================================================
    
    def _extract_import_features(self):
        """
        Extract the import table - which DLLs and functions this PE calls.
        This is a critical signal for ML models.
        """
        # Risky APIs that Defender looks for
        RISKY_APIS = [
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
            'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
            'NtCreateThreadEx', 'NtAllocateVirtualMemory', 'NtWriteVirtualMemory',
            'NtProtectVirtualMemory', 'NtUnmapViewOfSection', 'SetThreadContext',
            'QueueUserAPC', 'OpenProcess', 'CreateProcess', 'WinExec',
            'ShellExecute', 'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW',
            'GetProcAddress', 'GetModuleHandle', 'CreateToolhelp32Snapshot',
            'Process32First', 'Process32Next', 'MiniDumpWriteDump'
        ]
        
        imports = []
        dlls = set()
        risky_api_count = 0
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                dlls.add(dll_name)
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        imports.append({
                            'DLL': dll_name,
                            'Function': func_name,
                            'RVA': imp.address
                        })
                        
                        # Check if risky
                        if any(risky in func_name for risky in RISKY_APIS):
                            risky_api_count += 1
        
        self.features['imports'] = {
            'total_imports': len(imports),
            'dll_count': len(dlls),
            'dlls': list(dlls),
            'risky_api_count': risky_api_count,
            'import_list': imports,
            'has_risky_apis': risky_api_count > 0,
        }
        
        # Imphash - used by ML for family clustering
        try:
            self.features['imports']['imphash'] = self.pe.get_imphash()
        except:
            self.features['imports']['imphash'] = None
    
    # ========================================================================
    # 4. EXPORT TABLE FEATURES
    # ========================================================================
    
    def _extract_export_features(self):
        """
        Extract the export table - what functions this DLL provides.
        Only relevant for DLLs, but some EXEs also export.
        """
        exports = []
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            if self.pe.DIRECTORY_ENTRY_EXPORT:
                exp = self.pe.DIRECTORY_ENTRY_EXPORT
                self.features['exports'] = {
                    'export_count': exp.struct.NumberOfFunctions,
                    'name_count': exp.struct.NumberOfNames,
                    'dll_name': exp.struct.Name.decode('utf-8', errors='ignore') if exp.struct.Name else '',
                }
                
                for exp_entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    name = exp_entry.name.decode('utf-8', errors='ignore') if exp_entry.name else None
                    exports.append({
                        'name': name,
                        'ordinal': exp_entry.ordinal,
                        'address': exp_entry.address,
                        'forwarder': exp_entry.forwarder,
                    })
                
                self.features['exports']['symbols'] = exports
            else:
                self.features['exports'] = {'export_count': 0, 'name_count': 0}
        else:
            self.features['exports'] = {'export_count': 0, 'name_count': 0}
    
    # ========================================================================
    # 5. RICH HEADER FEATURES
    # ========================================================================
    
    def _extract_rich_header(self):
        """
        Extract the Rich Header - an undocumented MSVC linker fingerprint.
        This is a strong signal for ML models.
        """
        self.features['rich_header'] = {
            'present': False,
            'key': 0,
            'entries': []
        }
        
        dos = self.pe.DOS_HEADER
        nt_offset = dos.e_lfanew
        data = self.raw_data
        
        # Search for 'Rich' marker
        rich_key = None
        rich_start = None
        
        for i in range(0x40, nt_offset - 4, 4):
            if i + 8 <= len(data):
                if data[i:i+4] == b'Rich':
                    rich_key = struct.unpack('<I', data[i+4:i+8])[0]
                    # Search backwards for 'DanS' marker
                    for j in range(i - 4, 0x40, -4):
                        if j + 4 <= len(data):
                            val = struct.unpack('<I', data[j:j+4])[0]
                            if (val ^ rich_key) == 0x536E6144:  # 'DanS'
                                rich_start = j + 4
                                break
                    break
        
        if rich_key is not None and rich_start is not None:
            self.features['rich_header']['present'] = True
            self.features['rich_header']['key'] = rich_key
            
            # Decode entries
            i = rich_start
            while i < nt_offset - 4:
                val = struct.unpack('<I', data[i:i+4])[0]
                if (val ^ rich_key) == 0x52696368:  # 'Rich' marker
                    break
                comp_id = val ^ rich_key
                count = struct.unpack('<I', data[i+4:i+8])[0] ^ rich_key
                self.features['rich_header']['entries'].append({
                    'component_id': comp_id,
                    'count': count,
                    'product_id': (comp_id >> 16) & 0xFFFF,
                    'build_number': comp_id & 0xFFFF,
                })
                i += 8
    
    # ========================================================================
    # 6. RESOURCE FEATURES
    # ========================================================================
    
    def _extract_resource_features(self):
        """
        Extract resources - version info, icons, manifests, etc.
        ML models check for the presence of legitimate resources.
        """
        resources = {
            'has_version_info': False,
            'has_icon': False,
            'has_manifest': False,
            'has_any': False,
            'resource_count': 0,
            'resource_types': []
        }
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                res_type = entry.id
                resources['resource_types'].append(res_type)
                resources['resource_count'] += 1
                
                # RT_VERSION = 16
                if res_type == 16:
                    resources['has_version_info'] = True
                # RT_ICON = 3
                elif res_type == 3:
                    resources['has_icon'] = True
                # RT_MANIFEST = 24
                elif res_type == 24:
                    resources['has_manifest'] = True
            
            resources['has_any'] = resources['resource_count'] > 0
        
        self.features['resources'] = resources
    
    # ========================================================================
    # 7. FILE-LEVEL FEATURES
    # ========================================================================
    
    def _extract_file_features(self):
        """
        Extract file-level features like size, overlay, hashes.
        """
        file_size = len(self.raw_data)
        header_size = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        raw_data_size = sum(s.SizeOfRawData for s in self.pe.sections)
        overlay_size = max(0, file_size - header_size - raw_data_size)
        
        self.features['file_info'] = {
            'file_size': file_size,
            'header_size': header_size,
            'raw_data_size': raw_data_size,
            'overlay_size': overlay_size,
            'has_overlay': overlay_size > 0,
            
            # File hashes
            'md5': hashlib.md5(self.raw_data).hexdigest(),
            'sha1': hashlib.sha1(self.raw_data).hexdigest(),
            'sha256': hashlib.sha256(self.raw_data).hexdigest(),
        }
        
        # Fuzzy hash (ssdeep) - difficult without external lib, skip for now
    
    # ========================================================================
    # 8. STRING FEATURES
    # ========================================================================
    
    def _extract_string_features(self):
        """
        Extract embedded strings from the PE file.
        """
        suspicious_patterns = [
            'http://', 'https://', '.com', '.net', '.org',
            'cmd.exe', 'powershell', 'reg add', 'sc create',
            'schtasks', 'whoami', 'ipconfig', 'net user',
            'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread',
            'LoadLibrary', 'GetProcAddress', 'NtCreateThreadEx',
            '.onion', 'tor', 'telegram', 'api.telegram'
        ]
        
        # Extract ASCII strings (minimum 4 characters)
        strings = []
        current = []
        
        for byte in self.raw_data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    strings.append(''.join(current))
                current = []
        
        # Check for suspicious patterns
        found_patterns = []
        for pattern in suspicious_patterns:
            for s in strings:
                if pattern.lower() in s.lower():
                    found_patterns.append(pattern)
                    break
        
        self.features['strings'] = {
            'total_count': len(strings),
            'avg_length': sum(len(s) for s in strings) / len(strings) if strings else 0,
            'suspicious_patterns': found_patterns,
            'has_suspicious': len(found_patterns) > 0,
        }
    
    # ========================================================================
    # 9. ENTROPY FEATURES
    # ========================================================================
    
    def _extract_entropy_features(self):
        """
        Compute overall entropy features.
        """
        overall_entropy = self._compute_entropy(self.raw_data)
        self.features['entropy'] = {
            'overall': overall_entropy,
            'is_high': overall_entropy > 7.5,  # High entropy indicates packing
            'is_low': overall_entropy < 4.0,
        }
    
    # ========================================================================
    # 10. ML FEATURE VECTOR (Normalized)
    # ========================================================================
    
    def to_feature_vector(self) -> List[float]:
        """
        Convert extracted features to a normalized numeric vector.
        This is what you'll use in your genetic algorithm.
        
        Returns:
            List of 15+ normalized features (0.0 to 1.0)
        """
        fv = []
        
        # 1. Section count (normalized)
        fv.append(min(self.features['section_stats']['count'] / 20.0, 1.0))
        
        # 2. Average section entropy (normalized to 8.0 max)
        fv.append(self.features['section_stats']['entropy_avg'] / 8.0)
        
        # 3. Max section entropy (normalized)
        fv.append(self.features['section_stats']['entropy_max'] / 8.0)
        
        # 4. Overall entropy (normalized)
        fv.append(self.features['entropy']['overall'] / 8.0)
        
        # 5. Import count (normalized to 200 max)
        fv.append(min(self.features['imports']['total_imports'] / 200.0, 1.0))
        
        # 6. Risky API count (normalized to 10 max)
        fv.append(min(self.features['imports']['risky_api_count'] / 10.0, 1.0))
        
        # 7. Has RWX section (0 or 1)
        fv.append(1.0 if self.features['section_stats']['has_rwx'] else 0.0)
        
        # 8. Has ASLR (0 or 1)
        fv.append(1.0 if self.features['security_flags']['ASLR'] else 0.0)
        
        # 9. Has DEP (0 or 1)
        fv.append(1.0 if self.features['security_flags']['DEP'] else 0.0)
        
        # 10. Rich Header present (0 or 1)
        fv.append(1.0 if self.features['rich_header']['present'] else 0.0)
        
        # 11. Has version info (0 or 1)
        fv.append(1.0 if self.features['resources']['has_version_info'] else 0.0)
        
        # 12. Has any resource (0 or 1)
        fv.append(1.0 if self.features['resources']['has_any'] else 0.0)
        
        # 13. Timestamp plausibility (0=invalid, 1=valid)
        if self.features['timestamp_plausibility'] == 'Plausible':
            fv.append(1.0)
        else:
            fv.append(0.0)
        
        # 14. Has overlay (0 or 1)
        fv.append(1.0 if self.features['file_info']['has_overlay'] else 0.0)
        
        # 15. Rich entry count (normalized to 20 max)
        fv.append(min(len(self.features['rich_header']['entries']) / 20.0, 1.0))
        
        # 16. Is DLL (0 or 1)
        fv.append(1.0 if self.features['security_flags']['IsDLL'] else 0.0)
        
        # 17. Has suspicious strings (0 or 1)
        fv.append(1.0 if self.features['strings']['has_suspicious'] else 0.0)
        
        # 18. File size indicator (normalized to 50MB)
        fv.append(min(self.features['file_info']['file_size'] / (50 * 1024 * 1024), 1.0))
        
        return fv
    
    # ========================================================================
    # 11. UTILITY METHODS
    # ========================================================================
    
    def _compute_entropy(self, data: bytes) -> float:
        """
        Compute Shannon entropy of byte data.
        Higher entropy = more random = often indicates packing/encryption.
        
        Entropy range: 0.0 (completely predictable) to 8.0 (completely random)
        """
        if not data:
            return 0.0
        
        freq = Counter(data)
        n = len(data)
        entropy = 0.0
        
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        
        return entropy
    
    def to_dict(self) -> Dict:
        """Return all features as a dictionary."""
        return self.features


# ========================================================================
# MAIN EXECUTION (for testing)
# ========================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pe_parser.py <path_to_pe_file>")
        print("Example: python pe_parser.py malware.exe")
        sys.exit(1)
    
    # Initialize the extractor
    extractor = PEFeatureExtractor(sys.argv[1])
    
    # Extract all features
    features = extractor.extract_all()
    
    # Print summary
    print("\n" + "="*60)
    print("PE FEATURE EXTRACTION SUMMARY")
    print("="*60)
    
    # Section stats
    print(f"\n[Section Stats]")
    print(f"  Section count: {features['section_stats']['count']}")
    print(f"  Avg entropy: {features['section_stats']['entropy_avg']:.3f}")
    print(f"  Max entropy: {features['section_stats']['entropy_max']:.3f}")
    print(f"  Has RWX: {features['section_stats']['has_rwx']}")
    
    # Import stats
    print(f"\n[Import Stats]")
    print(f"  Total imports: {features['imports']['total_imports']}")
    print(f"  DLL count: {features['imports']['dll_count']}")
    print(f"  Risky APIs: {features['imports']['risky_api_count']}")
    print(f"  Imphash: {features['imports']['imphash']}")
    
    # Rich Header
    print(f"\n[Rich Header]")
    print(f"  Present: {features['rich_header']['present']}")
    if features['rich_header']['present']:
        print(f"  Entries: {len(features['rich_header']['entries'])}")
    
    # Resources
    print(f"\n[Resources]")
    print(f"  Has version info: {features['resources']['has_version_info']}")
    print(f"  Has any resource: {features['resources']['has_any']}")
    
    # Feature Vector
    print(f"\n[Feature Vector (for ML)]")
    fv = extractor.to_feature_vector()
    print(f"  Dimension: {len(fv)}")
    print(f"  Values: {[round(v, 3) for v in fv[:10]]}... (first 10)")
    
    # Save to file
    import json
    output_file = sys.argv[1] + "_features.json"
    with open(output_file, 'w') as f:
        json.dump(features, f, indent=2, default=str)
    print(f"\n[+] Features saved to: {output_file}")
    
    print("\n" + "="*60)
    print("DONE")
