"""
Generate benign and suspicious test files for ransomware detection testing
- Benign: Copy real system executables
- Suspicious: Synthetically generated PE files
"""

import shutil
import os
import struct
from pathlib import Path

def create_benign_files():
    """Copy known clean system files to testfolder"""
    
    testfolder = "testfolder"
    os.makedirs(testfolder, exist_ok=True)
    
    # Known clean Windows system files
    known_clean_files = [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\calc.exe",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\user32.dll",
        r"C:\Windows\System32\gdi32.dll"
    ]
    
    print("[*] Creating benign test files...")
    for file_path in known_clean_files:
        try:
            if os.path.exists(file_path):
                dest_path = os.path.join(testfolder, os.path.basename(file_path))
                shutil.copy2(file_path, dest_path)
                print(f"[+] Copied: {os.path.basename(file_path)}")
            else:
                print(f"[!] File not found: {file_path}")
        except Exception as e:
            print(f"[!] Error copying {file_path}: {e}")

def create_suspicious_files():
    """Generate suspicious PE executables"""
    
    testfolder = "testfolder"
    os.makedirs(testfolder, exist_ok=True)
    
    def write_pe_file(filename, is_dll=False):
        """Create synthetic PE file"""
        try:
            # MZ header
            mz_header = b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80)
            
            # PE header
            pe_signature = b'PE\x00\x00'
            # Characteristics: 0x0102 for EXE, 0x2102 for DLL
            characteristics = b'\x02\x01' if not is_dll else b'\x02\x21'
            file_header = b'\x4C\x01' + b'\x01\x00' + b'\x00' * 12 + b'\xE0\x00' + characteristics
            optional_header = b'\x0B\x01' + b'\x00' * 222
            
            section_header = (
                b'.text\x00\x00\x00' +
                struct.pack('<I', 0x1000) +
                struct.pack('<I', 0x1000) +
                struct.pack('<I', 0x200) +
                struct.pack('<I', 0x400) +
                b'\x00' * 16 +
                struct.pack('<I', 0xE0000020)
            )
            
            # Random section data (high entropy)
            section_data = os.urandom(0x200)
            
            # Write PE file
            with open(filename, "wb") as f:
                f.write(mz_header)
                f.seek(0x80)
                f.write(pe_signature)
                f.write(file_header)
                f.write(optional_header)
                f.write(section_header)
                f.seek(0x400)
                f.write(section_data)
            
            file_type = "DLL" if is_dll else "EXE"
            print(f"[+] Created suspicious {file_type}: {os.path.basename(filename)}")
        except Exception as e:
            print(f"[!] Error creating {filename}: {e}")
    
    print("[*] Creating suspicious test files...")
    write_pe_file(os.path.join(testfolder, "suspicious.exe"), is_dll=False)
    write_pe_file(os.path.join(testfolder, "suspicious.dll"), is_dll=True)

def main():
    """Generate all test files"""
    print("="*60)
    print("Generating Test Files for Ransomware Detection")
    print("="*60 + "\n")
    
    create_benign_files()
    print()
    create_suspicious_files()
    
    print("\n[✓] Test file generation complete!")
    print(f"[*] Test files location: testfolder/")

if __name__ == "__main__":
    main()
