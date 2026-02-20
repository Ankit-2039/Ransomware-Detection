"""
Real-Time File Monitor for Ransomware Detection - CLEAN OUTPUT
"""

import os
import sys
import warnings
import pefile
import numpy as np
import joblib
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pymongo import MongoClient
import psutil

# Suppress all output
warnings.filterwarnings('ignore')
import logging
logging.disable(logging.CRITICAL)

# Redirect stderr to suppress joblib output
import io
from contextlib import redirect_stderr

# MongoDB connection
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "ransomware_detection"

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    db = client[DB_NAME]
    threat_collection = db["threat_logs"]
    monitor_collection = db["monitor_logs"]
except Exception as e:
    threat_collection = None
    monitor_collection = None

# Load trained model and scaler with suppressed output
with redirect_stderr(io.StringIO()):
    try:
        model = joblib.load("models/ransomware_model.pkl")
        scaler = joblib.load("models/scaler.pkl")
        n_features = scaler.n_features_in_
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

# EXACT 54 features
FEATURE_NAMES = [
    'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion',
    'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
    'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
    'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
    'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
    'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags',
    'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy', 'SectionsMinEntropy', 'SectionsMaxEntropy',
    'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionMaxRawsize', 'SectionsMeanVirtualsize',
    'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal',
    'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy',
    'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize',
    'VersionInformationSize'
]

def calculate_entropy(data):
    if len(data) == 0:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / len(data)
            entropy -= p * np.log2(p)
    return entropy

def extract_features(file_path):
    try:
        pe = pefile.PE(file_path)
        features = {}
        
        features['Machine'] = pe.FILE_HEADER.Machine
        features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        features['Characteristics'] = pe.FILE_HEADER.Characteristics
        
        features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        features['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
        features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        features['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        
        features['SectionsNb'] = len(pe.sections)
        section_entropies = []
        section_rawsizes = []
        section_virtualsizes = []
        
        for section in pe.sections:
            try:
                data = section.get_data()
                section_entropies.append(calculate_entropy(data))
                section_rawsizes.append(section.SizeOfRawData)
                section_virtualsizes.append(section.Misc_VirtualSize)
            except:
                pass
        
        features['SectionsMeanEntropy'] = np.mean(section_entropies) if section_entropies else 0
        features['SectionsMinEntropy'] = np.min(section_entropies) if section_entropies else 0
        features['SectionsMaxEntropy'] = np.max(section_entropies) if section_entropies else 0
        features['SectionsMeanRawsize'] = np.mean(section_rawsizes) if section_rawsizes else 0
        features['SectionsMinRawsize'] = np.min(section_rawsizes) if section_rawsizes else 0
        features['SectionMaxRawsize'] = np.max(section_rawsizes) if section_rawsizes else 0
        features['SectionsMeanVirtualsize'] = np.mean(section_virtualsizes) if section_virtualsizes else 0
        features['SectionsMinVirtualsize'] = np.min(section_virtualsizes) if section_virtualsizes else 0
        features['SectionMaxVirtualsize'] = np.max(section_virtualsizes) if section_virtualsizes else 0
        
        features['ImportsNbDLL'] = 0
        features['ImportsNb'] = 0
        features['ImportsNbOrdinal'] = 0
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                for dll in pe.DIRECTORY_ENTRY_IMPORT:
                    features['ImportsNb'] += len(dll.imports)
                    for imp in dll.imports:
                        if imp.name is None:
                            features['ImportsNbOrdinal'] += 1
        except:
            pass
        
        features['ExportNb'] = 0
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except:
            pass
        
        features['ResourcesNb'] = 0
        resource_entropies = []
        resource_sizes = []
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    features['ResourcesNb'] += 1
                    try:
                        data = pe.get_data(entry.directory.entries[0].data.struct.OffsetToData, 
                                         entry.directory.entries[0].data.struct.Size)
                        resource_entropies.append(calculate_entropy(data))
                        resource_sizes.append(len(data))
                    except:
                        pass
        except:
            pass
        
        features['ResourcesMeanEntropy'] = np.mean(resource_entropies) if resource_entropies else 0
        features['ResourcesMinEntropy'] = np.min(resource_entropies) if resource_entropies else 0
        features['ResourcesMaxEntropy'] = np.max(resource_entropies) if resource_entropies else 0
        features['ResourcesMeanSize'] = np.mean(resource_sizes) if resource_sizes else 0
        features['ResourcesMinSize'] = np.min(resource_sizes) if resource_sizes else 0
        features['ResourcesMaxSize'] = np.max(resource_sizes) if resource_sizes else 0
        
        features['LoadConfigurationSize'] = 0
        features['VersionInformationSize'] = 0
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except:
            pass
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if entry.struct.Id == 16:
                        features['VersionInformationSize'] = entry.directory.entries[0].data.struct.Size
        except:
            pass
        
        return features
    
    except Exception as e:
        return None

def predict_file(file_path, features):
    try:
        if not features:
            return None, None
        
        feature_vector = np.array([features.get(fname, 0) for fname in FEATURE_NAMES]).reshape(1, -1)
        
        if feature_vector.shape[1] != n_features:
            return None, None
        
        feature_vector_scaled = scaler.transform(feature_vector)
        
        # Suppress all output during prediction
        with redirect_stderr(io.StringIO()):
            prediction = model.predict(feature_vector_scaled)[0]
            confidence = model.predict_proba(feature_vector_scaled)[0].max()
        
        return prediction, confidence
    
    except Exception as e:
        return None, None

def terminate_process(pid):
    try:
        process = psutil.Process(pid)
        process.kill()
        return True
    except:
        return False

def log_threat(file_path, confidence, pids_killed):
    if threat_collection is None:
        return
    
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_path": file_path,
        "prediction": "malware",
        "prediction_confidence": float(confidence),
        "action_taken": "TERMINATED",
        "processes_killed": pids_killed
    }
    
    try:
        threat_collection.insert_one(log_entry)
    except:
        pass

def log_monitor_event(file_path, event_type, prediction_label, confidence):
    if monitor_collection is None:
        return
    
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_path": file_path,
        "event_type": event_type,
        "prediction": "legitimate" if prediction_label == 1 else "malware",
        "confidence": float(confidence)
    }
    
    try:
        monitor_collection.insert_one(log_entry)
    except:
        pass

class MalwareFileHandler(FileSystemEventHandler):
    
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(('.exe', '.dll')):
            self.handle_file(event.src_path, 'created')
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(('.exe', '.dll')):
            self.handle_file(event.src_path, 'modified')
    
    def handle_file(self, file_path, event_type):
        filename = os.path.basename(file_path)
        time.sleep(0.5)
        
        features = extract_features(file_path)
        if features is None:
            return
        
        prediction, confidence = predict_file(file_path, features)
        if prediction is None:
            return
        
        label = "SUSPICIOUS" if prediction == 0 else "BENIGN"
        print(f"[*] {filename:30s} => {label:10s} ({confidence:.2%})")
        
        log_monitor_event(file_path, event_type, prediction, confidence)
        
        if prediction == 0:
            pids_killed = []
            try:
                for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                    try:
                        for open_file in proc.open_files():
                            if open_file.path == file_path:
                                if terminate_process(proc.pid):
                                    pids_killed.append(proc.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except:
                pass
            
            log_threat(file_path, confidence, pids_killed)

def start_monitoring():
    testfolder = "testfolder"
    os.makedirs(testfolder, exist_ok=True)
    
    print("\n" + "="*60)
    print("Ransomware Detection Monitor")
    print("="*60)
    print(f"Monitoring: testfolder/\n")
    
    handler = MalwareFileHandler()
    observer = Observer()
    observer.schedule(handler, path=testfolder, recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitoring()