import ast
import json
import numpy as np
import torch
import pandas as pd
from torch.utils.data import Dataset, DataLoader
from models.ember_structure import PEFilesDeatils
### pre-processing ready ember structure data exacting features make them Dataloader tensor:
##
#
def preprocessing_data_files(detailed_PE_files: list[PEFilesDeatils]):
    data_dicts = [model.dict() for model in detailed_PE_files]
    df = pd.DataFrame(data_dicts)
    seq_length = 128
    d_model = 512
    batch_size = 64
    eval_loader = create_dataloader(df, seq_length, d_model, batch_size) 
    return eval_loader   


def create_dataloader(df, seq_length, d_model, batch_size=64, shuffle=True):
    """Create a DataLoader from DataFrame."""
    dataset = MalwareDataset(df, seq_length, d_model)
    return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle)


class MalwareDataset(Dataset):
    def __init__(self, df, seq_length, d_model):
        self.df = df
        self.seq_length = seq_length
        self.d_model = d_model

    def __len__(self):
        return len(self.df)

    def __getitem__(self, idx):
        # Get the original row
        row = self.df.iloc[idx]
        # Extract the label before converting to JSON
        label = int(row['label'])
        # Convert the entire row to a JSON string
        row_json = row.to_json()
        # Extract features from the JSON string
        features_tensor = extract_features_from_json(row_json, self.seq_length, self.d_model)
        #print(features_tensor)
        return features_tensor, label


#############################################
# Wrappering to Process JSON Samples
#############################################
def extract_features_from_json(json_str, seq_length=256, d_model=512):
    """
    Converts a JSON string (from a pandas Series.to_json()) into a dictionary
    and extracts features.
    """
    data = json.loads(json_str)
    return extract_features(data, seq_length, d_model)     


#############################################
# Extract and Combine Features
#############################################
def extract_features(row, seq_length=256, d_model=512):
    features = []

    # 1. Extract histogram features (byte frequency distribution)
    try:
        histogram = ast.literal_eval(row['histogram'])
        histogram_norm = np.array(histogram) / max(max(histogram), 1)
        histogram_features = torch.tensor(histogram_norm, dtype=torch.float32)
        if len(histogram_features) > seq_length:
            indices = torch.linspace(0, len(histogram_features)-1, seq_length).long()
            histogram_features = histogram_features[indices]
        else:
            histogram_features = torch.nn.functional.pad(
                histogram_features, (0, seq_length - len(histogram_features))
            )
        features.append(histogram_features)
    except (ValueError, KeyError, TypeError):
        features.append(torch.zeros(seq_length, dtype=torch.float32))

    # 2. Extract byte entropy features
    try:
        byte_entropy = ast.literal_eval(row['byteentropy'])
        byte_entropy_norm = np.array(byte_entropy) / max(max(byte_entropy), 1)
        entropy_features = torch.tensor(byte_entropy_norm, dtype=torch.float32)
        if len(entropy_features) > seq_length:
            indices = torch.linspace(0, len(entropy_features)-1, seq_length).long()
            entropy_features = entropy_features[indices]
        else:
            entropy_features = torch.nn.functional.pad(
                entropy_features, (0, seq_length - len(entropy_features))
            )
        features.append(entropy_features)
    except (ValueError, KeyError, TypeError):
        features.append(torch.zeros(seq_length, dtype=torch.float32))

    # 3. Extract string features
    try:
        string_data = ast.literal_eval(row['strings'])
        string_features = []
        string_features.append(string_data.get('numstrings', 0) / 10000)
        string_features.append(string_data.get('avlength', 0) / 100)
        string_features.append(string_data.get('entropy', 0) / 8)
        string_features.append(string_data.get('paths', 0) / 100)
        string_features.append(string_data.get('urls', 0) / 100)
        string_features.append(string_data.get('registry', 0) / 100)
        string_features.append(string_data.get('MZ', 0) / 100)

        if 'printabledist' in string_data:
            printable_dist = np.array(string_data['printabledist'])
            printable_dist_norm = printable_dist / max(np.max(printable_dist), 1)
            if len(printable_dist_norm) > seq_length - len(string_features):
                indices = np.linspace(0, len(printable_dist_norm)-1, seq_length - len(string_features)).astype(int)
                printable_features = printable_dist_norm[indices]
            else:
                printable_features = np.pad(
                    printable_dist_norm,
                    (0, seq_length - len(string_features) - len(printable_dist_norm))
                )
            string_features.extend(printable_features)

        if len(string_features) < seq_length:
            string_features = np.pad(string_features, (0, seq_length - len(string_features)))

        features.append(torch.tensor(string_features, dtype=torch.float32))
    except (ValueError, KeyError, TypeError):
        features.append(torch.zeros(seq_length, dtype=torch.float32))

    # 4. Extract section information
    try:
        section_data = None
        try:
            section_data = ast.literal_eval(row['section'].replace("'", '"'))
        except Exception as e:
            # If section parsing fails, add zeros and skip the rest of this section
            features.append(torch.zeros(seq_length, dtype=torch.float32))
            return features  # or use "continue" if this is inside a loop
            
        # Only proceed if section_data was successfully parsed
        section_features = []
        entry_section = section_data.get('entry', '')
        common_sections = ['.text', '.data', '.rdata', '.rsrc', '.rsro', '.reloc','UPX0','CODE','rmnet','UPX1']
        for section in common_sections:
            section_features.append(1.0 if entry_section == section else 0.0)

        if 'sections' in section_data:
            sections = section_data['sections']
            total_size = sum(section.get('size', 0) for section in sections)
            total_vsize = sum(section.get('vsize', 0) for section in sections)
            for section_name in common_sections:
                section_found = False
                for section in sections:
                    if section.get('name', '') == section_name:
                        section_found = True
                        section_features.append(section.get('size', 0) / max(total_size, 1))
                        section_features.append(section.get('vsize', 0) / max(total_vsize, 1))
                        section_features.append(section.get('entropy', 0) / 8)
                        props = section.get('props', [])
                        common_props = ['CNT_CODE', 'CNT_INITIALIZED_DATA', 'MEM_EXECUTE', 'MEM_READ', 'MEM_WRITE']
                        for prop in common_props:
                            section_features.append(1.0 if prop in props else 0.0)
                        break
                if not section_found:
                    section_features.extend([0.0] * (3 + 5))

        if len(section_features) < seq_length:
            section_features = np.pad(section_features, (0, seq_length - len(section_features)))
        else:
            section_features = section_features[:seq_length]

        features.append(torch.tensor(section_features, dtype=torch.float32))
    except (ValueError, KeyError, TypeError) as e:
        features.append(torch.zeros(seq_length, dtype=torch.float32))

    # 5. Extract import information
    try:
        import_data = ast.literal_eval(row['imports'])#.replace("'", '"'))
        import_features = []
        total_imports = sum(len(funcs) for funcs in import_data.values())
        import_features.append(total_imports / 500)
        common_dlls = ['KERNEL32.dll', 'USER32.dll', 'ADVAPI32.dll', 'GDI32.dll',
                       'SHELL32.dll', 'ole32.dll', 'COMCTL32.dll', 'VERSION.dll']
        for dll in common_dlls:
            import_features.append(len(import_data.get(dll, [])) / 100)
        suspicious_apis = [
            'CreateProcess', 'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread',
            'RegSetValue', 'RegCreateKey', 'HttpSendRequest', 'InternetOpen',
            'ShellExecute', 'WinExec', 'CreateService', 'socket'
        ]
        for api in suspicious_apis:
            api_found = False
            for dll_funcs in import_data.values():
                if any(api in func for func in dll_funcs):
                    api_found = True
                    break
            import_features.append(1.0 if api_found else 0.0)
        if len(import_features) < seq_length:
            import_features = np.pad(import_features, (0, seq_length - len(import_features)))
        else:
            import_features = import_features[:seq_length]
        features.append(torch.tensor(import_features, dtype=torch.float32))
    except (ValueError, KeyError, TypeError):
        features.append(torch.zeros(seq_length, dtype=torch.float32))

    # 6. Extract header information
    try:
        header_data = ast.literal_eval(row['header'].replace("'", '"'))
        header_features = []
        if 'coff' in header_data:
            coff = header_data['coff']
            header_features.append(coff.get('timestamp', 0) / 2**32)
            machines = ['I386', 'AMD64', 'ARM', 'ARM64']
            machine = coff.get('machine', '')
            for m in machines:
                header_features.append(1.0 if machine == m else 0.0)
            common_chars = [
                'RELOCS_STRIPPED', 'EXECUTABLE_IMAGE', 'LINE_NUMS_STRIPPED',
                'LOCAL_SYMS_STRIPPED', 'AGGRESSIVE_WS_TRIM', 'LARGE_ADDRESS_AWARE',
                'BYTES_REVERSED_LO', 'CHARA_32BIT_MACHINE', 'DEBUG_STRIPPED',
                'REMOVABLE_RUN_FROM_SWAP', 'NET_RUN_FROM_SWAP', 'SYSTEM',
                'DLL', 'UP_SYSTEM_ONLY', 'BYTES_REVERSED_HI'
            ]
            characteristics = coff.get('characteristics', [])
            for char in common_chars:
                header_features.append(1.0 if char in characteristics else 0.0)
        if 'optional' in header_data:
            opt = header_data['optional']
            subsystems = ['WINDOWS_GUI', 'WINDOWS_CUI', 'NATIVE', 'POSIX_CUI', 'WINDOWS_CE_GUI']
            subsystem = opt.get('subsystem', '')
            for sub in subsystems:
                header_features.append(1.0 if subsystem == sub else 0.0)
            common_dll_chars = [
                'DYNAMIC_BASE', 'FORCE_INTEGRITY', 'NX_COMPAT', 'NO_ISOLATION',
                'NO_SEH', 'NO_BIND', 'WDM_DRIVER', 'TERMINAL_SERVER_AWARE'
            ]
            dll_characteristics = opt.get('dll_characteristics', [])
            for char in common_dll_chars:
                header_features.append(1.0 if char in dll_characteristics else 0.0)
            magic_types = ['PE32', 'PE32+']
            magic = opt.get('magic', '')
            for m in magic_types:
                header_features.append(1.0 if magic == m else 0.0)
            header_features.append(opt.get('major_image_version', 0) / 10)
            header_features.append(opt.get('minor_image_version', 0) / 10)
            header_features.append(opt.get('major_linker_version', 0) / 10)
            header_features.append(opt.get('minor_linker_version', 0) / 10)
            header_features.append(opt.get('major_operating_system_version', 0) / 10)
            header_features.append(opt.get('minor_operating_system_version', 0) / 10)
            header_features.append(opt.get('major_subsystem_version', 0) / 10)
            header_features.append(opt.get('minor_subsystem_version', 0) / 10)
            header_features.append(opt.get('sizeof_code', 0) / 1000000)
            header_features.append(opt.get('sizeof_headers', 0) / 1000000)
            header_features.append(opt.get('sizeof_heap_commit', 0) / 1000000)
        if len(header_features) < seq_length:
            header_features = np.pad(header_features, (0, seq_length - len(header_features)))
        else:
            header_features = header_features[:seq_length]
        features.append(torch.tensor(header_features, dtype=torch.float32))
    except (ValueError, KeyError, TypeError):
        features.append(torch.zeros(seq_length, dtype=torch.float32))

    # 7. Extract general information
    try:
        general_data = json.loads(row['general'])
        general_features = []
        general_features.append(general_data.get('size', 0) / 10000000)
        general_features.append(general_data.get('vsize', 0) / 10000000)
        general_features.append(general_data.get('has_debug', 0))
        general_features.append(general_data.get('has_resources', 0))
        general_features.append(general_data.get('has_signature', 0))
        general_features.append(general_data.get('exports', 0) / 1000)
        general_features.append(general_data.get('imports', 0) / 1000)
        if len(general_features) < seq_length:
            general_features = np.pad(general_features, (0, seq_length - len(general_features)))
        else:
            general_features = general_features[:seq_length]
        features.append(torch.tensor(general_features, dtype=torch.float32))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        features.append(torch.zeros(seq_length, dtype=torch.float32))

    combined_features = torch.stack(features)

    if combined_features.shape[0] * combined_features.shape[1] != d_model:
        flat_features = combined_features.flatten()
        if len(flat_features) > d_model:
            flat_features = flat_features[:d_model]
        else:
            flat_features = torch.nn.functional.pad(
                flat_features, (0, d_model - len(flat_features))
            )
        result_tensor = flat_features.reshape(1, d_model)
    else:
        result_tensor = combined_features.reshape(1, d_model)

    return result_tensor