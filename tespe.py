import os
import pefile
import pandas as pd
import hashlib
import math
import array as arr

def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = arr.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy += p_x*math.log(p_x, 2)

    return entropy

class PEFile:
    # representation of PE file
    def __init__(self, filename):
        with open(filename, "rb") as file_content:
            self.pe = pefile.PE(data=file_content.read(), fast_load=True)

        # IMAGE_DOS_HEADER
        self.md5hash = md5sum(filename)
        self.e_magic = self.pe.DOS_HEADER.e_magic
        self.e_cblp = self.pe.DOS_HEADER.e_cblp
        self.e_cp = self.pe.DOS_HEADER.e_cp
        self.e_crlc = self.pe.DOS_HEADER.e_crlc
        self.e_cparhdr = self.pe.DOS_HEADER.e_cparhdr
        self.e_minalloc = self.pe.DOS_HEADER.e_minalloc
        self.e_maxalloc = self.pe.DOS_HEADER.e_maxalloc
        self.e_ss = self.pe.DOS_HEADER.e_ss
        self.e_sp = self.pe.DOS_HEADER.e_sp
        self.e_csum = self.pe.DOS_HEADER.e_csum
        self.e_ip = self.pe.DOS_HEADER.e_ip
        self.e_cs = self.pe.DOS_HEADER.e_cs
        self.e_lfarlc = self.pe.DOS_HEADER.e_lfarlc
        self.e_ovno = self.pe.DOS_HEADER.e_ovno
        # self.e_res = self.pe.DOS_HEADER.e_res
        self.e_oemid = self.pe.DOS_HEADER.e_oemid
        self.e_oeminfo = self.pe.DOS_HEADER.e_oeminfo
        # self.e_res2 = self.pe.DOS_HEADER.e_res2
        self.e_lfanew = self.pe.DOS_HEADER.e_lfanew

        # FILE_HEADER
        self.Machine = self.pe.FILE_HEADER.Machine
        self.NumberOfSections = self.pe.FILE_HEADER.NumberOfSections
        self.TimeDateStamp = self.pe.FILE_HEADER.TimeDateStamp
        self.PointerToSymbolTable = self.pe.FILE_HEADER.PointerToSymbolTable
        self.NumberOfSymbols = self.pe.FILE_HEADER.NumberOfSymbols
        self.SizeOfOptionalHeader = self.pe.FILE_HEADER.SizeOfOptionalHeader
        self.Characteristics = self.pe.FILE_HEADER.Characteristics

        # OPTIONAL_HEADER
        self.Magic = self.pe.OPTIONAL_HEADER.Magic
        self.MajorLinkerVersion = self.pe.OPTIONAL_HEADER.MajorLinkerVersion
        self.MinorLinkerVersion = self.pe.OPTIONAL_HEADER.MinorLinkerVersion
        self.SizeOfCode = self.pe.OPTIONAL_HEADER.SizeOfCode
        self.SizeOfInitializedData = self.pe.OPTIONAL_HEADER.SizeOfInitializedData
        self.SizeOfUninitializedData = self.pe.OPTIONAL_HEADER.SizeOfUninitializedData
        self.AddressOfEntryPoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.BaseOfCode = self.pe.OPTIONAL_HEADER.BaseOfCode
        self.BaseOfData = self.pe.OPTIONAL_HEADER.BaseOfData
        self.ImageBase = self.pe.OPTIONAL_HEADER.ImageBase
        self.SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        self.FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
        self.MajorOperatingSystemVersion = self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        self.MinorOperatingSystemVersion = self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        self.MajorImageVersion = self.pe.OPTIONAL_HEADER.MajorImageVersion
        self.MinorImageVersion = self.pe.OPTIONAL_HEADER.MinorImageVersion
        self.MajorSubsystemVersion = self.pe.OPTIONAL_HEADER.MajorSubsystemVersion
        self.MinorSubsystemVersion = self.pe.OPTIONAL_HEADER.MinorSubsystemVersion
        self.Reserved1 = self.pe.OPTIONAL_HEADER.Reserved1
        self.SizeOfImage = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        self.CheckSum = self.pe.OPTIONAL_HEADER.CheckSum
        self.Subsystem = self.pe.OPTIONAL_HEADER.Subsystem
        self.DllCharacteristics = self.pe.OPTIONAL_HEADER.DllCharacteristics
        self.SizeOfStackReserve = self.pe.OPTIONAL_HEADER.SizeOfStackReserve
        self.SizeOfStackCommit = self.pe.OPTIONAL_HEADER.SizeOfStackCommit
        self.SizeOfHeapReserve = self.pe.OPTIONAL_HEADER.SizeOfHeapReserve
        self.SizeOfHeapCommit = self.pe.OPTIONAL_HEADER.SizeOfHeapCommit
        self.LoaderFlags = self.pe.OPTIONAL_HEADER.LoaderFlags
        self.NumberOfRvaAndSizes = self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        # SECTION
        self.SectionLength = len(self.pe.sections)
        entropy = list(map(lambda x:x.get_entropy(), self.pe.sections))
        self.SectionMeanEntropy = sum(entropy)/float(len(entropy))
        self.SectionMinEntropy = min(entropy)
        self.SectionMaxEntropy = max(entropy)
        raw_size = list(map(lambda x: x.SizeOfRawData, self.pe.sections))
        self.SectionMeanRawSize = sum(raw_size) / float(len(raw_size))
        self.SectionMinRawSize = min(raw_size)
        self.SectionMaxRawSize = max(raw_size)
        virtual_size = list(map(lambda x: x.Misc_VirtualSize, self.pe.sections))
        self.SectionMeanVirtualSize = sum(virtual_size) / float(len(virtual_size))
        self.SectionMinVirtualSize = min(virtual_size)
        self.SectionMaxVirtualSize = max(virtual_size)
        physical_size = list(map(lambda x: x.Misc_PhysicalAddress, self.pe.sections))
        self.SectionMeanPhysicalSize = sum(virtual_size) / float(len(virtual_size))
        self.SectionMinPhysicalSize = min(physical_size)
        self.SectionMaxPhysicalSize = max(physical_size)
        virtual_address = list(map(lambda x: x.VirtualAddress, self.pe.sections))
        self.SectionMeanVirtualAddress = sum(virtual_address) / float(len(virtual_address))
        self.SectionMinVirtualAddress = min(virtual_address)
        self.SectionMaxVirtualAddress = max(virtual_address)
        pointer_data = list(map(lambda x: x.PointerToRawData, self.pe.sections))
        self.SectionMeanPointerToRawData = sum(pointer_data) / float(len(pointer_data))
        self.SectionMinPointerToRawData = min(pointer_data)
        self.SectionMaxPointerToRawData = max(pointer_data)
        pointer_data = list(map(lambda x: x.PointerToRawData, self.pe.sections))
        self.SectionMeanPointerToRawData = sum(pointer_data) / float(len(pointer_data))
        self.SectionMinPointerToRawData = min(pointer_data)
        self.SectionMaxPointerToRawData = max(pointer_data)
        char = list(map(lambda x: x.Characteristics, self.pe.sections))
        self.SectionMeanCharacteristics = sum(char) / float(len(char))
        self.SectionMinCharacteristics = min(char)
        self.SectionMaxCharacteristics = max(char)

        # RVA
        # for data_directory in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        #     print('\t' + data_directory.name)
        self.SizeImageDirEntryExport = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        self.RVAImageDirEntryExport = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
        self.SizeImageDirEntryImport = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
        self.RVAImageDirEntryImport = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
        self.SizeImageDirEntryResource = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
        self.RVAImageDirEntryResource = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress
        self.SizeImageDirEntryException = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size
        self.RVAImageDirEntryException = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress
        self.SizeImageDirEntrySECURITY = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
        self.RVAImageDirEntrySECURITY = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress

        # Directory
        self.pe.parse_data_directories()
        count_f = 0
        count_m = 0
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            # print (entry.dll)
            count_f += 1
            for xx in entry.imports:
                # print ('\t', hex(xx.address), imp.name)
                count_m += 1
        self.SumImportFunction = count_f
        self.SumImportFunctionMethod = count_m

        file_content.close()
        print("Load File")

    def Construct(self):
        sample = {}
        for feature, value in self.__dict__.items():
            if (feature != "pe"):
                sample[feature] = value
        print("Extract Feature completed")
        return sample

def pe2vec():
    # dataset is a python dictionary which store the key value mapping
    dataset = {}

    # Recursively search for files within a specified directory and its subdir
    directory = "/home/x/ta/dataset/"
    for subdir, dirs, files in os.walk(directory):
        for f in files:
            file_path = os.path.join(subdir, f)
            try:
                # read PE file using PEFILE module
                pe = PEFile(file_path)
                # pe.construct returns a dictionary with features as key and feature value as value
                dataset[str(f)] = pe.Construct()
            except Exception as e:
                print(e)
    return dataset


def saveToCSV(dataset):
    df = pd.DataFrame(dataset)
    mal = df.transpose()
    print(mal.shape)
    mal.to_csv('dataset_m4lw4r3.csv', encoding='utf-8', index=False)


pedata = pe2vec()
saveToCSV(pedata)