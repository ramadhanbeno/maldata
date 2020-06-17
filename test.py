import pefile
import os
import hashlib
import array as arr
import math

def get_md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

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


def extract_infos(fpath):
    res = []
    res.append(os.path.basename(fpath))
    res.append(get_md5(fpath))
    pe = pefile.PE(fpath)
    # Image DOS Header
    res.append(pe.DOS_HEADER.e_magic)
    res.append(pe.DOS_HEADER.e_cblp)
    res.append(pe.DOS_HEADER.e_cp)
    res.append(pe.DOS_HEADER.e_crlc)
    res.append(pe.DOS_HEADER.e_cparhdr)
    res.append(pe.DOS_HEADER.e_minalloc)
    res.append(pe.DOS_HEADER.e_maxalloc)
    res.append(pe.DOS_HEADER.e_ss)
    res.append(pe.DOS_HEADER.e_sp)
    res.append(pe.DOS_HEADER.e_csum)
    res.append(pe.DOS_HEADER.e_ip)
    res.append(pe.DOS_HEADER.e_cs)
    res.append(pe.DOS_HEADER.e_lfarlc)
    res.append(pe.DOS_HEADER.e_ovno)
    res.append(pe.DOS_HEADER.e_oemid)
    res.append(pe.DOS_HEADER.e_oeminfo)
    res.append(pe.DOS_HEADER.e_lfanew)
    # FILE HEADER
    res.append(pe.FILE_HEADER.Machine)
    res.append(pe.FILE_HEADER.NumberOfSections)
    res.append(pe.FILE_HEADER.TimeDateStamp)
    res.append(pe.FILE_HEADER.PointerToSymbolTable)
    res.append(pe.FILE_HEADER.NumberOfSymbols)
    res.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    res.append(pe.FILE_HEADER.Characteristics)
    # OPTIONAL_HEADER
    res.append(pe.OPTIONAL_HEADER.Magic)
    res.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    res.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    res.append(pe.OPTIONAL_HEADER.SizeOfCode)
    res.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
    res.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
    res.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    res.append(pe.OPTIONAL_HEADER.BaseOfCode)
    try:
        res.append(pe.OPTIONAL_HEADER.BaseOfData)
    except AttributeError:
        res.append(0)
    res.append(pe.OPTIONAL_HEADER.ImageBase)
    res.append(pe.OPTIONAL_HEADER.SectionAlignment)
    res.append(pe.OPTIONAL_HEADER.FileAlignment)
    res.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    res.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    res.append(pe.OPTIONAL_HEADER.MajorImageVersion)
    res.append(pe.OPTIONAL_HEADER.MinorImageVersion)
    res.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    res.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
    res.append(pe.OPTIONAL_HEADER.Reserved1)
    res.append(pe.OPTIONAL_HEADER.SizeOfImage)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    res.append(pe.OPTIONAL_HEADER.CheckSum)
    res.append(pe.OPTIONAL_HEADER.Subsystem)
    res.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    res.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
    res.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    res.append(pe.OPTIONAL_HEADER.LoaderFlags)
    res.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)

    # Section
    if (len(pe.sections) !=0) :
        res.append(len(pe.sections))
        entropy = list(map(lambda x:x.get_entropy(), pe.sections))
        res.append(sum(entropy)/float(len(entropy)))
        res.append(min(entropy))
        res.append(max(entropy))
        raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
        res.append(sum(raw_sizes)/float(len(raw_sizes)))
        res.append(min(raw_sizes))
        res.append(max(raw_sizes))
        virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
        res.append(sum(virtual_sizes)/float(len(virtual_sizes)))
        res.append(min(virtual_sizes))
        res.append(max(virtual_sizes))
        physical_size = list(map(lambda x:x.Misc_PhysicalAddress, pe.sections))
        res.append(sum(physical_size)/float(len(physical_size)))
        res.append(min(physical_size))
        res.append(max(physical_size))
        virtual_address = list(map(lambda x:x.VirtualAddress, pe.sections))
        res.append(sum(virtual_address)/float(len(virtual_address)))
        res.append(min(virtual_address))
        res.append(max(virtual_address))
        pointer_data = list(map(lambda x:x.PointerToRawData, pe.sections))
        res.append(sum(pointer_data)/float(len(pointer_data)))
        res.append(min(pointer_data))
        res.append(max(pointer_data))
        char = list(map(lambda x:x.Characteristics, pe.sections))
        res.append(sum(char)/float(len(char)))
        res.append(min(char))
        res.append(max(char))
    else :
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)

    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)
    res.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress)

    # Directoey Import
    try:
        pe.parse_data_directories()
        count_f = 0
        count_m = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # print (entry.dll)
            count_f += 1
            for xx in entry.imports:
                # print ('\t', hex(xx.address), xx.name)
                count_m += 1
        res.append(count_f)
        res.append(count_m)
    except AttributeError:
        res.append(0)
        res.append(0)

    return res

if __name__ == '__main__':
    output = "Output_CSV/test.csv"
    csv_delimiter = "|"
    columns = [
        "Name",
        "Md5",
        "e_magic",
        "e_cblp",
        "e_cp",
        "e_crlc",
        "e_cparhdr",
        "e_minalloc",
        "e_maxalloc",
        "e_ss",
        "e_sp",
        "e_csum",
        "e_ip",
        "e_cs",
        "e_lfarlc",
        "e_ovno",
        "e_oemid",
        "e_oeminfo",
        "e_lfanew",
        "Machine",
        "NumberOfSections",
        "TimeDateStamp",
        "PointerToSymbolTable",
        "NumberOfSymbols",
        "SizeOfOptionalHeader",
        "Characteristics",
        "Magic",
        "MajorLinkerVersion",
        "MinorLinkerVersion",
        "SizeOfCode",
        "SizeOfInitializedData",
        "SizeOfUninitializedData",
        "AddressOfEntryPoint",
        "BaseOfCode",
        "BaseOfData",
        "ImageBase",
        "SectionAlignment",
        "FileAlignment",
        "MajorOperatingSystemVersion",
        "MinorOperatingSystemVersion",
        "MajorImageVersion",
        "MinorImageVersion",
        "MajorSubsystemVersion",
        "MinorSubsystemVersion",
        "Reserved1",
        "SizeOfImage",
        "SizeOfHeaders",
        "CheckSum",
        "Subsystem",
        "DllCharacteristics",
        "SizeOfStackReserve",
        "SizeOfStackCommit",
        "SizeOfHeapReserve",
        "SizeOfHeapCommit",
        "LoaderFlags",
        "NumberOfRvaAndSizes",
        "SectionsLength",
        "SectionMeanEntropy",
        "SectionMinEntropy",
        "SectionMaxEntropy",
        "SectionMeanRawsize",
        "SectionMinRawsize",
        "SectionMaxRawsize",
        "SectionMeanVirtualsize",
        "SectionMinVirtualsize",
        "SectionMaxVirtualsize",
        "SectionMeanPhysical",
        "SectionMinPhysical",
        "SectionMaxPhysical",
        "SectionMeanVirtualAddress",
        "SectionMinVirtualAddress",
        "SectionMaxVirtualAddress",
        "SectionMeanPointerData",
        "SectionMinPointerData",
        "SectionMaxPointerData",
        "SectionMeanChar",
        "SectionMinChar",
        "SectionMaxChar",
        "SizeImageDirectoryEntryExport",
        "RVAImageDirectoryEntryExport",
        "SizeImageDirectoryEntryImport",
        "RVAImageDirectoryEntryImport",
        "SizeImageDirectoryEntryResource",
        "RVAImageDirectoryEntryResource",
        "SizeImageDirectoryEntryException",
        "RVAImageDirectoryEntryException",
        "SizeImageDirectoryEntrySecurity",
        "RVAImageDirectoryEntrySecurity",
        "SumImportFunction",
        "SumImportFunctionMethod",

    ]

    ff = open(output, "a")
    ff.write(csv_delimiter.join(columns) + "\n")

    # Launch legitimate
    for ffile in os.listdir('/home/x/ta/dataset/test'):
        print(ffile)
        try:
            res = extract_infos(os.path.join('/home/x/ta/dataset/test', ffile))
            ff.write(csv_delimiter.join(map(lambda x: str(x), res)) + "\n")
        except pefile.PEFormatError:
            print('\t -> Bad PE format')

    ff.close()
# testdata
