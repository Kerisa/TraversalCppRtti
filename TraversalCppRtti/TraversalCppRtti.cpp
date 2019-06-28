// read.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>

using namespace std;

namespace Detail
{
#define CONTENT_OFFSET(type, member) ((uint32_t)&(((type*)0)->##member))

typedef struct _TypeDescriptor {
    void* pVFTable;     // points to type_info's vftable
    unsigned long spare;
    char name[1];
} _TypeDescriptor;

typedef const struct _s__RTTICompleteObjectLocator {
    unsigned long signature;
    unsigned long offset;     // offset of vtable within the class
    unsigned long cdOffset;
    _TypeDescriptor *pTypeDescriptor;     // class info
    __RTTIClassHierarchyDescriptor *pClassHierarchyDescriptor;  // class inherarchy info
} __RTTICompleteObjectLocator;

typedef const struct _s__RTTIClassHierarchyDescriptor {
    unsigned long signature;
    unsigned long attributes;       // Bit 0: multiple inheritance, Bit 1: virtual inheritance
    unsigned long numBaseClasses;   // count of base classed, includes self
    __RTTIBaseClassArray *pBaseClassArray;
} __RTTIClassHierarchyDescriptor;

#pragma warning (disable:4200)
typedef const struct _s__RTTIBaseClassArray {
    __RTTIBaseClassDescriptor *arrayOfBaseClassDescriptors[];
} __RTTIBaseClassArray;
#pragma warning (default:4200)

typedef struct _PMD {
    unsigned long mdisp; // vftable offset
    unsigned long pdisp; // vbtable offset(-1: vftable is at displacement mdisp inside the class)
    unsigned long vdisp; // base class vftable pointer inside the vbtable
} _PMD;

typedef const struct _s__RTTIBaseClassDescriptor {
    _TypeDescriptor *pTypeDescriptor;
    unsigned long numContainedBases;
    _PMD where;
    unsigned long attributes;
    __RTTIClassHierarchyDescriptor* pClassDescriptor;
} __RTTIBaseClassDescriptor;

string Dump(_s__RTTICompleteObjectLocator* rtti)
{
    string msg;
    char buf[256];
    sprintf_s(buf, sizeof(buf), R"(signature: %#x
offset: %#x
cdOffset: %#x
TypeDescriptor:
pVFTable: %#x
spare: %#x
name: %s
)", rtti->signature, rtti->offset, rtti->cdOffset, (uint32_t)rtti->pTypeDescriptor->pVFTable, rtti->pTypeDescriptor->spare, rtti->pTypeDescriptor->name);
    msg += buf;

    if (!rtti->pClassHierarchyDescriptor && !IsBadReadPtr(rtti->pClassHierarchyDescriptor, 4))
    {
        msg += "RTTIClassHierarchyDescriptor: <null>";
    }
    else
    {
        // multiple inheritance, Bit 1: virtual inheritance
        bool multiple = rtti->pClassHierarchyDescriptor->attributes & 0x1;
        bool virt = rtti->pClassHierarchyDescriptor->attributes & 0x2;
        string attrib = (multiple ? "<multiple inheritance>" : "");
        attrib += (virt ? ", <virtual inheritance>" : "");
        if (attrib.empty())
            attrib = "<normal>";
        sprintf_s(buf, sizeof(buf), R"(RTTIClassHierarchyDescriptor:
signature: %#x
attributes: %s
numBaseClasses: %#x
)", rtti->pClassHierarchyDescriptor->signature, attrib.c_str(), rtti->pClassHierarchyDescriptor->numBaseClasses);
        msg += buf;
        msg += "  Base Classes:\n";
        for (int i = 0; i < rtti->pClassHierarchyDescriptor->numBaseClasses; ++i)
        {
            auto desc = rtti->pClassHierarchyDescriptor->pBaseClassArray->arrayOfBaseClassDescriptors[i];
            sprintf_s(buf, sizeof(buf), R"(  <%x>
pVFTable: %#x
name: %s
)", i + 1, (uint32_t)desc->pTypeDescriptor->pVFTable, desc->pTypeDescriptor->name);
            msg += buf;
        }
    }
    return msg;
}

uint32_t GetImageBaseInPEHeader(const vector<uint8_t>& peData)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peData.data();
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(peData.data() + pDosHeader->e_lfanew);
    return pNtHeader->OptionalHeader.ImageBase;
}

uint32_t GetFileAddrBelongSectionIndex(const vector<uint8_t>& peData, uint32_t addr)
{
    assert(addr < peData.size());
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peData.data();
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(peData.data() + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)(peData.data() + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
    {
        if ((addr >= pSecHeader[i].PointerToRawData) &&
            (addr <= pSecHeader[i].PointerToRawData + pSecHeader[i].SizeOfRawData))
        {
            // 内存偏移 = 所在区块的内存偏移 + （该偏移 - 所在区块的文件偏移）
            return i;
        }
    }
    return -1;
}

uint32_t RVAToFileOffset(const vector<uint8_t>& peData, uint32_t offset)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peData.data();
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(peData.data() + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)(peData.data() + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    // 内存偏移转换为文件偏移

    // 若在PE头内，则两个偏移相同
    if (offset <= pNtHeader->OptionalHeader.SizeOfHeaders)
    {
        return offset;
    }
    // 不在PE头里，查看该地址在哪个区块中
    else
    {
        for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
        {
            DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
            if (offset >= pSecHeader[i].VirtualAddress)
            {
                if (offset <= pSecHeader[i].VirtualAddress + pSecHeader[i].SizeOfRawData)
                {
                    // 文件偏移 = 该区块的文件偏移 + （该偏移 - 该区块的内存偏移）
                    return pSecHeader[i].PointerToRawData + offset - pSecHeader[i].VirtualAddress;
                }
                else if (offset <= pSecHeader[i].VirtualAddress + pSecHeader[i].Misc.VirtualSize)
                {
                    // 在文件中没有对应的数据，装载时初始化为 0 
                    assert(pSecHeader[i].Misc.VirtualSize > pSecHeader[i].SizeOfRawData);
                    return (uint32_t)-2;
                }
            }
        }
    }
    return (uint32_t)-1;
}

uint32_t FileOffsetToRVA(const vector<uint8_t>& peData, uint32_t offset)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peData.data();
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(peData.data() + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)(peData.data() + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    // 内存偏移转换为文件偏移

    // 若在PE头内，则两个偏移相同
    if (offset <= pNtHeader->OptionalHeader.SizeOfHeaders)
    {
        return offset;
    }
    // 不在PE头里，查看该地址在哪个区块中
    else
    {
        for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
        {
            if ((offset >= pSecHeader[i].PointerToRawData) &&
                (offset <= pSecHeader[i].PointerToRawData + pSecHeader[i].SizeOfRawData))
            {
                // 内存偏移 = 所在区块的内存偏移 + （该偏移 - 所在区块的文件偏移）
                return pSecHeader[i].VirtualAddress + offset - pSecHeader[i].PointerToRawData;
            }
        }
    }
    return (uint32_t)-1;
}

// return vtable rva
uint32_t FindSingleRttiInPEFile(const vector<uint8_t>& fileData, const char* className)
{
    return 0;
}
} // end namespace Detail

vector<uint8_t> GetFileData(char* path)
{
    DWORD R;
    HANDLE hExe = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    vector<uint8_t> fileData(GetFileSize(hExe, NULL));
    ReadFile(hExe, fileData.data(), fileData.size(), &R, NULL);
    CloseHandle(hExe);
    return fileData;
}

uint32_t FindFirstReferenceInMem(uint32_t from, uint32_t to, uint32_t val, bool align4byte)
{
    assert(!align4byte || (uint32_t)from % 4 == 0);
    uint32_t step = align4byte ? sizeof(uint32_t) : 1;
    for (uint32_t i = from; i < to; i += step)
    {
        __try
        {
            if (*(uint32_t*)i == val)
            {
                return i;
            }
        }
        __except (1) { }
    }
    return to;
}

const char* FindFirstReferenceInMem(const char* from, const char* to, const char* str, uint32_t strLen)
{
    for (const char* i = from; i < to; ++i)
    {
        __try
        {
            if (!strncmp(i, str, strLen))
            {
                return i;
            }
        }
        __except (1)
        {
            i = (const char*)((((uint32_t)i >> 12) << 12) + 0x1000);
        }
    }
    return to;
}

vector<uint32_t> FindAllReferenceInMem(uint32_t from, uint32_t to, uint32_t val, bool align4byte)
{
    vector<uint32_t> offsets;
    for (uint32_t i = from; i < to;)
    {
        uint32_t result = FindFirstReferenceInMem(i, to, val, align4byte);
        if (result != to)
            offsets.push_back(result);
        i = result + 4;
    }
    return offsets;
}

vector<const char*> FindAllReferenceInMem(const char* from, const char* to, const char* str, uint32_t strLen)
{
    vector<const char*> offsets;
    for (const char* i = from; i < to;)
    {
        const char* result = FindFirstReferenceInMem(i, to, str, strLen);
        if (result != to)
            offsets.push_back(result);
        i = result + strLen;
    }
    return offsets;
}

#if 0
vector<pair<uint32_t, string>> FindTypeDescriptor(const vector<uint8_t>& fileData)
{
    vector<pair<uint32_t, string>> offsets;
    const char flag[] = { ".?AV" };
    for (auto i = 0; i < fileData.size(); ++i)
    {
        const char* ptr = (const char*)&fileData[i];
        if (!strncmp(flag, ptr, 4))
        {
            offsets.push_back(make_pair(i, ptr));
            i += strlen(ptr) - 1;
        }
    }
    return offsets;
}
#endif

uint32_t FindExeImageBase()
{
    uint32_t p = reinterpret_cast<uint32_t>(FindExeImageBase);
    p &= ~0xfff;
    while (p)
    {
        __try
        {
            if (*(char*)p == 'M' && *(char*)(p + 1) == 'Z')
                return p;
        } __except (1) { }
        p -= 0x1000;
    }
    return 0;
}



// return vtable rva
std::vector<uint32_t> FindAllRttiInPEFile(const vector<uint8_t>& peData)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peData.data();
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(peData.data() + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)(peData.data() + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    uint32_t imageBase = Detail::GetImageBaseInPEHeader(peData);

    const uint32_t findStart = (uint32_t)peData.data();
    const uint32_t findEnd = (uint32_t)(peData.data() + peData.size());
    vector<const char*> pos = FindAllReferenceInMem((const char*)findStart, (const char*)findEnd, ".?AV", 4);

    for (auto nameAddr : pos)
    {
        uint32_t peOffset = Detail::FileOffsetToRVA(peData, (uint32_t)nameAddr - findStart);
        uint32_t typeDesc = peOffset - CONTENT_OFFSET(Detail::_TypeDescriptor, name) + Detail::GetImageBaseInPEHeader(peData);
        auto typeDescRef = FindAllReferenceInMem(findStart, findEnd, (uint32_t)typeDesc, true);
        if (typeDescRef.empty())
        {
            int k = 0;
        }
        else
        {
            cout << nameAddr << ": \n";
            uint32_t rttiCOLFileOffset = 0;
            for (auto r : typeDescRef)
            {
                rttiCOLFileOffset = r - findStart - CONTENT_OFFSET(Detail::_s__RTTICompleteObjectLocator, pTypeDescriptor);
                uint32_t hierDescVA = *(uint32_t*)(peData.data() + rttiCOLFileOffset + CONTENT_OFFSET(Detail::_s__RTTICompleteObjectLocator, pClassHierarchyDescriptor));
                uint32_t hierDescFileOffset = Detail::RVAToFileOffset(peData, hierDescVA - imageBase);
                if ((int)hierDescFileOffset < 0)  // 过滤无效结果
                    continue;

                uint32_t result_attributes = *(uint32_t*)(peData.data() + hierDescFileOffset + CONTENT_OFFSET(Detail::_s__RTTIClassHierarchyDescriptor, attributes));
                if (result_attributes & ~3) // 过滤无效结果
                    continue;

                uint32_t result_numBaseClasses = *(uint32_t*)(peData.data() + hierDescFileOffset + CONTENT_OFFSET(Detail::_s__RTTIClassHierarchyDescriptor, numBaseClasses));
                if (result_numBaseClasses > 0xff) // 过滤无效结果
                    continue;

                uint32_t baseClassArrVA = *(uint32_t*)(peData.data() + hierDescFileOffset + CONTENT_OFFSET(Detail::_s__RTTIClassHierarchyDescriptor, pBaseClassArray));
                uint32_t baseClassArrFileOffset = Detail::RVAToFileOffset(peData, baseClassArrVA - imageBase);
                for (int k = 0; k < result_numBaseClasses; ++k)
                {
                    uint32_t baseVA = *(uint32_t*)(peData.data() + baseClassArrFileOffset + k * sizeof(uint32_t));
                    uint32_t baseFileOffset = Detail::RVAToFileOffset(peData, baseVA - imageBase);
                    uint32_t baseTypeDescVA = *(uint32_t*)(peData.data() + baseFileOffset + CONTENT_OFFSET(Detail::_s__RTTIBaseClassDescriptor, pTypeDescriptor));
                    uint32_t baseTypeDescFileOffset = Detail::RVAToFileOffset(peData, baseTypeDescVA - imageBase);
                    const char* result_baseTypeName = (const char*)(peData.data() + baseTypeDescFileOffset + CONTENT_OFFSET(Detail::_TypeDescriptor, name));

                    cout << "base: " << result_baseTypeName << ", ";
                }
                cout << "\n";
                uint32_t rttiCOLVA = imageBase + Detail::FileOffsetToRVA(peData, rttiCOLFileOffset);
                auto rttiRefs = FindAllReferenceInMem(findStart, findEnd, rttiCOLVA, false);
                for (int k = 0; k < rttiRefs.size(); ++k)
                {
                    uint32_t vtableRef = rttiRefs[k] - findStart + sizeof(uint32_t);
                    uint32_t vtableVA = Detail::FileOffsetToRVA(peData, vtableRef) + imageBase;
                    auto vtableRefs = FindAllReferenceInMem(findStart, findEnd, vtableVA, false);
                    for (int kk = 0; kk < vtableRefs.size(); ++kk)
                    {
                        uint32_t result_ctorRVA = Detail::FileOffsetToRVA(peData, vtableRefs[kk] - findStart);

                        cout << "reference in ctors(next instruction): " << hex << result_ctorRVA + 4 << ", ";    // 显示下一条指令的地址
                    }
                    cout << "\n";
                }
                cout << "\n";
            }
        }
    }
    return vector<uint32_t>();
}


class Animal01
{
public:
    virtual void fff01() {}
};
class Animal02
{
public:
    virtual void fff02() {}
};
class Animal11
{
public:
    virtual void fff11() {}
};
class Animal12
{
public:
    virtual void fff12() {}
};
class Animal0 : public Animal01, public Animal02
{
public:
    virtual ~Animal0() {}
};
class Animal1 : public Animal11, public Animal12
{
public:
    virtual void A1() {}
};
class Animal : virtual public Animal1, virtual public Animal0
{
public:
    virtual ~Animal(void) {}
};
class Cat : public Animal {};
class Dog : public Animal {};


void ListExeRtti()
{
    uint32_t imagebase = FindExeImageBase();
    vector<const char*> pos = FindAllReferenceInMem((char*)imagebase, (char*)(imagebase + 0x50000), ".?AV", 4);

    for (int i = 0; i < pos.size(); ++i)
    {
        const char* addr = pos[i];

        Detail::_TypeDescriptor* type = (Detail::_TypeDescriptor*)(addr - 8);
        auto ref = FindAllReferenceInMem(imagebase, imagebase + 0x50000, (uint32_t)type, true);
        if (ref.empty())
        {
            int k = 0;
        }
        else
        {
            Detail::_s__RTTICompleteObjectLocator* rtti = nullptr;
            for (auto r : ref)
            {
                rtti = (Detail::_s__RTTICompleteObjectLocator*)(r - 12);
                if (!IsBadReadPtr(rtti->pTypeDescriptor, sizeof(rtti->pTypeDescriptor)) && !IsBadReadPtr(rtti->pClassHierarchyDescriptor, sizeof(rtti->pClassHierarchyDescriptor)))
                    break;
            }
            std::string msg = Detail::Dump(rtti);
            cout << msg.c_str();
            auto vtable = FindAllReferenceInMem(imagebase, imagebase + 0x50000, (uint32_t)rtti, true);
            cout << "*vtable: ";
            for (auto p : vtable)
            {
                char buf[32];
                sprintf_s(buf, sizeof(buf), "%#x, ", p + 4);
                cout << buf;
            }
            if (!vtable.empty())
            {
                auto ctors = FindAllReferenceInMem(imagebase, imagebase + 0x50000, vtable[0] + 4, false);
                cout << "\n*referenced in ctors(next instruction): ";
                for (auto p : ctors)
                {
                    char buf[32];
                    sprintf_s(buf, sizeof(buf), "%#x, ", p + 4);
                    cout << buf;
                }
            }
            cout << "\n++++++++++++++++++++++++++\n";
        }
    }
}

int main(int argc, char** argv)
{
    Animal* d = new Dog();
    Animal* a = new Cat();
    Cat* c = dynamic_cast<Cat*>(a);
    Animal* aa = new Animal();
    Detail::__RTTICompleteObjectLocator* ptr = (Detail::__RTTICompleteObjectLocator*)(*(uint32_t**)aa)[-1];
    dynamic_cast<Cat*>(aa);
    vector<uint8_t> fileData = GetFileData(argc >= 2 ? argv[1] : argv[0]);
    FindAllRttiInPEFile(fileData);
    cout << "finish\n";
    return 0;
}
