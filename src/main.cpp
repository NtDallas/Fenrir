#include <iostream>
#include <vector>

#include <Windows.h>

#include "ntdll.h"
#include "vulcan.h"

#pragma comment(lib, "Ntdll.lib")

extern "C" PVOID NTAPI SpoofStub(PVOID a, ...);

using namespace std;

class spoof {

public:
    spoof(vector <StackFrameInfo> a, string b) : stackFrame(a), moduleNameGadget(b) { init(); }

    void* call(string moduleName, string functionName, vector <void*> args);
    void    show();

private:
    bool    init();
    void*   CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase);
    void*   CalculateFunctionStackSizeWrapper(PVOID ReturnAddress);
    bool    GetTextSectionSize(void* pModule, PDWORD pdwVirtualAddress, PDWORD pdwSize);
    void    ListGadget(void* pTextSectionAddr, DWORD dwTextSize, vector <void*>* gadgetList);

    vector <StackFrameInfo> stackFrame;
    string moduleNameGadget;

    vector <void*> gadgetList;
    PRM p = { 0 };
};

bool spoof::init()
{
    // prepare "jmp RDI" gadget
    void* pGadgetModule = LoadLibraryA(moduleNameGadget.c_str());
    DWORD dwVA, dwSize = 0;

    if (!GetTextSectionSize(pGadgetModule, &dwVA, &dwSize))
        return false;

    ListGadget(
        (void*)((UINT_PTR)pGadgetModule + dwVA),
        dwSize,
        &gadgetList
    );

    if (gadgetList.size() == 0)
        return false;

    ULONG seed = 0x1337;
    ULONG randomnNbr = RtlRandomEx(&seed);
    randomnNbr %= gadgetList.size();

    this->p.trampoline = gadgetList[randomnNbr];

    void* ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA(stackFrame[0].moduleName.c_str()), stackFrame[0].functionName.c_str())) + stackFrame[0].dwFunctionOffset;
    this->p.BTIT_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
    this->p.BTIT_retaddr = ReturnAddress;

    ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA(stackFrame[1].moduleName.c_str()), stackFrame[1].functionName.c_str())) + stackFrame[1].dwFunctionOffset;
    this->p.RUTS_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
    this->p.RUTS_retaddr = ReturnAddress;

    this->p.Gadget_ss = CalculateFunctionStackSizeWrapper(p.trampoline);

    if (
        (p.trampoline == nullptr) ||
        (p.BTIT_ss == nullptr) ||
        (p.BTIT_retaddr == nullptr) ||
        (p.RUTS_ss == nullptr) ||
        (p.RUTS_retaddr == nullptr) ||
        (p.Gadget_ss == nullptr)
        )
    {
        return false;
    }


    return true;
}

void* spoof::call(string moduleName, string functionName, vector <void*> args)
{
    void* pModuleAddr = LoadLibraryA(moduleName.c_str());
    if (pModuleAddr == NULL)
        return nullptr;

    void* pFunctionAddr = GetProcAddress(reinterpret_cast<HMODULE>(pModuleAddr), functionName.c_str());
    if (pFunctionAddr == NULL)
        return nullptr;

    switch (args.size())
    {
    case 0:
        return SpoofStub(nullptr, nullptr, nullptr, nullptr, &p, pFunctionAddr, nullptr);
        break;

    case 1:
        return SpoofStub(args[0], nullptr, nullptr, nullptr, &p, pFunctionAddr, nullptr);
        break;

    case 2:
        return SpoofStub(args[0], args[1], nullptr, nullptr, &p, pFunctionAddr, nullptr);
        break;

    case 3:
        return SpoofStub(args[0], args[1], args[2], nullptr, &p, pFunctionAddr, nullptr);
        break;

    case 4:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, nullptr);
        break;

    case 5:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4]);
        break;

    case 6:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5]);
        break;

    case 7:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6]);
        break;

    case 8:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6], args[7]);
        break;

    case 9:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6], args[7], args[8]);
        break;

    case 10:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6], args[7], args[8], args[9]);
        break;

    case 11:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6], args[7], args[8], args[9], args[10]);
        break;

    case 12:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11]);
        break;

    case 13:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12]);
        break;

    case 14:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13]);
        break;

    case 15:
        return SpoofStub(args[0], args[1], args[2], args[3], &p, pFunctionAddr, reinterpret_cast<void*>(args.size() - 4), args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14]);
        break;
    }

    return nullptr;

}

void spoof::show()
{
    cout << "\tSpoof init" << endl;
    cout << "Gadget addr : 0x" << p.trampoline << " Stack size : " << p.Gadget_ss << endl;
    cout << "Fake addr1 addr : 0x" << p.BTIT_retaddr << " Stack size : " << dec << p.BTIT_ss << endl;
    cout << "Fake addr2 addr : 0x" << p.RUTS_retaddr << " Stack size : " << dec << p.RUTS_ss << endl;
}

void* spoof::CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };

    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            stackFrame.totalStackSize += 8;
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            stackFrame.setsFramePointer = true;
            break;
        default:
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    }

    stackFrame.totalStackSize += 8;

    return (void*)stackFrame.totalStackSize;
Cleanup:
    return nullptr;
}

void* spoof::CalculateFunctionStackSizeWrapper(PVOID ReturnAddress)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

Cleanup:
    return nullptr;
}

bool spoof::GetTextSectionSize(void* pModule, PDWORD pdwVirtualAddress, PDWORD pdwSize)
{
    PIMAGE_DOS_HEADER pImgDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModule);
    if (pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    PIMAGE_NT_HEADERS pImgNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)pModule + pImgDosHeader->e_lfanew);
    if (pImgNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    PIMAGE_SECTION_HEADER   pImgSectionHeader = IMAGE_FIRST_SECTION(pImgNtHeaders);

    for (int i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (strcmp((char*)pImgSectionHeader[i].Name, (char*)".text") == 0)
        {
            *pdwVirtualAddress = pImgSectionHeader[i].VirtualAddress;
            *pdwSize = pImgSectionHeader[i].SizeOfRawData;
            return true;
        }
    }

    return false;
}

void spoof::ListGadget(void* pTextSectionAddr, DWORD dwTextSize, vector <void*>* gadgetList)
{
    for (int i = 0; i < (dwTextSize - 2); i++)
    {
        if (
            ((PBYTE)pTextSectionAddr)[i] == 0xFF &&
            ((PBYTE)pTextSectionAddr)[i + 1] == 0x27
            )
        {
            gadgetList->push_back(
                (void*)((UINT_PTR)pTextSectionAddr + i)
            );

        }
    }

}

int main()
{
    spoof test({
    { "kernel32.dll", "BaseThreadInitThunk", 0x14 },    // fake second frame
    { "ntdll.dll", "RtlUserThreadStart", 0x21 }         // fake third frame
        },
        "kernelbase.dll");                                  // module name for "jmp RDI" gadget

    void* pAllocatedAddr = nullptr;

    for (int i = 0; i < 20; i++)
    {
        pAllocatedAddr = test.call("Kernel32.dll", "VirtualAlloc", { nullptr, (void*)0x10000, (void*)MEM_COMMIT, (void*)PAGE_READWRITE });
        cout << "Allocaed addr : " << pAllocatedAddr << endl;
    }

    return EXIT_SUCCESS;
}
