#include <stdio.h>
#include <dbgeng.h>
#include <Windows.h>
#include <string>

IDebugClient2* g_Client2 = NULL;
IDebugControl* g_Control = NULL;
HRESULT                 Status = NULL;

void Exit(int Code, PCSTR Format, ...)
{
    if (g_Control != NULL)
    {
        g_Control->Release();
        g_Control = NULL;
    }
    if (g_Client2 != NULL)
    {
        g_Client2->EndSession(DEBUG_END_PASSIVE);
        g_Client2->Release();
        g_Client2 = NULL;
    }
    if (Format != NULL)
    {
        va_list Args;
        va_start(Args, Format);
        vfprintf(stderr, Format, Args);
        va_end(Args);
    }
    exit(Code);
};


class DebugEventCallbacksImpl : public IDebugEventCallbacks
{
public:
    STDMETHOD(QueryInterface)(THIS_ IN REFIID InterfaceId, OUT PVOID* Interface)
    {
        *Interface = NULL;
        if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
            IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks)))
        {
            *Interface = (IDebugOutputCallbacks*)this;
            AddRef();
            return S_OK;
        }
        else
        {
            return E_NOINTERFACE;
        }
    }
    STDMETHOD_(ULONG, AddRef)(THIS) { return 1; }
    STDMETHOD_(ULONG, Release)(THIS) { return 0; }
    
    STDMETHOD(GetInterestMask)(
        THIS_
        _Out_ PULONG Mask
        )
    {
        return S_OK;
    }

    STDMETHOD(Breakpoint)(
        THIS_
        _In_ PDEBUG_BREAKPOINT Bp
        )
    {
        return S_OK;
    }

    STDMETHOD(Exception)(
        THIS_
        _In_ PEXCEPTION_RECORD64 Exception,
        _In_ ULONG FirstChance
        )
    {
        return S_OK;
    }

    STDMETHOD(CreateThread)(
        THIS_
        _In_ ULONG64 Handle,
        _In_ ULONG64 DataOffset,
        _In_ ULONG64 StartOffset
        )
    {
        return S_OK;
    }

    STDMETHOD(ExitThread)(
        THIS_
        _In_ ULONG ExitCode
        )
    {
        return S_OK;
    }

    STDMETHOD(CreateProcess)(
        THIS_
        _In_ ULONG64 ImageFileHandle,
        _In_ ULONG64 Handle,
        _In_ ULONG64 BaseOffset,
        _In_ ULONG ModuleSize,
        _In_opt_ PCSTR ModuleName,
        _In_opt_ PCSTR ImageName,
        _In_ ULONG CheckSum,
        _In_ ULONG TimeDateStamp,
        _In_ ULONG64 InitialThreadHandle,
        _In_ ULONG64 ThreadDataOffset,
        _In_ ULONG64 StartOffset
        )
    {
        return S_OK;
    }

    _Analysis_noreturn_
        STDMETHOD(ExitProcess)(
            THIS_
            _In_ ULONG ExitCode
            )
    {
        return S_OK;
    }

    STDMETHOD(LoadModule)(
        THIS_
        _In_ ULONG64 ImageFileHandle,
        _In_ ULONG64 BaseOffset,
        _In_ ULONG ModuleSize,
        _In_opt_ PCSTR ModuleName,
        _In_opt_ PCSTR ImageName,
        _In_ ULONG CheckSum,
        _In_ ULONG TimeDateStamp
        )
    {
        return S_OK;
    }

    STDMETHOD(UnloadModule)(
        THIS_
        _In_opt_ PCSTR ImageBaseName,
        _In_ ULONG64 BaseOffset
        )
    {
        return S_OK;
    }

    STDMETHOD(SystemError)(
        THIS_
        _In_ ULONG Error,
        _In_ ULONG Level
        )
    {
        return S_OK;
    }

    STDMETHOD(SessionStatus)(
        THIS_
        _In_ ULONG Status
        )
    {
        return S_OK;
    }

    STDMETHOD(ChangeDebuggeeState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
        )
    {
        return S_OK;
    }

    STDMETHOD(ChangeEngineState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
        )
    {
        return S_OK;
    }

    STDMETHOD(ChangeSymbolState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
        )
    {
        return S_OK;
    }
};

DebugEventCallbacksImpl g_Events;


void CreateInterfaces()
{
    if ((Status = DebugCreate(__uuidof(IDebugClient), (void**)&g_Client2)) != S_OK)
    {
        Exit(1, "DebugCreate failed, 0x%X\n", Status);
    }

    if ((Status = g_Client2->QueryInterface(__uuidof(IDebugControl3), (void**)&g_Control)) != S_OK)
    {
        Exit(1, "g_Client2->QueryInterface(__uuidof(IDebugControl) failed, 0x%X\n", Status);
    }
    return;
}

void main3(int Argc, char* Argv[])
{
    char Exename[0x100];
    CreateInterfaces();

    ULONG id;
    if ((Status = g_Client2->GetRunningProcessSystemIdByExecutableName(NULL, "Test.exe", 0, &id)) != S_OK)
    {
        Exit(1, "g_Client2->GetRunningProcessSystemIdByExecutableName failed, 0x%X\n", Status);
    }

    //попробовать создать процесс
    if ((Status = g_Client2->AttachProcess(NULL,
        id, DEBUG_ATTACH_DEFAULT)) != S_OK)
    {
        Exit(1, "g_Client2->AttachProcess Failed, 0x%X\n", Status);
    }

    if ((Status = g_Client2->SetEventCallbacks(&g_Events)) != S_OK)
    {
        Exit(1, "g_Client2->SetEventCallbacks failed, 0x%X\n", Status);
    }



    PDEBUG_BREAKPOINT bp = NULL;
    if ((Status = g_Control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp)) != S_OK)
    {
        Exit(1, "g_Control->AddBreakpoint failed, 0x%X\n", Status);
    }

    if ((Status = g_Control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE)) != S_OK)
    {
        Exit(1, "g_Control->WaitForEvent Failed, 0x%X\n", Status);
    }

   

    bp->SetOffset(0x113BB);
    bp->AddFlags(DEBUG_BREAKPOINT_ENABLED);

    if ((Status = g_Client2->DispatchCallbacks(INFINITE)) != S_OK)
    {
        Exit(1, "g_Client2->DispatchCallbacks failed, 0x%X\n", Status);
    }

    while (true) {

        char expr[1000];
        ULONG exprSize = 0;
        bp->GetOffsetExpression(expr, 1000, &exprSize);
        if ((Status = g_Client2->DispatchCallbacks(INFINITE)) != S_OK)
        {
            Exit(1, "g_Client2->DispatchCallbacks failed, 0x%X\n", Status);
        }
        Sleep(1000);
    }
    
    Exit(0, "Finished Debugging Quitting\n");
}