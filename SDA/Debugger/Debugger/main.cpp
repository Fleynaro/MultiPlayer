
#include <Windows.h>
#include <dbgeng.h>
#include <atlcomcli.h>

#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"dbgeng.lib")


#define GET_HR_ERROR(hr)    -((hr) & 0xffffff)


IDebugClient* pclient = NULL;
IDebugControl3* pctrl = NULL;
IDebugRegisters2* registers = NULL;


class EventCallbacks : public DebugBaseEventCallbacks
{
private:
    int m_started;
    int m_dummy;

public:
    EventCallbacks()
    {
        m_started = 0;
        m_dummy = 0;
    }

    ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG	STDMETHODCALLTYPE Release() { return 0; }

    HRESULT Breakpoint(PDEBUG_BREAKPOINT p)
    {
        printf("BreakPoint p[%p]\n", p);

        ULONG64 addr;
        registers->GetInstructionOffset(&addr);


       
        ULONG registerIndex = 0;
        auto hres = registers->GetIndexByName("rcx", &registerIndex);
        if (FAILED(hres)) {
            return DEBUG_STATUS_NO_CHANGE;
        }

        DEBUG_VALUE value;
        registers->GetValue(registerIndex, &value);
        value.I32 *= 2;
        registers->SetValue(registerIndex, &value);

        
        return DEBUG_STATUS_BREAK;
    }

    HRESULT ChangeDebuggeeState(ULONG flags, ULONG64 arg)
    {
        printf("ChangeDebuggeeState flags[0x%lx] arg[0x%llx]\n", flags, arg);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT ChangeEngineState(ULONG flags, ULONG64 arg)
    {
        printf("ChangeEngineState flags [0x%lx] arg[0x%llx]\n", flags, arg);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT ChangeSymbolState(ULONG flags, ULONG64 arg)
    {
        printf("ChangeSymbolState flags [0x%lx] arg[0x%llx]\n", flags, arg);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT CreateProcess(ULONG64 imghdl, ULONG64 hdl, ULONG64 baseoff, ULONG modsize,
        PCSTR modname, PCSTR imgname, ULONG chksum, ULONG timestamp, ULONG64 initthrhdl, ULONG64 thrdataoff,
        ULONG64 startoff)
    {
        printf("CreateProcess imghdl [0x%llx] hdl [0x%llx] baseoff [0x%llx] modsize [0x%lx] modname [%s] imgname [%s] chksum [0x%lx] timestamp [0x%lx] initthrhdl [0x%llx] thrdataoff [0x%llx] startoff [0x%llx]", imghdl, hdl, baseoff, modsize, modname,
            imgname, chksum, timestamp, initthrhdl, thrdataoff, startoff);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT CreateThread(ULONG64 hdl, ULONG64 dataoff, ULONG64 startoff)
    {
        printf("CreateThread hdl[0x%llx] dataoff[0x%llx] startoff[0x%llx]",
            hdl, dataoff, startoff);
        this->m_started = 1;
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT Exception(PEXCEPTION_RECORD64 pexp, ULONG firstchance)
    {
        printf("Exception pexp[%p] firstchance [0x%lx]", pexp, firstchance);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT ExitProcess(ULONG exitcode)
    {
        printf("ExitProcess exitcode [0x%lx]", exitcode);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT ExitThread(ULONG exitcode)
    {
        printf("ExitThread exitcode [0x%lx]", exitcode);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT GetInterestMask(ULONG* pmask)
    {
        *pmask = (DEBUG_EVENT_BREAKPOINT |
            DEBUG_EVENT_EXCEPTION |
            DEBUG_EVENT_CREATE_THREAD |
            DEBUG_EVENT_EXIT_THREAD |
            DEBUG_EVENT_CREATE_PROCESS |
            DEBUG_EVENT_EXIT_PROCESS |
            DEBUG_EVENT_LOAD_MODULE |
            DEBUG_EVENT_UNLOAD_MODULE |
            DEBUG_EVENT_SYSTEM_ERROR |
            DEBUG_EVENT_SESSION_STATUS |
            DEBUG_EVENT_CHANGE_DEBUGGEE_STATE |
            DEBUG_EVENT_CHANGE_ENGINE_STATE |
            DEBUG_EVENT_CHANGE_SYMBOL_STATE);
        return S_OK;
    }

    HRESULT LoadModule(ULONG64 imghdl, ULONG64 baseoff, ULONG modsize, PCSTR modname, PCSTR imgname, ULONG chksum, ULONG timestamp)
    {
        printf("LoadModule imghdl[0x%llx] baseoff[0x%llx] modsize [0x%lx] modname[%s] imgname[%s] chksum [0x%lx] timestamp [0x%lx]",
            imghdl, baseoff, modsize, modname, imgname, chksum, timestamp);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT SessionStatus(ULONG status)
    {
        printf("SessionStatus status[0x%lx]", status);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT SystemError(ULONG error, ULONG level)
    {
        printf("SystemError error[0x%lx] level[0x%lx]", error, level);
        return DEBUG_STATUS_NO_CHANGE;
    }

    HRESULT UnloadModule(PCSTR imgname, ULONG64 baseoff)
    {
        printf("UnloadModule imgname[%s] baseoff[0x%llx]", imgname, baseoff);
        return DEBUG_STATUS_NO_CHANGE;
    }

    int is_started()
    {
        return this->m_started;
    }
};

class OutputCallback : public IDebugOutputCallbacks
{
public:
    OutputCallback() {}
    virtual ~OutputCallback() {}
    HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface)
    {
        if (IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks)))
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

    ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG	STDMETHODCALLTYPE Release() { return 0; }
    HRESULT Output(ULONG mask, PCSTR text)
    {
        fprintf(stdout, "Output[0x%lx]%s", mask, text);
        return S_OK;
    }
};

class InputCallback : public IDebugInputCallbacks
{
public:
    InputCallback() {}
    virtual ~InputCallback() {}
    HRESULT STDMETHODCALLTYPE QueryInterface(const IID& InterfaceId, PVOID* Interface)
    {
        if (IsEqualIID(InterfaceId, __uuidof(IDebugInputCallbacks)))
        {
            *Interface = (IDebugInputCallbacks*)this;
            AddRef();
            return S_OK;
        }
        else
        {
            return E_NOINTERFACE;
        }
    }

    ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG	STDMETHODCALLTYPE Release() { return 0; }
    HRESULT EndInput()
    {
        printf("EndInput");
        return S_OK;
    }
    HRESULT StartInput(ULONG bufsize)
    {
        printf("StartInput bufsize[0x%lx]", bufsize);
        return S_OK;
    }
};


bool stepOver()
{
    ULONG64 addr;
    registers->GetInstructionOffset(&addr);

    {
        auto hr = pctrl->SetExecutionStatus(DEBUG_STATUS_STEP_OVER);
        if (FAILED(hr))
        {
            _tprintf(TEXT("Failed to set execution status.  hr = %#x\n"), hr);
            return false;
        }

        hr = pctrl->WaitForEvent(0, INFINITE);
        if (hr != S_OK) {
            auto ret = GET_HR_ERROR(hr);
            printf("wait for error[%d] [0x%lx]", ret, hr);
            return false;
        }
    }

    return true;
}


int main(int argc, char* argv[])
{
    HRESULT hr;
    int ret;
    char* pcmd = NULL;
    int cmdsize = 0;
    int i;
    
    EventCallbacks* pevtcallback = NULL;
    int setevt = 0;
    int cnt = 0;
    char readbuf[256];
    int readsize = 256;
    char* pptr = NULL;
    int readlen;
    InputCallback* inputcallback = NULL;
    OutputCallback* outputcallback = NULL;
    int setinput = 0, setoutput = 0;
    ULONG outmask = 0;
    HRESULT                 Status = NULL;
    PDEBUG_BREAKPOINT bp = NULL;

    //better try to get last interface IDebugClient7
    hr = DebugCreate(__uuidof(IDebugClient), (void**)&pclient);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("debug create error[%d]", ret);
        goto out;
    }

    //attach to proccess
    ULONG id;
    if ((Status = pclient->GetRunningProcessSystemIdByExecutableName(NULL, "Test.exe", 0, &id)) != S_OK)
    {
        printf("pclient->GetRunningProcessSystemIdByExecutableName failed, 0x%X\n", Status);
        goto out;
    }
    if ((Status = pclient->AttachProcess(NULL,
        id, DEBUG_ATTACH_DEFAULT)) != S_OK)
    {
        printf("pclient->AttachProcess failed, 0x%X\n", Status);
        goto out;
    }
    /*hr = pclient->CreateProcessAndAttach(NULL, (PSTR)"M:\\Users\\user\\source\\repos\\Debugger\\x64\\Debug\\Test.exe", DEBUG_PROCESS, NULL, DEBUG_ATTACH_DEFAULT);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("could not create [%s] error[%d] [0x%lx]", pcmd, ret, hr);
        goto out;
    }*/



    hr = pclient->QueryInterface(__uuidof(IDebugControl3), (void**)&pctrl);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("can not query interface control3 error[%d] [0x%lx]", ret, hr);
        goto out;
    }
    hr = pclient->QueryInterface(__uuidof(IDebugRegisters2), (void**)&registers);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("can not query interface control3 error[%d] [0x%lx]", ret, hr);
        goto out;
    }


    //set callbacks
    pevtcallback = new EventCallbacks();
    hr = pclient->SetEventCallbacks(pevtcallback);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("can not set event callback error[%d] [0x%lx]", ret, hr);
        goto out;
    }
    setevt = 1;

    inputcallback = new InputCallback();
    hr = pclient->SetInputCallbacks(inputcallback);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("can not set input callback error[%d] [0x%lx]", ret, hr);
        goto out;
    }
    setinput = 1;

    outputcallback = new OutputCallback();
    hr = pclient->SetOutputCallbacks(outputcallback);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("can not set output callback error[%d] [0x%lx]", ret, hr);
        goto out;
    }
    setoutput = 1;

    //set mask for output event
    outmask = DEBUG_OUTPUT_NORMAL |
        DEBUG_OUTPUT_ERROR |
        DEBUG_OUTPUT_WARNING |
        DEBUG_OUTPUT_VERBOSE |
        DEBUG_OUTPUT_PROMPT |
        DEBUG_OUTPUT_PROMPT_REGISTERS |
        DEBUG_OUTPUT_EXTENSION_WARNING |
        DEBUG_OUTPUT_DEBUGGEE |
        DEBUG_OUTPUT_DEBUGGEE_PROMPT |
        DEBUG_OUTPUT_SYMBOLS |
        DEBUG_OUTPUT_STATUS;
    hr = pclient->SetOutputMask(outmask);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("can not set output mask error[%d] [0x%lx]", ret, hr);
        goto out;
    }

    //first
    hr = pctrl->WaitForEvent(0, INFINITE);
    if (hr != S_OK) {
        ret = GET_HR_ERROR(hr);
        printf("wait for [%s] error[%d] [0x%lx]", pcmd, ret, hr);
        goto out;
    }

    
    //add breakpoint
    if ((Status = pctrl->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp)) != S_OK)
    {
        goto out;
    }
    bp->SetOffset(0x7FF6E7BE13FC); //abs addr
    bp->AddFlags(DEBUG_BREAKPOINT_ENABLED); //enable

    
    //main debug loop
    while (1)
    {
        //wait for breakpoint hit or something that
        hr = pctrl->WaitForEvent(0, INFINITE);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            printf("wait for [%s] error[%d] [0x%lx]", pcmd, ret, hr);
            goto out;
        }


        hr = pctrl->GetExecutionStatus(&outmask);
        if (hr != S_OK) {
            ret = GET_HR_ERROR(hr);
            printf("GetExecutionStatus error[%d] [0x%lx]", ret, hr);
            goto out;
        }
        printf("\nGetExecutionStatus = %i\n", outmask);


        //if we get that status then
        if (outmask == DEBUG_STATUS_BREAK) {
            static int counter = 0;
            counter++;
            printf("============= DEBUG_STATUS_BREAK(%i) =============\n", counter);
            
            if (!stepOver()) goto out;
            if (!stepOver()) goto out;
            if (!stepOver()) goto out;
            if (!stepOver()) goto out;
        }
    }


    ret = 0;
    printf("\n\n\n====END DEBUG====\n\n\n");


out:
    if (setoutput) {
        pclient->SetOutputCallbacks(NULL);
    }
    setoutput = 0;
    if (outputcallback) {
        delete outputcallback;
    }
    outputcallback = NULL;

    if (setinput) {
        pclient->SetInputCallbacks(NULL);
    }
    setinput = 0;

    if (inputcallback) {
        delete inputcallback;
    }
    inputcallback = NULL;

    if (setevt) {
        pclient->SetEventCallbacks(NULL);
    }
    if (pevtcallback) {
        delete pevtcallback;
    }
    pevtcallback = NULL;

    if (pctrl) {
        pctrl->Release();
    }
    pctrl = NULL;
    if (pclient) {
        pclient->Release();
    }
    pclient = NULL;
    return ret;
}