// Copyright (c) .NET Foundation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CorProfiler.h"
#include "corhlpr.h"
#include "CComPtr.h"
#include "profiler_pal.h"
#include <cstddef>
#include <cuchar>
#include <string>
#include <cstring>
#include <iostream>
#include <sstream>
#include <locale>
#include <codecvt>
#include <chrono>
#include <thread>
#include <stack>
#include <list>
#include <utility>
#include <mutex>

using namespace std;

void Error(const char *str) {
    cerr << "ERROR: " << str << '\n';
}

ICorProfilerInfo8 *pInfo = nullptr;
std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert;

class FuncInfo {
public:
    FunctionID id;
    mdToken token;
    ClassID classID;
    mdTypeDef classToken;
    ModuleID moduleID;

    string funcName;
    string className;
    string moduleName;
    string assemblyName;
};



class CallInfo {
    std::chrono::high_resolution_clock::time_point started;
    FuncInfo *pFunc;
    ULONG argInfoSize;
    unique_ptr<COR_PRF_FUNCTION_ARGUMENT_INFO> pArgInfo;
    COR_PRF_FRAME_INFO frameInfo;
    thread::id thread0;
    thread::id thread1;

public:
    void Enter(ostringstream *oss, FuncInfo *pFunc, COR_PRF_ELT_INFO elt) {
        HRESULT hr;

        this->thread0 = this_thread::get_id();

        ULONG argumentInfoSize = 0;
        COR_PRF_FRAME_INFO frameInfo;
        hr = pInfo->GetFunctionEnter3Info(pFunc->id, elt, &this->frameInfo, &this->argInfoSize, NULL);
        if(hr != 0x8007007A) {
            cerr << hex << hr << '\n';
            return Error("Unexpected response from GetFunctionEnter3Info");
        }

        unsigned char *buffer = new unsigned char[this->argInfoSize];
        hr = pInfo->GetFunctionEnter3Info(pFunc->id, elt, &this->frameInfo, &this->argInfoSize, (COR_PRF_FUNCTION_ARGUMENT_INFO*)buffer);
        if(FAILED(hr)) {
            cerr << "0x" << hex << hr << '\n';
            return Error("enter info 2");
        }

        this->pArgInfo = unique_ptr<COR_PRF_FUNCTION_ARGUMENT_INFO>((COR_PRF_FUNCTION_ARGUMENT_INFO*)buffer);

        this->pFunc = pFunc;
        this->started = std::chrono::high_resolution_clock::now();
    }

    void Leave(ostringstream *oss) {
        HRESULT hr;

        auto end = std::chrono::high_resolution_clock::now();
        auto threadId = this_thread::get_id();

        *oss << hex << 'T' << threadId << " " << this->pFunc->className << '{' << this->pFunc->classToken << "}." << this->pFunc->funcName << '{' << this->pFunc->token << "} (" << dec << std::chrono::duration_cast<std::chrono::microseconds>(end - this->started).count() << " microseconds)";
    }
};

class ThreadContext {
    ostringstream oss;
    stack<CallInfo> calls;

public:
    void Enter(FuncInfo *pFunc, COR_PRF_ELT_INFO eltInfo) {
        if(pFunc->id == 0) return;
        
        this->calls.emplace();
        this->calls.top().Enter(&this->oss, pFunc, eltInfo);
    }

    void Leave(FuncInfo *pFunc) {
        if(pFunc->id == 0) return;

        auto &&call = std::move(this->calls.top());
        this->calls.pop();

        call.Leave(&this->oss);

        cerr << this->oss.str() << '\n';
        this->oss = ostringstream();
    }
};



thread_local ThreadContext threadCtx;

PROFILER_STUB EnterStub(FunctionIDOrClientID functionId, COR_PRF_ELT_INFO eltInfo)
{
    // cerr << "ENTER " << hex << functionId.clientID <<'\n';
    threadCtx.Enter((FuncInfo*)functionId.clientID, eltInfo);
}

PROFILER_STUB LeaveStub(FunctionIDOrClientID functionId, COR_PRF_ELT_INFO eltInfo)
{
    // cerr << "LEAVE " << hex << functionId.clientID <<'\n';
    threadCtx.Leave((FuncInfo*)functionId.clientID);
}

PROFILER_STUB TailcallStub(FunctionIDOrClientID functionId, COR_PRF_ELT_INFO eltInfo)
{
    // cerr << "TAILCALL " << hex << functionId.clientID <<'\n';
    threadCtx.Leave((FuncInfo*)functionId.clientID);
}

#ifdef _X86_
#ifdef _WIN32
void __declspec(naked) EnterNaked(FunctionIDOrClientID functionIDOrClientID, COR_PRF_ELT_INFO eltInfo)
{
    __asm
    {
        PUSH EAX
        PUSH ECX
        PUSH EDX
        PUSH [ESP + 16]
        CALL EnterStub
        POP EDX
        POP ECX
        POP EAX
        RET 8
    }
}

void __declspec(naked) LeaveNaked(FunctionIDOrClientID functionIDOrClientID, COR_PRF_ELT_INFO eltInfo)
{
    __asm
    {
        PUSH EAX
        PUSH ECX
        PUSH EDX
        PUSH [ESP + 16]
        CALL LeaveStub
        POP EDX
        POP ECX
        POP EAX
        RET 8
    }
}

void __declspec(naked) TailcallNaked(FunctionIDOrClientID functionIDOrClientID, COR_PRF_ELT_INFO eltInfo)
{
    __asm
    {
        PUSH EAX
        PUSH ECX
        PUSH EDX
        PUSH[ESP + 16]
        CALL TailcallStub
        POP EDX
        POP ECX
        POP EAX
        RET 8
    }
}
#endif
#elif defined(_AMD64_)
EXTERN_C void EnterNaked(FunctionIDOrClientID functionIDOrClientID, COR_PRF_ELT_INFO eltInfo);
EXTERN_C void LeaveNaked(FunctionIDOrClientID functionIDOrClientID, COR_PRF_ELT_INFO eltInfo);
EXTERN_C void TailcallNaked(FunctionIDOrClientID functionIDOrClientID, COR_PRF_ELT_INFO eltInfo);
#endif


std::mutex funcsMutex;
std::list<FuncInfo> funcs;

EXTERN_C UINT_PTR FuncMapper(FunctionID funcID, BOOL *result) {
    HRESULT hr;
    FuncInfo func;

    *result = FALSE;

    func.id = funcID;

    hr = pInfo->GetFunctionInfo(funcID, &func.classID, &func.moduleID, &func.token);
    if(FAILED(hr)) { Error("func info"); return 0; }

    if(func.classID == 0) {
        //generic class, sidestep
        func.funcName = string("GENERIC");
        *result = FALSE;
        return funcID;
    }

    char16_t inbuff[2048];
    char buff[4096];

    LPCBYTE loadAddress;
    ULONG nameLen = 0;
    AssemblyID assemblyId;
    hr = pInfo->GetModuleInfo(func.moduleID, &loadAddress, nameLen, &nameLen, NULL, &assemblyId);
    if(FAILED(hr) || nameLen > 2048) { Error("mod info"); return 0; }

    hr = pInfo->GetModuleInfo(func.moduleID, &loadAddress, nameLen, &nameLen, inbuff, &assemblyId);
    if(FAILED(hr)) { Error("mod info 2"); return 0; };
    func.moduleName = string(convert.to_bytes(inbuff));
    // *oss << convert.to_bytes(inbuff) << '\n';

    hr = pInfo->GetAssemblyInfo(assemblyId, 0, &nameLen, NULL, NULL, NULL);
    if(FAILED(hr) || nameLen > 2048) { Error("asm info"); return 0; }

    hr = pInfo->GetAssemblyInfo(assemblyId, nameLen, &nameLen, inbuff, NULL, NULL);
    if(FAILED(hr)) { Error("asm info 2"); return 0; }
    func.assemblyName = string(convert.to_bytes(inbuff));

    mdTypeDef mdType;
    ClassID parentClassId; // not needed in our scenario 
    ULONG32 numGenericTypeArgs = 0;
    ClassID* genericTypeArgs = NULL;
    
    hr = pInfo->GetClassIDInfo2(func.classID, NULL, &func.classToken, &parentClassId, 0, &numGenericTypeArgs, NULL);
    if (FAILED(hr)) { cerr << hex << hr; Error("class info"); return 0; }


    IMetaDataImport *pMeta;
    IUnknown *pMetaUnk;
    hr = pInfo->GetModuleMetaData(func.moduleID, ofRead | ofWrite, IID_IMetaDataImport, &pMetaUnk);
    if(FAILED(hr)) { Error("meta interface"); return 0; }

    hr = pMetaUnk->QueryInterface(IID_IMetaDataImport, (void **)&pMeta);
    if(FAILED(hr)) { Error("meta interface query"); return 0; }

    DWORD flags;
    mdTypeDef mdBaseType;
    hr = pMeta->GetTypeDefProps(func.classToken, inbuff, 2047, nullptr, &flags, nullptr);
    if (FAILED(hr)) { Error("typedefprops"); return 0; }
    func.className = string(convert.to_bytes(inbuff).data());

    mdTypeDef type;
    ULONG size;
    ULONG attributes;
    PCCOR_SIGNATURE pSig;
    ULONG blobSize;
    ULONG codeRva;
    hr = pMeta->GetMethodProps(func.token, &type, inbuff, 2047, &size, &attributes, &pSig, &blobSize, &codeRva, &flags);
    if(FAILED(hr)) { Error("method props"); return 0; }
    func.funcName = string(convert.to_bytes(inbuff));

    *result = TRUE;

    {
        std::lock_guard<std::mutex> lock(funcsMutex);
        funcs.push_back(std::move(func));
    }
       
    return (UINT_PTR)&funcs.back();
}


CorProfiler::CorProfiler() : refCount(0), corProfilerInfo(nullptr)
{
}

CorProfiler::~CorProfiler()
{
    if (this->corProfilerInfo != nullptr)
    {
        this->corProfilerInfo->Release();
        this->corProfilerInfo = nullptr;
    }
}

HRESULT STDMETHODCALLTYPE CorProfiler::Initialize(IUnknown *pICorProfilerInfoUnk)
{
    HRESULT queryInterfaceResult = pICorProfilerInfoUnk->QueryInterface(__uuidof(ICorProfilerInfo8), reinterpret_cast<void **>(&this->corProfilerInfo));
    if (FAILED(queryInterfaceResult)) return E_FAIL;

    pInfo = this->corProfilerInfo;

    DWORD eventMask = COR_PRF_MONITOR_ENTERLEAVE | COR_PRF_ENABLE_FUNCTION_ARGS | COR_PRF_ENABLE_FUNCTION_RETVAL | COR_PRF_ENABLE_FRAME_INFO;

    auto hr = this->corProfilerInfo->SetEventMask(eventMask);
    if(FAILED(hr)) Error("Failed to set event mask");

    hr = this->corProfilerInfo->SetEnterLeaveFunctionHooks3WithInfo(EnterNaked, LeaveNaked, TailcallNaked);
    if(FAILED(hr)) Error("Failed to register hooks");

    hr = this->corProfilerInfo->SetFunctionIDMapper(FuncMapper);
    if(FAILED(hr)) Error("Failed to set function mapper");

    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::Shutdown()
{
    if (this->corProfilerInfo != nullptr)
    {
        this->corProfilerInfo->Release();
        this->corProfilerInfo = nullptr;
    }

    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::AppDomainCreationStarted(AppDomainID appDomainId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::AppDomainCreationFinished(AppDomainID appDomainId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::AppDomainShutdownStarted(AppDomainID appDomainId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::AppDomainShutdownFinished(AppDomainID appDomainId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::AssemblyLoadStarted(AssemblyID assemblyId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::AssemblyLoadFinished(AssemblyID assemblyId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::AssemblyUnloadStarted(AssemblyID assemblyId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::AssemblyUnloadFinished(AssemblyID assemblyId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ModuleLoadStarted(ModuleID moduleId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ModuleLoadFinished(ModuleID moduleId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ModuleUnloadStarted(ModuleID moduleId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ModuleUnloadFinished(ModuleID moduleId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ModuleAttachedToAssembly(ModuleID moduleId, AssemblyID AssemblyId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ClassLoadStarted(ClassID classId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ClassLoadFinished(ClassID classId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ClassUnloadStarted(ClassID classId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ClassUnloadFinished(ClassID classId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::FunctionUnloadStarted(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::JITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::JITCompilationFinished(FunctionID functionId, HRESULT hrStatus, BOOL fIsSafeToBlock)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::JITCachedFunctionSearchStarted(FunctionID functionId, BOOL *pbUseCachedFunction)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::JITCachedFunctionSearchFinished(FunctionID functionId, COR_PRF_JIT_CACHE result)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::JITFunctionPitched(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::JITInlining(FunctionID callerId, FunctionID calleeId, BOOL *pfShouldInline)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ThreadCreated(ThreadID threadId)
{
    cerr << "THREAD " << threadId << " CREATED [" << this_thread::get_id() <<  "]\n";
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ThreadDestroyed(ThreadID threadId)
{
    cerr << "THREAD " << threadId << " DESTROYED [" << this_thread::get_id() <<  "]\n";
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ThreadAssignedToOSThread(ThreadID managedThreadId, DWORD osThreadId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RemotingClientInvocationStarted()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RemotingClientSendingMessage(GUID *pCookie, BOOL fIsAsync)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RemotingClientReceivingReply(GUID *pCookie, BOOL fIsAsync)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RemotingClientInvocationFinished()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RemotingServerReceivingMessage(GUID *pCookie, BOOL fIsAsync)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RemotingServerInvocationStarted()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RemotingServerInvocationReturned()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RemotingServerSendingReply(GUID *pCookie, BOOL fIsAsync)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::UnmanagedToManagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ManagedToUnmanagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON suspendReason)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeSuspendFinished()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeSuspendAborted()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeResumeStarted()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeResumeFinished()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeThreadSuspended(ThreadID threadId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeThreadResumed(ThreadID threadId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::MovedReferences(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], ULONG cObjectIDRangeLength[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ObjectAllocated(ObjectID objectId, ClassID classId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ObjectsAllocatedByClass(ULONG cClassCount, ClassID classIds[], ULONG cObjects[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ObjectReferences(ObjectID objectId, ClassID classId, ULONG cObjectRefs, ObjectID objectRefIds[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RootReferences(ULONG cRootRefs, ObjectID rootRefIds[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionThrown(ObjectID thrownObjectId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchFunctionEnter(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchFunctionLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchFilterEnter(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchFilterLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchCatcherFound(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionOSHandlerEnter(UINT_PTR __unused)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionOSHandlerLeave(UINT_PTR __unused)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionUnwindFunctionEnter(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionUnwindFunctionLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionUnwindFinallyEnter(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionUnwindFinallyLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCatcherEnter(FunctionID functionId, ObjectID objectId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCatcherLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::COMClassicVTableCreated(ClassID wrappedClassId, REFGUID implementedIID, void *pVTable, ULONG cSlots)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::COMClassicVTableDestroyed(ClassID wrappedClassId, REFGUID implementedIID, void *pVTable)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCLRCatcherFound()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCLRCatcherExecute()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ThreadNameChanged(ThreadID threadId, ULONG cchName, WCHAR name[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::GarbageCollectionStarted(int cGenerations, BOOL generationCollected[], COR_PRF_GC_REASON reason)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::SurvivingReferences(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], ULONG cObjectIDRangeLength[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::GarbageCollectionFinished()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::FinalizeableObjectQueued(DWORD finalizerFlags, ObjectID objectID)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::RootReferences2(ULONG cRootRefs, ObjectID rootRefIds[], COR_PRF_GC_ROOT_KIND rootKinds[], COR_PRF_GC_ROOT_FLAGS rootFlags[], UINT_PTR rootIds[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::HandleCreated(GCHandleID handleId, ObjectID initialObjectId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::HandleDestroyed(GCHandleID handleId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::InitializeForAttach(IUnknown *pCorProfilerInfoUnk, void *pvClientData, UINT cbClientData)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ProfilerAttachComplete()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ProfilerDetachSucceeded()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ReJITCompilationStarted(FunctionID functionId, ReJITID rejitId, BOOL fIsSafeToBlock)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::GetReJITParameters(ModuleID moduleId, mdMethodDef methodId, ICorProfilerFunctionControl *pFunctionControl)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ReJITCompilationFinished(FunctionID functionId, ReJITID rejitId, HRESULT hrStatus, BOOL fIsSafeToBlock)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ReJITError(ModuleID moduleId, mdMethodDef methodId, FunctionID functionId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::MovedReferences2(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], SIZE_T cObjectIDRangeLength[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::SurvivingReferences2(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], SIZE_T cObjectIDRangeLength[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ConditionalWeakTableElementReferences(ULONG cRootRefs, ObjectID keyRefIds[], ObjectID valueRefIds[], GCHandleID rootIds[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::GetAssemblyReferences(const WCHAR *wszAssemblyPath, ICorProfilerAssemblyReferenceProvider *pAsmRefProvider)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::ModuleInMemorySymbolsUpdated(ModuleID moduleId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::DynamicMethodJITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock, LPCBYTE ilHeader, ULONG cbILHeader)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::DynamicMethodJITCompilationFinished(FunctionID functionId, HRESULT hrStatus, BOOL fIsSafeToBlock)
{
    return S_OK;
}
