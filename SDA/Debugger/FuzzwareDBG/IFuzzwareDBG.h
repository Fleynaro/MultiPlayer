

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 7.00.0500 */
/* at Fri May 02 18:29:57 2008
 */
/* Compiler settings for IFuzzwareDBG.idl:
    Oicf, W1, Zp8, env=Win32 (32b run)
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
//@@MIDL_FILE_HEADING(  )

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __IFuzzwareDBG_h__
#define __IFuzzwareDBG_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IFuzzwareDBG_FWD_DEFINED__
#define __IFuzzwareDBG_FWD_DEFINED__
typedef interface IFuzzwareDBG IFuzzwareDBG;
#endif 	/* __IFuzzwareDBG_FWD_DEFINED__ */


#ifndef __IFuzzwareDBG_FWD_DEFINED__
#define __IFuzzwareDBG_FWD_DEFINED__
typedef interface IFuzzwareDBG IFuzzwareDBG;
#endif 	/* __IFuzzwareDBG_FWD_DEFINED__ */


#ifndef __FuzzwareDBG_FWD_DEFINED__
#define __FuzzwareDBG_FWD_DEFINED__

#ifdef __cplusplus
typedef class FuzzwareDBG FuzzwareDBG;
#else
typedef struct FuzzwareDBG FuzzwareDBG;
#endif /* __cplusplus */

#endif 	/* __FuzzwareDBG_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __IFuzzwareDBG_INTERFACE_DEFINED__
#define __IFuzzwareDBG_INTERFACE_DEFINED__

/* interface IFuzzwareDBG */
/* [uuid][object] */ 


EXTERN_C const IID IID_IFuzzwareDBG;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("4CD86B5B-BB54-4713-BED0-823B4F4EADC7")
    IFuzzwareDBG : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE SetOutputDir( 
            /* [string][in] */ const BSTR bstrOutputDir) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CreateCrashDumps( 
            /* [in] */ boolean bVal) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CreateProcess( 
            /* [string][in] */ const BSTR bstrCommandLine) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE AttachToProcess( 
            /* [in] */ long zProcessId) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RunProcess( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE ExecuteCommand( 
            /* [string][in] */ const BSTR bstrCommand,
            /* [string][out] */ BSTR *pbstrDebuggerOutput) = 0;
        
    };
    
#else 	/* C style interface */

    typedef struct IFuzzwareDBGVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IFuzzwareDBG * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IFuzzwareDBG * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IFuzzwareDBG * This);
        
        HRESULT ( STDMETHODCALLTYPE *SetOutputDir )( 
            IFuzzwareDBG * This,
            /* [string][in] */ const BSTR bstrOutputDir);
        
        HRESULT ( STDMETHODCALLTYPE *CreateCrashDumps )( 
            IFuzzwareDBG * This,
            /* [in] */ boolean bVal);
        
        HRESULT ( STDMETHODCALLTYPE *CreateProcess )( 
            IFuzzwareDBG * This,
            /* [string][in] */ const BSTR bstrCommandLine);
        
        HRESULT ( STDMETHODCALLTYPE *AttachToProcess )( 
            IFuzzwareDBG * This,
            /* [in] */ long zProcessId);
        
        HRESULT ( STDMETHODCALLTYPE *RunProcess )( 
            IFuzzwareDBG * This);
        
        HRESULT ( STDMETHODCALLTYPE *ExecuteCommand )( 
            IFuzzwareDBG * This,
            /* [string][in] */ const BSTR bstrCommand,
            /* [string][out] */ BSTR *pbstrDebuggerOutput);
        
        END_INTERFACE
    } IFuzzwareDBGVtbl;

    interface IFuzzwareDBG
    {
        CONST_VTBL struct IFuzzwareDBGVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IFuzzwareDBG_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IFuzzwareDBG_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IFuzzwareDBG_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IFuzzwareDBG_SetOutputDir(This,bstrOutputDir)	\
    ( (This)->lpVtbl -> SetOutputDir(This,bstrOutputDir) ) 

#define IFuzzwareDBG_CreateCrashDumps(This,bVal)	\
    ( (This)->lpVtbl -> CreateCrashDumps(This,bVal) ) 

#define IFuzzwareDBG_CreateProcess(This,bstrCommandLine)	\
    ( (This)->lpVtbl -> CreateProcess(This,bstrCommandLine) ) 

#define IFuzzwareDBG_AttachToProcess(This,zProcessId)	\
    ( (This)->lpVtbl -> AttachToProcess(This,zProcessId) ) 

#define IFuzzwareDBG_RunProcess(This)	\
    ( (This)->lpVtbl -> RunProcess(This) ) 

#define IFuzzwareDBG_ExecuteCommand(This,bstrCommand,pbstrDebuggerOutput)	\
    ( (This)->lpVtbl -> ExecuteCommand(This,bstrCommand,pbstrDebuggerOutput) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IFuzzwareDBG_INTERFACE_DEFINED__ */



#ifndef __IFuzzwareDBGLibrary_LIBRARY_DEFINED__
#define __IFuzzwareDBGLibrary_LIBRARY_DEFINED__

/* library IFuzzwareDBGLibrary */
/* [uuid] */ 



EXTERN_C const IID LIBID_IFuzzwareDBGLibrary;

EXTERN_C const CLSID CLSID_FuzzwareDBG;

#ifdef __cplusplus

class DECLSPEC_UUID("8C9991FE-3D7A-4f0b-A62A-0EBD08B0725F")
FuzzwareDBG;
#endif
#endif /* __IFuzzwareDBGLibrary_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

unsigned long             __RPC_USER  BSTR_UserSize(     unsigned long *, unsigned long            , BSTR * ); 
unsigned char * __RPC_USER  BSTR_UserMarshal(  unsigned long *, unsigned char *, BSTR * ); 
unsigned char * __RPC_USER  BSTR_UserUnmarshal(unsigned long *, unsigned char *, BSTR * ); 
void                      __RPC_USER  BSTR_UserFree(     unsigned long *, BSTR * ); 

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


