#pragma once

#include <string>
#include <map>
#include "pyaux.h"

/////////////////////////////////////////////////////////////////////////////////

std::string
dbgCommand( const std::wstring &command );

template <ULONG status>
void
setExecutionStatus()
{
    HRESULT     hres;

    hres = dbgExt->control->SetExecutionStatus( status );

    if ( FAILED( hres ) )
        throw DbgException( "IDebugControl::SetExecutionStatus failed" );

    ULONG    currentStatus;

    do {
        
        {
            PyThread_StateRestore pyThreadRestore;
            hres = dbgExt->control->WaitForEvent( 0, INFINITE );
        }

        if ( FAILED( hres ) )
        {
            if (E_UNEXPECTED == hres)
                throw WaitEventException();

            throw  DbgException( "IDebugControl::WaitForEvent  failed" );
        }

        hres = dbgExt->control->GetExecutionStatus( &currentStatus );

        if ( FAILED( hres ) )
            throw  DbgException( "IDebugControl::GetExecutionStatus  failed" ); 

    } while( currentStatus != DEBUG_STATUS_BREAK && currentStatus != DEBUG_STATUS_NO_DEBUGGEE );

}

/////////////////////////////////////////////////////////////////////////////////

class dbgExtensionClass {

public:

    dbgExtensionClass() :
        m_handle( NULL )
        {}
    
    dbgExtensionClass( const char* path );
    
    ~dbgExtensionClass();
    
    std::string
    call( const std::string &command, const std::string param );

    std::string
    print() const;
    
private:

    ULONG64         m_handle;  
	std::string     m_path;
};


/////////////////////////////////////////////////////////////////////////////////

ULONG64
evaluate( const std::string  &expression );
    
/////////////////////////////////////////////////////////////////////////////////

void
breakin();

/////////////////////////////////////////////////////////////////////////////////