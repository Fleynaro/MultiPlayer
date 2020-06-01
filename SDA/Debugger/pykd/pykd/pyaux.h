#pragma once

#include <windows.h>

///////////////////////////////////////////////////////////////////////////////

class PyThreadStateSaver {

public:

    PyThreadStateSaver() {
        m_index = TlsAlloc();
    }

    ~PyThreadStateSaver() {
        TlsFree( m_index );
    }

    void saveState() {
        if ( !isWindbgExt() )
            TlsSetValue( m_index, PyEval_SaveThread() );
        else
            WindbgGlobalSession::SavePyState();                
    }

    void restoreState() {
        if ( !isWindbgExt() )
        {
            PyThreadState*      state = (PyThreadState*)TlsGetValue( m_index );
            if ( state )
                PyEval_RestoreThread( state );
        }
        else
        {
            WindbgGlobalSession::RestorePyState();
        }
    }

private:

    DWORD   m_index;
};

extern PyThreadStateSaver       g_pyThreadState;


//typedef PyThreadState *PyThreadStatePtr;
//extern __declspec( thread ) PyThreadStatePtr ptrPyThreadState;

//  --> call back 
//  { PyThread_StateSave  state( winext->getThreadState() );
//    do_callback();
//  }
//
//  ���� ������ ��� ������ � ��� ���� � ������� ������ �������� �������� ( ��� ����� setExecutionStatus )
//  �� ����� ����������� ������������ ���� ����� ������������ ��������, � ����� �������� ����������,
//  ����� ��������� ���

class PyThread_StateSave {

public:

    PyThread_StateSave() 
    {
        g_pyThreadState.restoreState();
    }

    ~PyThread_StateSave() {
        g_pyThreadState.saveState();
    }
};

// { PyThread_StateRestore   state;
//   long_or_block_opreration();
// }

class PyThread_StateRestore
{
public:

    PyThread_StateRestore() {
        g_pyThreadState.saveState();
    }

    ~PyThread_StateRestore() {
        g_pyThreadState.restoreState();
    }
};

///////////////////////////////////////////////////////////////////////////////