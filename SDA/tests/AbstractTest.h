#pragma once
//SDA
#include <Program.h>
#include <Project.h>
#include <Manager/Managers.h>

//gtest
#define _DEBUG
#undef NDEBUG
#include "gtest/gtest.h"

using namespace CE;

class ProgramFixture : public ::testing::Test
{
    bool m_isClear = false;

protected:
    CE::Program* m_program;
    CE::Project* m_project;

    DB::ITransaction* m_tr;
    CE::TypeManager* m_typeManager;
    CE::SymbolManager* m_symManager;
    CE::SymbolTableManager* m_symTabManger;
    CE::FunctionManager* m_funcManager;
public:
    ProgramFixture()
    {
        m_program = new Program;
    }

    ~ProgramFixture() {
        delete m_program;
        delete m_project;
    }

    void createProject(const fs::path& dir) {
        m_project = m_program->getProjectManager()->createProject(m_program->getExecutableDirectory() / dir);
        initProject();
    }

    void loadProject(const fs::path& dir) {
        m_project = m_program->getProjectManager()->loadProject(m_program->getExecutableDirectory() / dir);
        initProject();
        m_project->load();
    }

    void initProject() {
        m_project->initDataBase("database.db");
        m_project->initManagers();

        // for being short
        m_tr = m_project->getTransaction();
        m_typeManager = m_project->getTypeManager();
        m_symManager = m_project->getSymbolManager();
        m_symTabManger = m_project->getSymTableManager();
        m_funcManager = m_project->getFunctionManager();
    }
};