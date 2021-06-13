#pragma once
//SDA
#include <Program.h>

//gtest
#define _DEBUG
#undef NDEBUG
#include "gtest/gtest.h"

using namespace CE;

class ProgramModuleFixtureBase {
public:
    ProgramModuleFixtureBase(bool isClear = false) {
        if (isClear) {
            clear();
        }
        getCurrentDir().createIfNotExists();
        m_project = new Project(getCurrentDir());

        m_project->initDataBase("database.db");
        m_project->initManagers();
        m_project->load();
    }

    ~ProgramModuleFixtureBase() {
        if (m_project != nullptr)
            delete m_project;
    }


    FS::Directory getCurrentDir() {
        char filename[MAX_PATH];
        GetModuleFileName(NULL, filename, MAX_PATH);
        return FS::File(filename).getDirectory().next("test");
    }

    void clear() {
        if (m_project != nullptr) {
            delete m_project;
            m_project = nullptr;
        }
        getCurrentDir().removeAll();
    }

    CE::Project* m_project;
};

class ProgramModuleFixture : public ProgramModuleFixtureBase, public ::testing::Test {
public:
    ProgramModuleFixture(bool isClear = false)
        : ProgramModuleFixtureBase(isClear)
    {}

    ~ProgramModuleFixture() {

    }
};