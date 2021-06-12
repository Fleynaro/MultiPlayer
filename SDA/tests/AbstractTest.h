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
        m_programModule = new Project(getCurrentDir());

        m_programModule->initDataBase("database.db");
        m_programModule->initManagers();
        m_programModule->load();
    }

    ~ProgramModuleFixtureBase() {
        if (m_programModule != nullptr)
            delete m_programModule;
    }


    FS::Directory getCurrentDir() {
        char filename[MAX_PATH];
        GetModuleFileName(NULL, filename, MAX_PATH);
        return FS::File(filename).getDirectory().next("test");
    }

    void clear() {
        if (m_programModule != nullptr) {
            delete m_programModule;
            m_programModule = nullptr;
        }
        getCurrentDir().removeAll();
    }

    CE::Project* m_programModule;
};

class ProgramModuleFixture : public ProgramModuleFixtureBase, public ::testing::Test {
public:
    ProgramModuleFixture(bool isClear = false)
        : ProgramModuleFixtureBase(isClear)
    {}

    ~ProgramModuleFixture() {

    }
};