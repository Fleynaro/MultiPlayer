#include "test.h"
using namespace CE;

class ProgramModuleFixture : public ::testing::Test {
public:
    ProgramModuleFixture() {
        m_programModule = new ProgramExe(GetModuleHandle(NULL), getCurrentDir());

        m_programModule->initDataBase("database.db");
        m_programModule->initManagers();
        m_programModule->initGhidraClient();
        m_programModule->load();
    }

    ~ProgramModuleFixture() {
        delete m_programModule;
    }

    FS::Directory getCurrentDir() {
        char filename[MAX_PATH];
        GetModuleFileName(NULL, filename, MAX_PATH);
        return FS::File(filename).getDirectory();
    }

    CE::ProgramModule* m_programModule;
};

TEST_F(ProgramModuleFixture, Test_DataBaseCreatedAndFilled)
{
    EXPECT_GE(m_programModule->getDB().execAndGet("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").getInt(), 20);
    auto tr = m_programModule->getTransaction();

    //for functions
    {
        auto funcManager = m_programModule->getFunctionManager();
        auto declManager = funcManager->getFunctionDeclManager();
        void* funcAddr = &setRot;

        EXPECT_EQ(funcManager->getItemsCount(), 0);

        auto decl = declManager->createFunctionDecl(g_testFuncName, "set rot to an entity");
        auto function = m_programModule->getFunctionManager()->createFunction(funcAddr, { Function::AddressRange(&setRot, 200) }, decl);
    }

    tr->commit();
}

TEST_F(ProgramModuleFixture, Test_DataBaseLoaded)
{
    //for functions
    {
        auto funcManager = m_programModule->getFunctionManager();
        EXPECT_EQ(funcManager->getItemsCount(), 1);
        
        FunctionManager::Iterator it(funcManager);
        ASSERT_EQ(it.hasNext(), true);
        auto func = it.next();
        ASSERT_EQ(func->getDeclaration().getFunctions().size(), 1);
        ASSERT_EQ(func->getRangeList().size(), 1);
        ASSERT_EQ(func->getRangeList().begin()->getMinAddress(), &setRot);
        ASSERT_EQ(func->getName(), g_testFuncName);
        EXPECT_EQ(it.hasNext(), false);
    }

    //remove test database
    m_programModule->remove();
}


class SomeClass
{
public:
    virtual int getValue() {
        return 4;
    }
};

auto g_someClass = new SomeClass;
int g_IntegerVal = 4;

void setPlayerPos() {
    g_IntegerVal = 5;
}

void setPlayerVel() {
    int a = 5;
}

float gVar = 0;
void changeGvar() {
    gVar = 2.0;
    setPlayerVel();
}

int setRot(int a, float x, float y, float z, int c)
{
    if (a <= 2) {
        int result = setRot(a + 1, x, y, z, c);
    }
    g_IntegerVal = 100;
    float result = x + y + z + a + c + g_someClass->getValue();
    result = pow(result, 1);
    setPlayerPos();
    gVar = float(rand() % 10);
    changeGvar();
    return (int)result;
}

int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
