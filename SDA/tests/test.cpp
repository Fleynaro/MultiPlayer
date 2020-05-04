#include "test.h"
#include <CallGraph/CallGraph.h>
using namespace CE;

TEST(DataType, Parsing)
{
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "*")), "[1]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "***")), "[1][1][1]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "[3][5]")), "[3][5]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "(**[10][5])*")), "[1][10][5][1][1]");
}

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
        ASSERT_EQ(funcManager->getItemsCount(), 0);

        auto function1 = funcManager->createFunction(&setRot,       { Function::AddressRange(&setRot, 200) },       declManager->createFunctionDecl(g_testFuncName, "set rot to an entity"));
        auto function2 = funcManager->createFunction(&changeGvar,   { Function::AddressRange(&changeGvar, 10) },    declManager->createFunctionDecl("changeGvar", ""));
        auto function3 = funcManager->createFunction(&rand,         { Function::AddressRange(&rand, 300) },         declManager->createFunctionDecl("rand", ""));
        auto function4 = funcManager->createFunction(&setPlayerPos, { Function::AddressRange(&setPlayerPos, 10) },  declManager->createFunctionDecl("setPlayerPos", ""));
        auto function5 = funcManager->createFunction(&setPlayerVel, { Function::AddressRange(&setPlayerVel, 10) },  declManager->createFunctionDecl("setPlayerVel", ""));
        
        //m_programModule->getFunctionManager()->buildFunctionBodies();
        //m_programModule->getFunctionManager()->buildFunctionBasicInfo();
    }

    //for types
    {
        auto typeManager = m_programModule->getTypeManager();

        //enumeration
        auto enumeration = typeManager->createEnum("EntityType", "this is a enumeration");
        enumeration->addField("PED", 1);
        enumeration->addField("CAR", 2);
        enumeration->addField("VEHICLE", 3);

        //typedef
        auto tdef = typeManager->createTypedef(DataType::GetUnit(enumeration), "ObjectType");

        //class
        auto entity = typeManager->createClass("Entity", "this is a class type");
        entity->addField(20, "type", DataType::GetUnit(tdef), "position of entity");
        auto tPos = DataType::GetUnit(typeManager->getTypeByName("float"), "[3]");
        entity->addField(30, "pos", tPos, "position of entity");
    }

    try {
        tr->commit();
    }
    catch (std::exception& e) {
        DebugOutput("Transaction commit: " + std::string(e.what()));
        ASSERT_EQ(0, 1);
    }
}

TEST_F(ProgramModuleFixture, Test_DataBaseLoaded)
{
    //for functions
    {
        auto funcManager = m_programModule->getFunctionManager();
        EXPECT_EQ(funcManager->getItemsCount(), 5);
        
        auto func = funcManager->getFunctionAt(&setRot);
        ASSERT_EQ(func->getDeclaration().getFunctions().size(), 1);
        ASSERT_EQ(func->getRangeList().size(), 1);
        ASSERT_EQ(func->getRangeList().begin()->getMinAddress(), &setRot);
        ASSERT_EQ(func->getName(), g_testFuncName);
    }

    //for types
    {
        auto typeManager = m_programModule->getTypeManager();

        //for class
        {
            auto type = typeManager->getTypeByName("Entity");
            ASSERT_NE(type, nullptr);
            ASSERT_EQ(type->getGroup(), DataType::Type::Class);
            if (auto entity = dynamic_cast<DataType::Class*>(type)) {
                ASSERT_EQ(entity->getAllFieldCount(), 2);
            }
        }

        //for typedef & enumeration
        {
            auto type = typeManager->getTypeByName("ObjectType");
            ASSERT_NE(type, nullptr);
            ASSERT_EQ(type->getGroup(), DataType::Type::Typedef);
            if (auto objType = dynamic_cast<DataType::Typedef*>(type)) {
                ASSERT_NE(objType->getRefType(), nullptr);
                ASSERT_EQ(objType->getRefType()->getGroup(), DataType::Type::Enum);
                if (auto refType = dynamic_cast<DataType::Enum*>(objType->getRefType()->getType())) {
                    ASSERT_EQ(refType->getFieldDict().size(), 3);
                }
            }
        }
    }

    //remove test database
    //m_programModule->remove();
}

TEST_F(ProgramModuleFixture, Test_FunctionAnalysis)
{
    auto funcManager = m_programModule->getFunctionManager();
    EXPECT_EQ(funcManager->getItemsCount(), 5);

    auto function1 = funcManager->getFunctionAt(&setRot);
    ASSERT_NE(function1, nullptr);

    CallGraph::FunctionBodyBuilder bodyBuilder(function1);
    bodyBuilder.build();

    auto body = function1->getBody();
    ASSERT_EQ(body->getFunctionsReferTo().size(), 1);
    
    auto& nodes = body->getNodeList();
    ASSERT_EQ(nodes.size(), 7);

    //funcManager->buildFunctionBasicInfo();
    //auto& info = body->getBasicInfo();
    //ASSERT_EQ(info.m_calculatedFuncCount, 7);
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

    Hook::init();
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    DebugOutput_Console = true;

	return RUN_ALL_TESTS();
}
