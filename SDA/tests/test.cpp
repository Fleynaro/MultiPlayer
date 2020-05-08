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
    auto typeManager = m_programModule->getTypeManager();
    auto funcManager = m_programModule->getFunctionManager();
    auto declManager = funcManager->getFunctionDeclManager();

    //for functions
    {
        ASSERT_EQ(funcManager->getItemsCount(), 0);

        auto function1 = funcManager->createFunction(&setRot,       { Function::AddressRange(&setRot, 200) },       declManager->createFunctionDecl(g_testFuncName, "set rot to an entity"));
        auto function2 = funcManager->createFunction(&changeGvar,   { Function::AddressRange(&changeGvar, 10) },    declManager->createFunctionDecl("changeGvar", ""));
        auto function3 = funcManager->createFunction(&rand,         { Function::AddressRange(&rand, 300) },         declManager->createFunctionDecl("rand", ""));
        auto function4 = funcManager->createFunction(&setPlayerPos, { Function::AddressRange(&setPlayerPos, 10) },  declManager->createFunctionDecl("setPlayerPos", ""));
        auto function5 = funcManager->createFunction(&setPlayerVel, { Function::AddressRange(&setPlayerVel, 10) },  declManager->createFunctionDecl("setPlayerVel", ""));
        auto function6 = funcManager->createFunction(&sumArray,     { Function::AddressRange(&sumArray, 30) },      declManager->createFunctionDecl("sumArray", ""));
        
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("int32_t")), "arg1");
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("float")), "arg2");
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("float")), "arg3");
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("float")), "arg4");
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("int32_t")), "arg5");

        function6->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("int32_t"), "*[3][2]"), "arr");
        function6->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("char"), "*"), "str");
        //m_programModule->getFunctionManager()->buildFunctionBodies();
        //m_programModule->getFunctionManager()->buildFunctionBasicInfo();
    }

    //for types
    {
        //enumeration
        auto enumeration = typeManager->createEnum("EntityType", "this is a enumeration");
        enumeration->addField("PED", 1);
        enumeration->addField("CAR", 2);
        enumeration->addField("VEHICLE", 3);

        //typedef
        auto tdef = typeManager->createTypedef(DataType::GetUnit(enumeration), "ObjectType");

        //structure
        auto screen = typeManager->createStructure("Screen", "this is a structure type");
        screen->addField(0, "width", DataType::GetUnit(typeManager->getTypeByName("float")));
        screen->addField(4, "height", DataType::GetUnit(typeManager->getTypeByName("float")));
        ASSERT_EQ(screen->getSize(), 8);

        //class
        auto entity = typeManager->createClass("Entity", "this is a class type");
        entity->addField(20, "type", DataType::GetUnit(tdef), "position of entity");
        auto tPos = DataType::GetUnit(typeManager->getTypeByName("float"), "[3]");
        entity->addField(30, "pos", tPos, "position of entity");
        entity->addField(50, "screen", DataType::GetUnit(screen), "screen of entity");
        ASSERT_EQ(entity->getSize(), 58);

        //derrived class
        auto ped = typeManager->createClass("Ped", "this is a derrived class type");
        ped->setBaseClass(entity);
        ped->addField(100, "head_angle", DataType::GetUnit(typeManager->getTypeByName("float")));
        auto methodDecl = declManager->createMethodDecl("getHeadAngle");
        ped->addMethod(methodDecl);
    }

    //for triggers
    {
        auto trigger1 = m_programModule->getTriggerManager()->createFunctionTrigger("testTrigger1");
        ASSERT_NE(trigger1, nullptr);
        auto filter1 = new Trigger::Function::Filter::Cmp::Argument(1, 1, Trigger::Function::Filter::Cmp::Eq);
        auto filter2 = new Trigger::Function::Filter::Cmp::RetValue(0, Trigger::Function::Filter::Cmp::Ge);
        trigger1->getFilters()->addFilter(filter1);
        trigger1->getFilters()->addFilter(filter2);

        auto trigger2 = m_programModule->getTriggerManager()->createFunctionTrigger("testTrigger2");
        ASSERT_NE(trigger2, nullptr);

        auto trGroup = m_programModule->getTriggerGroupManager()->createTriggerGroup("triggerTestGroup");
        trGroup->addTrigger(trigger1);
        trGroup->addTrigger(trigger2);
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
        ASSERT_EQ(funcManager->getItemsCount(), 6);
        
        auto func = funcManager->getFunctionAt(&setRot);
        ASSERT_EQ(func->getDeclaration().getArgNameList().size(), 5);
        ASSERT_EQ(func->getDeclaration().getFunctions().size(), 1);
        ASSERT_EQ(func->getRangeList().size(), 1);
        ASSERT_EQ(func->getRangeList().begin()->getMinAddress(), &setRot);
        ASSERT_EQ(func->getName(), g_testFuncName);
    }

    //for types
    {
        auto typeManager = m_programModule->getTypeManager();

        //for structure
        {
            auto type = typeManager->getTypeByName("Screen");
            ASSERT_NE(type, nullptr);
            ASSERT_EQ(type->getGroup(), DataType::Type::Structure);
            if (auto screen = dynamic_cast<DataType::Structure*>(type)) {
                ASSERT_EQ(screen->getFields().size(), 2);
            }
        }

        //for class
        {
            auto type = typeManager->getTypeByName("Entity");
            ASSERT_NE(type, nullptr);
            ASSERT_EQ(type->getGroup(), DataType::Type::Class);
            if (auto entity = dynamic_cast<DataType::Class*>(type)) {
                ASSERT_EQ(entity->getFields().size(), 3);
            }
        }

        //for derrived class
        {
            auto type = typeManager->getTypeByName("Ped");
            ASSERT_NE(type, nullptr);
            ASSERT_EQ(type->getGroup(), DataType::Type::Class);
            if (auto ped = dynamic_cast<DataType::Class*>(type)) {
                ASSERT_NE(ped->getBaseClass(), nullptr);
                ASSERT_EQ(ped->getFields().size(), 2);
                ASSERT_EQ(ped->getMethods().size(), 1);
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

    //for triggers
    {
        auto trManager = m_programModule->getTriggerManager();
        auto trGroupManager = m_programModule->getTriggerGroupManager();
        
        //for function trigger
        {
            auto trigger = trManager->getTriggerByName("testTrigger1");
            ASSERT_NE(trigger, nullptr);
            if (auto funcTrigger = dynamic_cast<Trigger::Function::Trigger*>(trigger)) {
                ASSERT_EQ(funcTrigger->getFilters()->getFilters().size(), 2);
                auto it = funcTrigger->getFilters()->getFilters().begin();
                if (auto filter = dynamic_cast<Trigger::Function::Filter::Cmp::Argument*>(*(it++))) {
                    ASSERT_EQ(filter->m_argId, 1);
                    ASSERT_EQ(filter->m_value, 1);
                    ASSERT_EQ(filter->m_operation, Trigger::Function::Filter::Cmp::Eq);
                }
                if (auto filter = dynamic_cast<Trigger::Function::Filter::Cmp::RetValue*>(*(it++))) {
                    ASSERT_EQ(filter->m_operation, Trigger::Function::Filter::Cmp::Ge);
                }
            }
        }

        //for group trigger
        {
            auto group = trGroupManager->getTriggerGroupByName("triggerTestGroup");
            ASSERT_NE(group, nullptr);
            if (auto trgroup = dynamic_cast<Trigger::TriggerGroup*>(group)) {
                ASSERT_EQ(trgroup->getTriggers().size(), 2);
            }
        }
    }
}

TEST_F(ProgramModuleFixture, Test_FunctionTrigger)
{
    auto typeManager = m_programModule->getTypeManager();
    auto statManager = m_programModule->getStatManager();
    auto funcManager = m_programModule->getFunctionManager();
    EXPECT_EQ(funcManager->getItemsCount(), 6);

    auto function = funcManager->getFunctionAt(&setRot);
    ASSERT_NE(function, nullptr);

    function->createHook();
    auto hook = function->getHook();
    ASSERT_NE(hook, nullptr);

    hook->getDynHook()->enable();

    auto trigger = m_programModule->getTriggerManager()->createFunctionTrigger("testTrigger1");
    ASSERT_NE(trigger, nullptr);
    auto filter1 = new Trigger::Function::Filter::Cmp::Argument(1, 1, Trigger::Function::Filter::Cmp::Eq);
    auto filter2 = new Trigger::Function::Filter::Cmp::RetValue(12, Trigger::Function::Filter::Cmp::Eq);
    trigger->setStatCollectingEnable(true);
    trigger->setTableLogEnable(true);
    trigger->getFilters()->addFilter(filter1);
    hook->addActiveTrigger(trigger);

    //call hooked function
    auto retOrigValue = setRot(10, 2, 3, 4, 5);

    //table log
    {
        using namespace CE::Trigger::Function;
        auto tableLog = trigger->getTableLog();
        auto result = tableLog->all();
        ASSERT_EQ(result.getList().size(), 1);
        auto it = result.getList().begin();
        if (auto row = tableLog->getRow(*(it++))) {
            ASSERT_EQ(std::get<TableLog::FunctionId>(*row), function->getId());
            auto argsValues = std::get<TableLog::ArgValues>(*row);
            ASSERT_EQ(argsValues.size(), 5);
            ASSERT_EQ(std::get<TableLog::RetValue>(*row).m_rawValue, retOrigValue);
            auto argIt = argsValues.begin();
            ASSERT_EQ((argIt++)->m_rawValue, 10);

            auto fval = reinterpret_cast<float&>((argIt++)->m_rawValue);
            ASSERT_EQ(fval, 2.0);
            fval = reinterpret_cast<float&>((argIt++)->m_rawValue);
            ASSERT_EQ(fval, 3.0);
        }
    }

    setRot(1, 2.6f, 3.7f, 4.8f, 500);
    setRot(1, 20, 30, 400, 50000);

    for (int i = 0; i < 1; i++)
    {
        std::thread t([i] {
            for (int j = 0; j < 100; j++) {
                setRot(10 + j, -10.f, 10.f, 888.4f, 999);
                //Sleep(1);
            }
            });
        t.join();
    }

    //Pointer & array
    function = funcManager->getFunctionAt(&sumArray);
    ASSERT_NE(function, nullptr);
    trigger = m_programModule->getTriggerManager()->createFunctionTrigger("testTrigger2");
    trigger->setStatCollectingEnable(true);
    trigger->setTableLogEnable(true);

    function->createHook();
    hook = function->getHook();
    ASSERT_NE(hook, nullptr);
    hook->getDynHook()->enable();

    hook->addActiveTrigger(trigger);

    int arr[3*2] = {1, 2, 3, 4, 5, 7};

    //in the stack
    arrType arr2[3][2] = {
        {&arr[0], &arr[1]},
        {&arr[2], &arr[3]},
        {&arr[4], &arr[5]}
    };

    //in the pile
    arrType** arr3 = new arrType * [3];
    for (int i = 0; i < 3; i++) {
        arr3[i] = new arrType[2];
        for (int j = 0; j < 2; j++) {
            arr3[i][j] = arr2[i][j];
        }
    }

    const char* str = "hello, world!";
    for (size_t i = 0; i < 100; i++)
    {
        retOrigValue = sumArray(arr2, (char*)str);
    }

    //iterator 1
    {
        int i = 0;
        DereferenceIterator it(arr3, function->getDeclaration().getSignature().getArgList()[0]);
        while (it.hasNext()) {
            auto item = it.next();
            auto value = *(int*)item.first;
            ASSERT_EQ(value, arr[i]);
            i++;
        }
    }

    //iterator 2
    {
        int i = 0;
        DereferenceIterator it(&arr, DataType::GetUnit(typeManager->getTypeByName("int32_t"), "[6]"));
        while (it.hasNext()) {
            auto item = it.next();
            auto value = *(int*)item.first;
            ASSERT_EQ(value, arr[i]);
            i++;
        }
    }


    //table log
    {
        using namespace CE::Trigger::Function;
        auto tableLog = trigger->getTableLog();
        auto result = tableLog->all();
        ASSERT_EQ(result.getList().size(), 100);
        auto it = result.getList().begin();
        if (auto row = tableLog->getRow(*(it++))) {
            ASSERT_EQ(std::get<TableLog::FunctionId>(*row), function->getId());
            auto argsValues = std::get<TableLog::ArgValues>(*row);
            ASSERT_EQ(argsValues.size(), 2);
            ASSERT_EQ(std::get<TableLog::RetValue>(*row).m_rawValue, retOrigValue);
            
            auto argIt = ++argsValues.begin();
            ASSERT_EQ(std::string((char*)argIt->getRawData(), argIt->getRawDataSize()), std::string(str));
        }
    }

    statManager->getCollector()->getBufferManager()->save();
}

#include <Statistic/Function/Analysis/Providers/SignatureAnalysisProvider.h>
#include <Statistic/Function/Analysis/Providers/StringSearchProvider.h>
TEST_F(ProgramModuleFixture, Test_FunctionStatAnalysis)
{
    auto statManager = m_programModule->getStatManager();
    auto loader = new Stat::Function::BufferLoader(statManager->getCollector()->getBufferManager());
    loader->loadAllBuffers();
    auto provider = new Stat::Function::Analyser::StringSearchProvider("hello");
    auto analyser = new Stat::Function::Analyser::Analyser(provider, loader);
    analyser->startAnalysis();

    while (analyser->isWorking()) {
        fflush(stdout);
        printf("\nanalysis progress: %.0f%%\n", analyser->getProgress() * 100.0f);
        Sleep(1);
    }

    ASSERT_EQ(provider->getFoundRecords().size(), 100);
}

TEST_F(ProgramModuleFixture, Test_FunctionAnalysis)
{
    auto funcManager = m_programModule->getFunctionManager();

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

TEST_F(ProgramModuleFixture, Test_RemoveDB)
{
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

int sumArray(arrType arr[3][2], char* str)
{
    int sum = 0;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 2; j++) {
            sum += *arr[i][j];
        }
    }
    return sum;
}

int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);

    Hook::init();
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    DebugOutput_Console = true;

	return RUN_ALL_TESTS();
}
