#include "test.h"
using namespace CE;

TEST(DataType, Parsing)
{
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "*")), "[1]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "***")), "[1][1][1]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "[3][5]")), "[3][5]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "(**[10][5])*")), "[1][10][5][1][1]");
}

class ProgramModuleFixtureBase {
public:
    ProgramModuleFixtureBase(bool isClear = false) {
        if (isClear) {
            clear();
        }
        getCurrentDir().createIfNotExists();
        m_programModule = new ProgramModule(getCurrentDir());

        auto f = &rand;

        m_programModule->initDataBase("database.db");
        m_programModule->initManagers();
        m_programModule->load();

        m_programModule->getFunctionManager()->buildFunctionBodies();
        m_programModule->getFunctionManager()->buildFunctionBasicInfo();
        m_programModule->getFunctionTagManager()->calculateAllTags();
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

    CE::ProgramModule* m_programModule;
};

class ProgramModuleFixture : public ProgramModuleFixtureBase, public ::testing::Test {
public:
    ProgramModuleFixture(bool isClear = false)
        : ProgramModuleFixtureBase(isClear)
    {}

    ~ProgramModuleFixture() {

    }
};

class ProgramModuleFixtureStart : public ProgramModuleFixture {
public:
    ProgramModuleFixtureStart()
        : ProgramModuleFixture(true)
    {}
};

TEST_F(ProgramModuleFixtureStart, Test_DataBaseCreatedAndFilled)
{
    EXPECT_GE(m_programModule->getDB().execAndGet("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").getInt(), 20);
    auto tr = m_programModule->getTransaction();
    auto typeManager = m_programModule->getTypeManager();
    auto funcManager = m_programModule->getFunctionManager();
    auto declManager = funcManager->getFunctionDeclManager();
    auto modulesManager = m_programModule->getProcessModuleManager();
    ProcessModule* kernel32;
    ProcessModule* ucrtbase;

    //for processes
    {
        auto modules = modulesManager->getCurrentlyLoadedModules();
        for (auto it : modules) {
            if (!modulesManager->findProcessModule(it)) {
                modulesManager->createProcessModule(it);
            }
        }

        kernel32 = modulesManager->getProcessModuleByName("kernel32.dll");
        ASSERT_NE(kernel32, nullptr);
        ucrtbase = modulesManager->getProcessModuleByName("ucrtbase.dll");
        ASSERT_NE(ucrtbase, nullptr);
    }

    //for functions
    {
        auto tagManager = m_programModule->getFunctionTagManager();
        ASSERT_EQ(funcManager->getItemsCount(), 0);
        auto module = m_programModule->getProcessModuleManager()->getMainModule();

        auto function1 = funcManager->createFunction(module,    { AddressRange(&setRot, calculateFunctionSize((byte*)&setRot)) },                 declManager->createFunctionDecl(g_testFuncName, "set rot to an entity"));
        auto function2 = funcManager->createFunction(module,    { AddressRange(&changeGvar, calculateFunctionSize((byte*)&changeGvar)) },         declManager->createFunctionDecl("changeGvar", ""));
        auto function3 = funcManager->createFunction(ucrtbase,  { AddressRange(&rand, calculateFunctionSize((byte*)&rand)) },                     declManager->createFunctionDecl("rand", ""));
        auto function4 = funcManager->createFunction(module,    { AddressRange(&setPlayerPos, calculateFunctionSize((byte*)&setPlayerPos)) },     declManager->createFunctionDecl("setPlayerPos", ""));
        auto function5 = funcManager->createFunction(module,    { AddressRange(&setPlayerVel, calculateFunctionSize((byte*)&setPlayerVel)) },     declManager->createFunctionDecl("setPlayerVel", ""));
        auto function6 = funcManager->createFunction(module,    { AddressRange(&sumArray, calculateFunctionSize((byte*)&sumArray)) },             declManager->createFunctionDecl("sumArray", ""));
        
        auto libExportedFunctions = kernel32->getExportedFunctions();
        for (auto it : libExportedFunctions) {
            if (it.first != "GetErrorMode")
                continue;
            auto function = funcManager->createFunction(ucrtbase, { AddressRange(it.second, calculateFunctionSize((byte*)it.second)) }, declManager->createFunctionDecl(it.first, "exported function from kernel32.dll"));
            tagManager->createUserTag(function->getDeclarationPtr(), tagManager->m_setTag, "WinAPI", "From kernel32.dll");
            function->setExported(true);
        }
        
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("int32_t")), "arg1");
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("float")), "arg2");
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("float")), "arg3");
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("float")), "arg4");
        function1->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("int32_t")), "arg5");

        function6->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("int32_t"), "*[3][2]"), "arr");
        function6->getDeclaration().addArgument(DataType::GetUnit(typeManager->getTypeByName("char"), "*"), "str");

        //for function tags
        {
            tagManager->createUserTag(function1->getDeclarationPtr(), tagManager->m_getTag, "tag1", "test GET tag1");
            tagManager->createUserTag(function2->getDeclarationPtr(), tagManager->m_setTag, "tag2", "test SET tag2");
        }
    }

    //for types
    {
        //enumeration
        auto enumeration = typeManager->createEnum("EntityType", "this is a enumeration");
        enumeration->addField("PED", 1);
        enumeration->addField("CAR", 2);
        enumeration->addField("VEHICLE", 3);

        //typedef
        auto tdef = typeManager->createTypedef("ObjectType");
        tdef->setRefType(DataType::GetUnit(enumeration));

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
        ASSERT_EQ(funcManager->getItemsCount(), 7);
        
        auto func = funcManager->getFunctionAt(&setRot);
        ASSERT_EQ(func->getDeclaration().getArgNameList().size(), 5);
        ASSERT_EQ(func->getDeclaration().getFunctions().size(), 1);
        ASSERT_EQ(func->getAddressRangeList().size(), 1);
        ASSERT_EQ(func->getAddressRangeList().begin()->getMinAddress(), &setRot);
        ASSERT_EQ(func->getName(), g_testFuncName);

        //for function tags
        {
            auto tagManager = m_programModule->getFunctionTagManager();
            ASSERT_EQ(tagManager->getItemsCount(), 3 + 2);

            auto tags = tagManager->getTagCollection(func);
            ASSERT_EQ(tags.getTags().size(), 3);
        }
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
        printf("\nanalysis progress: %.0f%%", analyser->getProgress() * 100.0f);
        Sleep(1);
    }

    ASSERT_EQ(provider->getFoundRecords().size(), 100);
}

#include <CodeGraph/Analysis/CompareFunctionBodies.h>
#include <CodeGraph/Analysis/ContextDistance.h>
#include <CodeGraph/Analysis/GenericAnalysis.h>
#include <CodeGraph/FunctionBodyBuilder.h>
TEST_F(ProgramModuleFixture, Test_CodeGraph)
{
    using namespace CodeGraph;
    auto funcManager = m_programModule->getFunctionManager();

    auto function = funcManager->getFunctionAt(&setRot);
    ASSERT_NE(function, nullptr);

    FunctionBodyBuilder builder(function->getBody(), function->getAddressRangeList(), funcManager);
    builder.build();


    CallGraphIterator it(funcManager);
    it.iterate([&](Node::Node* node, CallStack& stack)
        {
            
            return true;
        });
}

#include <GhidraSync/GhidraSyncCommitment.h>
TEST_F(ProgramModuleFixture, Test_GhidraSync)
{
    using namespace Ghidra;
    auto sync = m_programModule->getGhidraSync();
    auto typeManager = m_programModule->getTypeManager();
    auto funcManager = m_programModule->getFunctionManager();
    bool someGhidraSyncError = false;
    DataType::Structure* screen2d_vtable = nullptr;

    //download
    {
        packet::SDataFullSyncPacket dataPacket;
        try {
            Transport tr(sync->getClient());
            sync->getDataSyncPacketManagerServiceClient()->recieveFullSyncPacket(dataPacket);
        }
        catch (std::exception ex) {
            someGhidraSyncError = true;
            printf(ex.what());
        }

        ASSERT_GT(dataPacket.typedefs.size(), 0);
        ASSERT_GT(dataPacket.structures.size(), 0);
        ASSERT_GT(dataPacket.functions.size(), 0);

        typeManager->loadTypesFrom(&dataPacket);
        funcManager->loadFunctionsFrom(&dataPacket);

        auto type = typeManager->getTypeByName("Screen2D");
        if (type != nullptr) {
            int runCode = rand();
            printf("<<< Run code = %i >>>", runCode);

            ASSERT_EQ(type->getSize(), 0x10);
            if (auto screen2d = dynamic_cast<DataType::Structure*>(type)) {
                ASSERT_EQ(screen2d->getFields().size(), 3);

                auto vtable = screen2d->getFields().begin()->second;
                ASSERT_EQ(vtable->getName(), "vtable");
                if (screen2d_vtable = dynamic_cast<DataType::Structure*>(vtable->getType()->getType())) {
                    ASSERT_EQ(screen2d_vtable->getSize(), 0x10);
                    auto vfunc1 = screen2d_vtable->getFields().begin()->second;
                    vfunc1->setComment("runCode = " + std::to_string(runCode));
                }
            }
        }
    }

    //upload
    {
        SyncCommitment SyncCommitment(sync);

        if (screen2d_vtable != nullptr) {
            SyncCommitment.upsert(screen2d_vtable);
        }

        if (false) {
            auto function = funcManager->getFunctionAt(&setRot);
            ASSERT_NE(function, nullptr);
            SyncCommitment.upsert(function);

            auto type = typeManager->getTypeByName("Screen");
            if (auto screen = dynamic_cast<DataType::Structure*>(type)) {
                SyncCommitment.upsert(screen);
            }
        }

        try {
            SyncCommitment.commit();
        }
        catch (std::exception ex) {
            someGhidraSyncError = true;
            printf(ex.what());
        }
    }

    if (someGhidraSyncError) {
        printf("\n*****************\nGhidra not started!!! Impossible to send data packet.\n*****************\n");
    }
}

TEST_F(ProgramModuleFixture, Test_RemoveDB)
{
    //remove test database
    //clear();
}

void executeCode() {
    /*using namespace Ghidra;
    auto m_programModule = (new ProgramModuleFixtureBase)->m_programModule;
    auto sync = m_programModule->getGhidraSync();
    auto typeManager = m_programModule->getTypeManager();
    auto funcManager = m_programModule->getFunctionManager();
    
    Transport tr(sync->getClient());
    packet::SDataFullSyncPacket dataPacket;
    sync->getDataSyncPacketManagerServiceClient()->recieveFullSyncPacket(dataPacket);

    typeManager->loadTypesFrom(&dataPacket);
    funcManager->loadFunctionsFrom(&dataPacket);*/
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
    auto errorMode = GetErrorMode();
    return (int)result + errorMode;
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

    executeCode();

    Hook::init();
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    DebugOutput_Console = true;

	return RUN_ALL_TESTS();
}
