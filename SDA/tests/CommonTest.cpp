#include "CommonTest.h"
using namespace CE;

bool GHIDRA_TEST = false;

TEST(DataType, Parsing)
{
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "*")), "[1]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "***")), "[1][1][1]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "[3][5]")), "[3][5]");
    ASSERT_EQ(DataType::GetPointerLevelStr(DataType::GetUnit(new DataType::Float, "(**[10][5])*")), "[1][10][5][1][1]");
}

TEST_F(ProgramModuleFixtureStart, Test_Common_DataBaseCreatedAndFilled)
{
    EXPECT_GE(m_programModule->getDB().execAndGet("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").getInt(), 20);
    auto tr = m_programModule->getTransaction();
    auto typeManager = m_programModule->getTypeManager();
    auto symbolManager = m_programModule->getSymbolManager();
    auto memoryAreaManager = m_programModule->getMemoryAreaManager();
    auto funcManager = m_programModule->getFunctionManager();
    auto modulesManager = m_programModule->getProcessModuleManager();
    ProcessModule* kernel32;
    ProcessModule* ucrtbase;
    memoryAreaManager->createMainGlobalSymTable(0x1000000);

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

        auto setRotSig = typeManager->createSignature("setRotSig");
        setRotSig->addParameter("arg1", DataType::GetUnit(typeManager->getTypeByName("int32_t")));
        setRotSig->addParameter("arg2", DataType::GetUnit(typeManager->getTypeByName("float")));
        setRotSig->addParameter("arg3", DataType::GetUnit(typeManager->getTypeByName("float")));
        setRotSig->addParameter("arg4", DataType::GetUnit(typeManager->getTypeByName("float")));
        setRotSig->addParameter("arg5", DataType::GetUnit(typeManager->getTypeByName("int32_t")));

        auto sumArraySig = typeManager->createSignature("sumArraySig");
        sumArraySig->addParameter("arr", DataType::GetUnit(typeManager->getTypeByName("int32_t"), "*[3][2]"));
        sumArraySig->addParameter("str", DataType::GetUnit(typeManager->getTypeByName("char"), "*"));

        auto function1 = funcManager->createFunction(g_testFuncName, module,    { AddressRange(&setRot, calculateFunctionSize((byte*)&setRot)) },                   setRotSig, "set rot to an entity");
        auto function2 = funcManager->createFunction("changeGvar", module,    { AddressRange(&changeGvar, calculateFunctionSize((byte*)&changeGvar)) },             typeManager->createSignature("changeGvarSig"));
        auto function3 = funcManager->createFunction("rand", ucrtbase,  { AddressRange(&rand, calculateFunctionSize((byte*)&rand)) },                               typeManager->createSignature("randSig"));
        auto function4 = funcManager->createFunction("setPlayerPos", module,    { AddressRange(&setPlayerPos, calculateFunctionSize((byte*)&setPlayerPos)) },       typeManager->createSignature("setPlayerPosSig"));
        auto function5 = funcManager->createFunction("setPlayerVel", module,    { AddressRange(&setPlayerVel, calculateFunctionSize((byte*)&setPlayerVel)) },       typeManager->createSignature("setPlayerVelSig"));
        auto function6 = funcManager->createFunction("sumArray", module,    { AddressRange(&sumArray, calculateFunctionSize((byte*)&sumArray)) },                   sumArraySig);
        
        auto libExportedFunctions = kernel32->getExportedFunctions();
        for (auto it : libExportedFunctions) {
            if (it.first != "GetErrorMode")
                continue;
            auto function = funcManager->createFunction(it.first, ucrtbase, { AddressRange(it.second, calculateFunctionSize((byte*)it.second)) }, typeManager->createSignature(it.first + "_sig"), "exported function from kernel32.dll");
            tagManager->createUserTag(function, tagManager->m_setTag, "WinAPI", "From kernel32.dll");
            function->setExported(true);
        }

        //for function tags
        {
            tagManager->createUserTag(function1, tagManager->m_getTag, "tag1", "test GET tag1");
            tagManager->createUserTag(function2, tagManager->m_setTag, "tag2", "test SET tag2");
        }
    }

    //for symbols & memory areas
    {
        using namespace Symbol;
        auto stackVar_0x10 = new LocalStackVarSymbol(symbolManager, 0x10, DataType::GetUnit(typeManager->getTypeByName("int32_t")), "stackVar_0x10");
        auto stackVar_0x20 = new LocalStackVarSymbol(symbolManager, 0x10, DataType::GetUnit(typeManager->getTypeByName("int64_t")), "stackVar_0x20");
        symbolManager->bind(stackVar_0x10);
        symbolManager->bind(stackVar_0x20);
        auto stackFrame = memoryAreaManager->createSymbolTable(SymbolTable::STACK_SPACE, 0x100);
        stackFrame->addSymbol(stackVar_0x10, 0x10);
        stackFrame->addSymbol(stackVar_0x20, 0x20);
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
        {
            //check space
            ASSERT_EQ(entity->areEmptyFieldsInBytes(0, 20), true);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(19, 1), true);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(20, 4), false);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(23, 1), false);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(24, 6), true);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(30, 3), false);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(30, 50), false);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(49, 1), true);
            //move field
            entity->moveField(20 * 0x8, -10 * 0x8);
            entity->moveFields(30 * 0x8, -10 * 0x8);
            entity->moveField(40 * 0x8, 10 * 0x8);
            //check space
            ASSERT_EQ(entity->areEmptyFieldsInBytes(0, 20), false);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(13, 1), false);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(14, 1), true);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(20, 1), false);
            ASSERT_EQ(entity->areEmptyFieldsInBytes(40, 1), false);
        }

        //derrived class
        auto ped = typeManager->createClass("Ped", "this is a derrived class type");
        ped->setBaseClass(entity);
        ped->addField(100, "head_angle", DataType::GetUnit(typeManager->getTypeByName("float")));
        auto method = funcManager->createFunction("getHeadAngle", modulesManager->getMainModule(), {}, typeManager->createSignature("getHeadAngleSig"));
        ped->addMethod(method);
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

TEST_F(ProgramModuleFixture, Test_Common_DataBaseLoaded)
{
    //for functions
    {
        auto funcManager = m_programModule->getFunctionManager();
        ASSERT_EQ(funcManager->getItemsCount(), 8);
        
        auto func = funcManager->getFunctionAt(&setRot);
        ASSERT_EQ(func->getSignature()->getParameters().size(), 5);
        ASSERT_EQ(func->getAddressRangeList().size(), 1);
        ASSERT_EQ(func->getAddressRangeList().begin()->getMinAddress(), &setRot);
        ASSERT_EQ(func->getName(), g_testFuncName);

        //for function tags
        {
            /*auto tagManager = m_programModule->getFunctionTagManager();
            ASSERT_EQ(tagManager->getItemsCount(), 3 + 2);

            auto tags = tagManager->getTagCollection(func);
            ASSERT_EQ(tags.getTags().size(), 3);*/
        }
    }

    //for symbols & memory areas
    {
        auto symbolManager = m_programModule->getSymbolManager();
        ASSERT_GE(symbolManager->getItemsCount(), 1);
        auto memoryAreaManager = m_programModule->getMemoryAreaManager();
        ASSERT_GE(memoryAreaManager->getItemsCount(), 2);

        if (auto testStackFrame = memoryAreaManager->getSymbolTableById(2)) {
            ASSERT_EQ(testStackFrame->getSymbols().size(), 2);
            //testStackFrame->getSymbolAt(0x10);
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

TEST_F(ProgramModuleFixture, Test_Common_FunctionTrigger)
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
        DereferenceIterator it(arr3, function->getSignature()->getParameters()[0]->getDataType());
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
TEST_F(ProgramModuleFixture, Test_Common_FunctionStatAnalysis)
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

#include <GhidraSync/GhidraSyncCommitment.h>
TEST_F(ProgramModuleFixture, Test_Common_GhidraSync)
{
    if (!GHIDRA_TEST)
        return;
    using namespace Ghidra;
    auto sync = m_programModule->getGhidraSync();
    auto typeManager = m_programModule->getTypeManager();
    auto funcManager = m_programModule->getFunctionManager();
    DataType::Structure* screen2d_vtable = nullptr;

    //download
    {
        packet::SDataFullSyncPacket dataPacket;
        try {
            Transport tr(sync->getClient());
            sync->getDataSyncPacketManagerServiceClient()->recieveFullSyncPacket(dataPacket);
        }
        catch (std::exception ex) {
            printf("\n*****************\nGhidra not started!!! Impossible to send data packet.\n*****************\n");
            printf(ex.what());
            printf("\n");
            return;
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
                if (screen2d_vtable = dynamic_cast<DataType::Structure*>(vtable->getDataType()->getType())) {
                    ASSERT_EQ(screen2d_vtable->getSize(), 0x10);
                    auto it = screen2d_vtable->getFields().begin();
                    auto vfunc1 = it->second;
                    vfunc1->setComment("runCode = " + std::to_string(runCode));
                    it++;
                    if (auto vfunc2 = dynamic_cast<DataType::Signature*>(it->second->getDataType()->getType())) {
                        ASSERT_EQ(vfunc2->getParameters().size(), 1);
                        ASSERT_EQ(vfunc2->getParameters()[0]->getDataType()->getType(), screen2d);
                    }
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

        //class
        {
            auto type = typeManager->getTypeByName("Entity");
            if (auto screen = dynamic_cast<DataType::Class*>(type)) {
                SyncCommitment.upsert(screen);
            }
        }

        try {
            SyncCommitment.commit();
        }
        catch (std::exception ex) {
            printf("\n*****************\nGhidra not started!!! Impossible to send data packet.\n*****************\n");
            printf(ex.what());
            printf("\n");
        }
    }
}

TEST_F(ProgramModuleFixture, Test_Common_RemoveDB)
{
    //remove test database
    //clear();
}










class SomeClass
{
public:
    virtual int getValue() {
        return 4;
    }
};

SomeClass* g_someClass = new SomeClass;
int g_IntegerVal;

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

#ifdef UNIT_TEST
int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);
    
    Hook::init();
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    DebugOutput_Console = true;

    //::testing::GTEST_FLAG(filter) = "Test_Dec_*";
	return RUN_ALL_TESTS();
}
#endif
