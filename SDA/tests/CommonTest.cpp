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

TEST_F(ProgramFixture, Test_Common_DataBaseCreatedAndFilled)
{
    createProject("test");

    // check count of tables
    EXPECT_EQ(m_project->getDB().execAndGet("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").getInt(), 9);

    // create the address space
    auto testAddrSpace = m_project->getAddrSpaceManager()->createAddressSpace("testAddrSpace");

    // create the image decorator
    auto testImageDec = m_project->getImageManager()->createImage(testAddrSpace, ImageDecorator::IMAGE_PE, "testImageSpace");
    fs::copy_file(m_program->getExecutableDirectory() / "test_images/img1.exe", m_program->getExecutableDirectory() / "testAddrSpace/testImageSpace.exe");
    testImageDec->load();

    // check raw-image
    ASSERT_EQ(testImageDec->getAddress(), 0x140000000);
    ASSERT_EQ(testImageDec->getSize(), 0x63000);

    // create data types
    {
        // enumeration
        auto EntityType = m_typeManager->getFactory().createEnum("EntityType", "this is a enumeration");
        EntityType->addField("PED", 1);
        EntityType->addField("CAR", 2);
        EntityType->addField("VEHICLE", 3);

        // typedef
        auto MyEntityType = m_typeManager->getFactory().createTypedef("MyEntityType");
        MyEntityType->setRefType(DataType::GetUnit(EntityType));

        // structure
        auto Screen = m_typeManager->getFactory().createStructure("Screen", "this is a structure type");
        Screen->addField(0, "width", DataType::GetUnit(m_typeManager->findTypeByName("float")));
        Screen->addField(4, "height", DataType::GetUnit(m_typeManager->findTypeByName("float")));
        ASSERT_EQ(Screen->getSize(), 8);

        // structure
        auto Entity = m_typeManager->getFactory().createStructure("Entity", "this is a class type");
        Entity->addField(20, "type", DataType::GetUnit(MyEntityType), "position of entity");
        auto tPos = DataType::GetUnit(m_typeManager->findTypeByName("float"), "[3]");
        Entity->addField(30, "pos", tPos, "position of entity");
        Entity->addField(50, "screen", DataType::GetUnit(Screen), "screen of entity");
        ASSERT_EQ(Entity->getSize(), 58);
        {
            // check space
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(0, 20), true);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(19, 1), true);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(20, 4), false);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(23, 1), false);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(24, 6), true);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(30, 3), false);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(30, 50), false);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(49, 1), true);
            // move field
            Entity->moveField(20 * 0x8, -10 * 0x8);
            Entity->moveFields(30 * 0x8, -10 * 0x8);
            Entity->moveField(40 * 0x8, 10 * 0x8);
            // check space
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(0, 20), false);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(13, 1), false);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(14, 1), true);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(20, 1), false);
            ASSERT_EQ(Entity->areEmptyFieldsInBytes(40, 1), false);
        }
    }

    // create the test function 1
    Function::Function* testFunc1;
    {
        // create the function graph
        auto testFunc1_graph = testImageDec->getPCodeGraph()->createFunctionGraph();
        {
            auto block1 = testImageDec->getPCodeGraph()->createBlock(0x1000, 0x1200);
            testFunc1_graph->addBlock(block1);
            auto block2 = testImageDec->getPCodeGraph()->createBlock(0x1000, 0x1200);
            testFunc1_graph->addBlock(block2);

            block1->setNextFarBlock(block2);
            testFunc1_graph->setStartBlock(block1);
        }

        // create the function signature
        auto testFunc1_sig = m_typeManager->getFactory().createSignature(DataType::IFunctionSignature::FASTCALL, "testFunc1_sig");
        testFunc1_sig->addParameter("value", DataType::GetUnit(m_typeManager->findTypeById(DataType::SystemType::Int32)));
        testFunc1_sig->addParameter("fValue", DataType::GetUnit(m_typeManager->findTypeByName("float")));
        testFunc1_sig->addParameter("array", DataType::GetUnit(m_typeManager->findTypeByName("int32_t"), "*[3][2]"));
        testFunc1_sig->addParameter("pStr", DataType::GetUnit(m_typeManager->findTypeByName("char"), "*"));
        testFunc1_sig->setReturnType(DataType::GetUnit(m_typeManager->findTypeByName("int64_t")));

        // create the function itself
        testFunc1 = m_funcManager->getFactory().createFunction(0x1000, testFunc1_sig, testImageDec, "testFunc1");
    }

    // create the test function 2
    Function::Function* testFunc2;
    {
        // create the function graph
        auto testFunc2_graph = testImageDec->getPCodeGraph()->createFunctionGraph();
        {
            auto block1 = testImageDec->getPCodeGraph()->createBlock(0x2000, 0x2500);
            testFunc2_graph->addBlock(block1);
            testFunc2_graph->setStartBlock(block1);
        }

        // create the function signature
        auto testFunc2_sig = m_typeManager->getFactory().createSignature(DataType::IFunctionSignature::FASTCALL, "testFunc2_sig");
        testFunc2_sig->addParameter("pEntity", DataType::GetUnit(m_typeManager->findTypeByName("Entity"), "*"));
        testFunc2_sig->addParameter("screen", DataType::GetUnit(m_typeManager->findTypeByName("Screen")));

        // create the function itself
        testFunc2 = m_funcManager->getFactory().createFunction(0x2000, testFunc2_sig, testImageDec, "testFunc2");

        // create a local var
        {
            auto stackVar_0x10 = m_symManager->getFactory().createLocalStackVarSymbol(0x10, DataType::GetUnit(m_typeManager->findTypeByName("int32_t")), "stackVar_0x10");
            testFunc2->getStackSymbolTable()->addSymbol(stackVar_0x10, 0x10);
        }
    }

    // make connections for the func. call graph
    testFunc1->getFuncGraph()->addNonVirtFuncCall(testFunc2->getFuncGraph());

    try {
        m_tr->commit();
    }
    catch (std::exception& e) {
        std::cout << "Transaction commit: " << std::string(e.what());
        ASSERT_EQ(0, 1);
    }
}

TEST_F(ProgramFixture, Test_Common_DataBaseCreatedAndFilled)
{
    loadProject("test");

    // load the address space
    auto testAddrSpace = m_project->getAddrSpaceManager()->findAddressSpaceByName("testAddrSpace");

    // load the image decorator
    auto testImageDec = m_project->getImageManager()->findImageByName("testImageSpace");

    // check raw-image
    ASSERT_EQ(testImageDec->getAddress(), 0x140000000);

    // load data types
    {
        // for structure
        {
            auto type = m_typeManager->findTypeByName("Screen");
            ASSERT_NE(type, nullptr);
            ASSERT_EQ(type->getGroup(), DataType::AbstractType::Structure);
            if (auto screen = dynamic_cast<DataType::Structure*>(type)) {
                ASSERT_EQ(screen->getFields().size(), 2);
            }
        }

        // for structure
        {
            auto type = m_typeManager->findTypeByName("Entity");
            ASSERT_NE(type, nullptr);
            ASSERT_EQ(type->getGroup(), DataType::AbstractType::Structure);
            if (auto entity = dynamic_cast<DataType::Class*>(type)) {
                ASSERT_EQ(entity->getFields().size(), 3);
            }
        }

        // for typedef & enumeration
        {
            auto type = m_typeManager->findTypeByName("EntityType");
            ASSERT_NE(type, nullptr);
            ASSERT_EQ(type->getGroup(), DataType::AbstractType::Typedef);
            if (auto objType = dynamic_cast<DataType::Typedef*>(type)) {
                ASSERT_NE(objType->getRefType(), nullptr);
                ASSERT_EQ(objType->getRefType()->getGroup(), DataType::AbstractType::Enum);
                if (auto refType = dynamic_cast<DataType::Enum*>(objType->getRefType()->getType())) {
                    ASSERT_EQ(refType->getFields().size(), 3);
                }
            }
        }
    }

    // load functions
    {
        ASSERT_EQ(m_funcManager->getItemsCount(), 2);

        auto testFunc1_symbol = dynamic_cast<Symbol::FunctionSymbol*>(testImageDec->getGlobalSymbolTable()->getSymbolAt(0x1000).second);
        ASSERT_NE(testFunc1_symbol, nullptr);
        auto testFunc1 = testFunc1_symbol->getFunction();

        // check func. signature
        {
            ASSERT_EQ(testFunc1->getSignature()->getParameters().size(), 4);
            // check data type for the param 3
            auto testFunc1_param3 = testFunc1->getSignature()->getParameters()[3];
            ASSERT_EQ(testFunc1_param3->getDataType()->getName(), "char");
            ASSERT_EQ(testFunc1_param3->getDataType()->getPointerLevels().size(), 1);
        }

        // func. graph
        ASSERT_EQ(testFunc1->getFuncGraph()->getBlocks().size(), 2);
        ASSERT_EQ(testFunc1->getFuncGraph()->getNonVirtFuncCalls().size(), 1);

        // func. stack
        auto testFunc1_localVar = dynamic_cast<Symbol::LocalStackVarSymbol*>(testFunc1->getStackSymbolTable()->getSymbolAt(0x10).second);
        ASSERT_NE(testFunc1_localVar, nullptr);
    }
}

#ifdef UNIT_TEST
int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);
    
    Hook::init();
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    //::testing::GTEST_FLAG(filter) = "Test_Dec_*";
	return RUN_ALL_TESTS();
}
#endif
