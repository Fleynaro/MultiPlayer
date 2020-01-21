#include <Program.h>
#include <SdaInterface.h>
#include <CallGraph/CallGraph.h>
Program* g_program = nullptr;


int setRot(int a, float x, float y, float z, int c);


static const char* const TOKEN_TYPES[] =
{
	"INVALID          ",
	"WHITESPACE       ",
	"DELIMITER        ",
	"PARENTHESIS_OPEN ",
	"PARENTHESIS_CLOSE",
	"PREFIX           ",
	"MNEMONIC         ",
	"REGISTER         ",
	"ADDRESS_ABS      ",
	"ADDRESS_REL      ",
	"DISPLACEMENT     ",
	"IMMEDIATE        ",
	"TYPECAST         ",
	"DECORATOR        ",
	"SYMBOL           "
};


ZydisFormatterFunc default_print_address_absolute;

static ZyanStatus ZydisFormatterPrintAddressAbsolute(const ZydisFormatter* formatter,
	ZydisFormatterBuffer* buffer, ZydisFormatterContext* context)
{
	ZyanU64 address;
	ZYAN_CHECK(ZydisCalcAbsoluteAddress(context->instruction, context->operand,
		context->runtime_address, &address));

	
	return default_print_address_absolute(formatter, buffer, context);
}

#include <Disassembler/Disassembler.h>

void dissasm()
{
	using namespace CE::Disassembler;
	Decoder decoder_(&setRot, 200);
	decoder_.decode([&](Code::Instruction& instruction) {
		void* addr = nullptr;

		if (instruction.getMnemonicId() == ZYDIS_MNEMONIC_CALL) {
			auto& instr = (Code::Instructions::Call&)instruction;
			if (instr.hasAbsoluteAddr()) {
				addr = instr.getAbsoluteAddr();
			}
		}

		if (instruction.getMnemonicId() == ZYDIS_MNEMONIC_MOV) {
			auto& instr = (Code::Instructions::Mov&)instruction;
			int a = 5;
		}

		if (instruction.isGeneric()) {
			auto& instr = (Code::Instructions::Generic&)instruction;
			addr = instr.getAbsoluteAddr();
		}

		if (addr != nullptr) {
			int a = 5;
		}

		return true;
	});


	int size = 140;
	ZyanUSize offset = 0;

	ZydisFormatter formatter;
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	char buffer[256];

	default_print_address_absolute = (ZydisFormatterFunc)&ZydisFormatterPrintAddressAbsolute;
	ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS,
		(const void**)&default_print_address_absolute);

	ZyanU64 runtime_address = (ZyanU64)&setRot;

	ZydisDecodedInstruction instruction;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)((ZyanU64)&setRot + offset), size - offset,
		&instruction)))
	{
		ZydisFormatterFormatInstruction(&formatter, &instruction, &buffer[0], sizeof(buffer),
			runtime_address);
		runtime_address += instruction.length;
		ZYAN_PRINTF(" %s\n", &buffer[0]);

		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL || instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
			
			auto op1 = instruction.operands[0].imm.value.s + runtime_address;
			auto op2 = instruction.operands[0].mem.disp.value + runtime_address;
			auto reg = instruction.operands[0].mem.base;
			if (instruction.operands[0].mem.disp.has_displacement) {

			}

			int a = 5;
		}

		/*const ZydisFormatterToken* token;
		if (ZYAN_SUCCESS(ZydisFormatterTokenizeInstruction(&formatter, &instruction, &buffer[0],
			sizeof(buffer), 0, &token)))
		{
			ZydisTokenType token_type;
			ZyanConstCharPointer token_value = nullptr;
			while (token)
			{
				ZydisFormatterTokenGetValue(token, &token_type, &token_value);
				printf("ZYDIS_TOKEN_%17s (%02X): \"%s\"\n", TOKEN_TYPES[token_type], token_type,
					token_value);
				if (!ZYAN_SUCCESS(ZydisFormatterTokenNext(&token)))
				{
					token = nullptr;
				}
			}
		}*/

		offset += instruction.length;
		if (offset >= size) {
			break;
		}
	}
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

float gVar = 0;
void changeGvar() {
	gVar = 2.0;
}

int setRot(int a, float x, float y, float z, int c)
{
	g_IntegerVal = 100;
	float result = x + y + z + a + c + g_someClass->getValue();
	result = pow(result, 1);
	gVar = rand() % 10;
	return result;
}

int main()
{
	g_program = new Program(GetModuleHandle(NULL));
	DebugOutput_Console = false;
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	printf("SDA module executing\n\n");
	using namespace CE;

	/*dissasm();
	return 0;*/

	ProgramExe* sda = new ProgramExe(GetModuleHandle(NULL), FS::Directory("R:\\Rockstar Games\\MULTIPLAYER Dev\\MultiPlayer\\MultiPlayer\\SDA\\Databases"));
	try {
		sda->initDataBase("database.db");
		sda->initGhidraClient();
		sda->initManagers();
		sda->load();

		if(false)
		{
			Ghidra::Client client(sda);
			Ghidra::DataTypeManager& dataTypeManager = *client.m_dataTypeManager;
			Ghidra::FunctionManager& funcManager = *client.m_functionManager;

			auto EntityPosClass = sda->getTypeManager()->createClass("EntityPos", "")->getClass();
			EntityPosClass->addField(0x0, "x", new Type::Float);
			EntityPosClass->addField(0x4, "y", new Type::Float);
			EntityPosClass->addField(0x8, "z", new Type::Float);

			auto EntityClass = sda->getTypeManager()->createClass("Entity", "EntityClass")->getClass();
			EntityClass->addField(20, "position", EntityPosClass, "pos of entity");
			EntityClass->addField(35, "arr", new Type::Array(new Type::Int32, 3), "some arr");
			EntityClass->addField(60, "val2", new Type::Float, "some value");
			EntityClass->resize(0);

			auto PedClass = sda->getTypeManager()->createClass("Ped", "PedClass")->getClass();
			PedClass->setBaseClass(EntityClass);
			PedClass->addField(30, "arr", new Type::Array(new Type::Int32, 40), "some big arr");

			dataTypeManager.buildDesc(EntityPosClass);
			dataTypeManager.buildDesc(EntityClass);
			dataTypeManager.buildDesc(PedClass);

			Ghidra::datatype::Id id = dataTypeManager.getId(new Type::Array(new Type::Int8, 2));
			auto type = dataTypeManager.findTypeById(id);

			try {
				dataTypeManager.updateAll();
				/*dataTypeManager.updateTypedefs(Ghidra::DataTypeManager::HashMap());
				dataTypeManager.updateTypedefs(dataTypeManager.generateHashMap());
				dataTypeManager.updateTypedefs(dataTypeManager.generateHashMap());*/
				/*dataTypeManager.updateEnums(Ghidra::DataTypeManager::HashMap());
				dataTypeManager.updateEnums(dataTypeManager.generateHashMap());
				dataTypeManager.updateEnums(dataTypeManager.generateHashMap());*/
				/*dataTypeManager.updateStructures(Ghidra::DataTypeManager::HashMap());
				dataTypeManager.updateStructures(dataTypeManager.generateHashMap());
				dataTypeManager.updateStructures(dataTypeManager.generateHashMap());*/

				funcManager.update(funcManager.generateHashMap());
				funcManager.update(funcManager.generateHashMap());

				if (false) {
					auto func = sda->getFunctionManager()->getFunctionById(4)->getFunction();
					func->setName("AllocateMemory");
					func->getSignature().setReturnType(new Type::Pointer(new Type::Void));
					func->deleteAllArguments();
					func->addArgument(new Type::Pointer(new Type::Void), "addr");
					func->setDesc("this allocate memory\nlol");

					funcManager.push({
						funcManager.buildDesc(func)
						});
				}

				dataTypeManager.push({
					dataTypeManager.buildDesc(EntityPosClass),
					dataTypeManager.buildDesc(EntityClass),
					dataTypeManager.buildDesc(PedClass)
					});
				//dataTypeManager.updateStructures();
			}
			catch (TException& tx) {
				DebugOutput("exception: " + std::string(tx.what()));
			}

			return 0;
			auto enumeration = sda->getTypeManager()->createEnum("EntityType", "lolldlsaldlas 2020!")->getEnum();
			enumeration->addField("PED", 1);
			enumeration->addField("CAR", 130);
			enumeration->addField("VEHICLE", 0x93522223);

			try {
				dataTypeManager.push({
					dataTypeManager.buildDesc(enumeration)
					});

				/*auto structures = dataTypeManager.pullStructures(
					Ghidra::HashMap()
				);

				auto enums = dataTypeManager.pullEnums(
					Ghidra::HashMap()
				);*/
				int a = 5;
			}
			catch (TException& tx) {
				DebugOutput("exception: " + std::string(tx.what()));
			}
			return 0;
		}

		auto functiondb = sda->getFunctionManager()->createFunction(&setRot, { Function::Function::Range(&setRot, 200) }, "setRot", "get rot of entity");
		auto function = functiondb->getFunction();

		CallGraph::FunctionBodyBuilder bodyBuilder(functiondb);
		bodyBuilder.build();
		functiondb->setBody(bodyBuilder.getFunctionBody());
		CallGraph::Analyser::Generic analysis(functiondb);
		analysis.doAnalyse();
		
		functiondb->change([&] {
			function->addArgument(new Type::Int32, "a");
			function->addArgument(new Type::Float, "x");
			function->addArgument(new Type::Float, "y");
			function->addArgument(new Type::Float, "z");
			function->addArgument(new Type::Int32, "c");
		});

		auto hook = function->createHook();
		hook->getDynHook()->setArgCount(5);
		hook->getDynHook()->setMethod(new CE::Hook::Method::Method2<CE::Trigger::Function::TriggerState>(hook->getDynHook()));
		hook->getDynHook()->hook();

		auto trigger = sda->getTriggerManager()->createFunctionTrigger("for filtering");
		//auto filter1 = new Trigger::Function::Filter::Object(nullptr);
		//auto filter1 = new Trigger::Function::Filter::Empty;
		auto filter1 = new Trigger::Function::Filter::Cmp::Argument(1, 12, Trigger::Function::Filter::Cmp::Eq);
		//auto filter1 = new Trigger::Function::Filter::Cmp::RetValue(12, Trigger::Function::Filter::Cmp::Eq);

		trigger->setStatArgManager(sda->getStatManager()->getFuncArgManager());
		trigger->setStatRetManager(sda->getStatManager()->getFuncRetManager());
		trigger->addFilter(filter1);
		hook->addTrigger(trigger);

		//sda->getTriggerManager()->saveTrigger(trigger);
		//sda->getTriggerManager()->loadTriggers();

		//if(false)
		{
			using namespace CE::Stat::Function;
			Account account(&sda->getStatManager()->getDB(), function);
			account.iterateCalls([&](Account::CallInfo& info) {
				printf("callId = %llu: %i,%i,%i,%i(float %f,%f,%f,%f) => %i(float %f)\n", info.m_uid, info.m_args[0], info.m_args[1], info.m_args[2], info.m_args[3], info.m_xmm_args[0], info.m_xmm_args[1], info.m_xmm_args[2], info.m_xmm_args[3], info.m_ret, info.m_xmm_ret);
				}, trigger, 1);

			auto statInfo = account.createStatInfo(trigger);
			statInfo->debugShow();
			return 0;
		}
		//return;
		//CE::Trigger::Function::callback_before(hook->getDynHook(), 0);
		//CE::Trigger::Function::callback_before(hook->getDynHook(), 0);

		/*CE::Hook::DynHook::newCallState();
		CE::Hook::DynHook::newCallState();*/

		//int result = setRot(9, -10, 11, -12, 13);
//		setRot(10, 11, 12);


		//std::thread t([&] {
		//	auto hook = new CE::Hook::DynHook;
		//	hook->setUserPtr(function);
		//	while (true) {
		//		CE::Trigger::Function::callback_before(hook, 0);
		//	}
		//	});
		//t.detach();

		//printf("%i\n", result);

		sda->getStatManager()->clearGeneralDB();

		for (int i = 0; i < 1; i++)
		{
			std::thread t([i] {
				for (int j = 0; j < 10; j++) {
					setRot(10 + j, -10, 10, 888.4, 999);
					//Sleep(1);
				}
				});
			t.detach();
		}

		Sleep(2000);
		printf("\n\nupdateGeneralDB\n");
		sda->getStatManager()->updateGeneralDB();

		//sda->getFunctionManager()->saveFunction(function);
		//sda->getFunctionManager()->saveFunctionArguments(function);

		auto method = sda->getFunctionManager()->getFunctionById(3);


		printf("%s | %s\n", method->getFunction()->getSigName().c_str(), sda->getTypeManager()->getTypeById(11)->getType()->getName());
	}
	catch (std::exception& e) {
		DebugOutput("exception: " + std::string(e.what()));
	}


	/*Type::Class* entity = new Type::Class(100, "Entity");

	Function::Method* setPos = new Function::Method(nullptr, 0, 50, "setPos");
	setPos->getSignature().setReturnType(new Type::Void);
	setPos->addArgument(nullptr, "This");
	setPos->addArgument(new Type::Float, "x");
	setPos->addArgument(new Type::Float, "y");
	setPos->addArgument(new Type::Float, "z");
	entity->addMethod(setPos);

	Function::Method* setVel = new Function::Method(nullptr, 0, 50, "setPos");
	setVel->getSignature().setReturnType(new Type::Void);
	setVel->addArgument(nullptr, "This");
	setVel->addArgument(new Type::Float, "x");
	setVel->addArgument(new Type::Float, "y");
	setVel->addArgument(new Type::Float, "z");
	entity->addMethod(setVel);

	entity->iterateMethods([](Function::Method* method) {
		printf("%s\n", method->getSigName().c_str());
	});*/

	printf("\n\n");
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DebugOutput("sda.dll loaded successfully!");
		g_program = new Program(hModule);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}