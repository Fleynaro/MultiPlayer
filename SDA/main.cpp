﻿#include <Manager/Manager.h>
#include <GhidraSync/GhidraSync.h>


float gVar = 0;

int setRot(int a, float x, float y, float z, int c)
{
	float result = x + y + z + a + c;
	result = pow(result, 1);
	gVar = rand() % 10;
	return result;
}


int sda()
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	printf("SDA module executing\n\n");
	using namespace CE;

	//setRot(10, 11, 12);

	/*Stat::Analyser analyser;
	analyser.addValue(1.2);
	analyser.addValue(1.0);
	analyser.addValue(0.0);
	analyser.addValue(7);

	analyser.doAnalyse();
	return;*/

	SDA* sda = new SDA(GetModuleHandle(NULL), FS::Directory("Databases"));
	try {
		sda->initDataBase("Databases//database.db");
		sda->initManagers();
		sda->load();

		{
			Ghidra::Client client(sda);
			Ghidra::DataTypeManager& dataTypeManager = *client.m_dataTypeManager;
			Ghidra::FunctionManager& funcManager = *client.m_functionManager;

			auto EntityPosClass = sda->getTypeManager()->createClass("EntityPos", "");
			EntityPosClass->addField(0x0, "x", new Type::Float);
			EntityPosClass->addField(0x4, "y", new Type::Float);
			EntityPosClass->addField(0x8, "z", new Type::Float);

			auto EntityClass = sda->getTypeManager()->createClass("Entity", "EntityClass");
			EntityClass->addField(20, "position", EntityPosClass, "pos of entity");
			EntityClass->addField(35, "arr", new Type::Array(new Type::Int32, 3), "some arr");
			EntityClass->addField(60, "val2", new Type::Float, "some value");
			EntityClass->resize(0);

			auto PedClass = sda->getTypeManager()->createClass("Ped", "PedClass");
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
					auto func = sda->getFunctionManager()->getFunctionById(4);
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
				std::cout << "ERROR: " << tx.what() << std::endl;
			}

			return 0;
			auto enumeration = sda->getTypeManager()->createEnum("EntityType", "lolldlsaldlas 2020!");
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
				std::cout << "ERROR: " << tx.what() << std::endl;
			}
			return 0;
		}

		auto function = sda->getFunctionManager()->createFunction(&setRot, { Function::Function::Range(&setRot, 50) }, "setRot", "get rot of entity");
		function->addArgument(new Type::Int32, "a");
		function->addArgument(new Type::Float, "x");
		function->addArgument(new Type::Float, "y");
		function->addArgument(new Type::Float, "z");
		function->addArgument(new Type::Int32, "c");
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


		printf("%s | %s\n", method->getSigName().c_str(), sda->getTypeManager()->getTypeById(11)->getName());
	}
	catch (std::exception& e) {
		std::cout << "exception: " << e.what() << std::endl;
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
		sda();
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}