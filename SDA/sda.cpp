#include "sda.h"

CE::Type::SystemType::Types CE::Type::SystemType::GetBasicTypeOf(Type* type)
{
	if (type != nullptr)
	{
		if (type->isSystem())
			return (Types)type->getId();
		if (type->getGroup() == Typedef)
			return GetBasicTypeOf(((CE::Type::Typedef*)type)->getRefType());
	}
	return Types::Void;
}

CE::Type::SystemType::Set CE::Type::SystemType::GetNumberSetOf(Type* type)
{
	if (type->isSystem() && !type->isPointer() && !type->isArray())
		return ((SystemType*)type)->getSet();
	if (type->getGroup() == Typedef)
		return GetNumberSetOf(((CE::Type::Typedef*)type)->getRefType());
	return Set::Undefined;
}

std::string CE::Function::Method::getName() {
	return getClass()->getName() + "::" + Function::getName();
}

void CE::Function::Method::setClass(Type::Class* Class) {
	if (getSignature().getArgList().size() > 0) {
		getSignature().getArgList()[0]->free();
		getSignature().getArgList()[0] = new Type::Pointer(Class);
	}
	else {
		addArgument(new Type::Pointer(Class), "this");
	}
}

void CE::SDA::load()
{
	getTypeManager()->loadTypes();
	getTypeManager()->loadTypedefs();
	getGVarManager()->loadGVars();
	getFunctionManager()->loadFunctions();
	getFunctionManager()->loadFunctionBodies();
	getVTableManager()->loadVTables();
	getTypeManager()->loadClasses();
}

void CE::SDA::initManagers()
{
	m_typeManager = new TypeManager(this);
	m_functionManager = new FunctionManager(this);
	m_gvarManager = new GVarManager(this);
	m_vtableManager = new VtableManager(this);
	m_triggerManager = new TriggerManager(this);
	m_statManager = new StatManager(this);
}

void CE::Ghidra::Client::initManagers() {
	m_dataTypeManager = new DataTypeManager(getSDA()->getTypeManager(), this);
	m_functionManager = new FunctionManager(getSDA()->getFunctionManager(), this);
}

void CE::SDA::initDataBase(std::string filename)
{
	m_db = new SQLite::Database(filename, SQLite::OPEN_READWRITE);
}

CE::Function::Method* CE::Function::Function::getMethodBasedOn() {
	auto method = new Method(m_addr, m_ranges, getId(), getName(), getDesc());
	method->getArgNameList().swap(getArgNameList());
	method->getSignature().getArgList().swap(getSignature().getArgList());
	method->getSignature().setReturnType(getSignature().getReturnType());
	return method;
}

void CE::TypeManager::loadInfoForClass(Type::Class* Class)
{
	using namespace SQLite;

	SQLite::Database& db = getSDA()->getDB();
	SQLite::Statement query(db, "SELECT * FROM sda_classes WHERE class_id=?1");
	query.bind(1, Class->getId());
	query.executeStep();

	Function::VTable* vtable = getSDA()->getVTableManager()->getVTableById(query.getColumn("vtable_id"));
	if (vtable != nullptr) {
		Class->setVtable(vtable);
	}
	Type::Class* baseClass = (Type::Class*)getTypeById(query.getColumn("base_class_id"));
	if (baseClass != nullptr) {
		Class->setBaseClass(baseClass);
	}
	Class->resize(query.getColumn("size"));
}

void CE::TypeManager::loadMethodsForClass(Type::Class* Class) {
	using namespace SQLite;

	SQLite::Database& db = getSDA()->getDB();
	SQLite::Statement query(db, "SELECT function_id FROM sda_class_methods WHERE class_id=?1");
	query.bind(1, Class->getId());

	while (query.executeStep())
	{
		Function::Function* function = getSDA()->getFunctionManager()->getFunctionById(query.getColumn("function_id"));
		if (function != nullptr && function->isMethod()) {
			Class->addMethod((Function::Method*)function);
		}
	}
}

CE::Trigger::Function::Hook* CE::Function::Function::createHook() {
	m_hook = new CE::Trigger::Function::Hook(this);
	return m_hook;
}

CE::Trigger::Function::Hook::Hook(CE::Function::Function* func)
{
	m_hook = CE::Hook::DynHook(func->getAddress(), &callback_before, &callback_after);
	m_hook.setUserPtr(func);
}

void CE::Stat::Function::Args::Garbager::add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
{
	m_bufferMutex.lock();
	m_buffers.push(Buffer(hook, trigger));
	m_bufferMutex.unlock();
}

void CE::Stat::Function::Ret::Garbager::add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
{
	m_bufferMutex.lock();
	m_buffers.push(Buffer(hook, trigger));
	m_bufferMutex.unlock();
}

void CE::Stat::Function::Args::Garbager::send(Buffer& buffer)
{
	try {
		SQLite::Database& db = getDB();
		//SQLite::Transaction transaction(db);
		
		{
			SQLite::Statement query(db, "INSERT INTO sda_call_before (id, function_id, trigger_id) VALUES(?1, ?2, ?3)");
			query.bind(1, (long long)buffer.m_uid);
			query.bind(2, buffer.getFunction()->getId());
			query.bind(3, buffer.m_trigger->getId());
			query.exec();
		}

		{
			for (int i = 0; i < buffer.m_hook->getArgCount(); i++) {
				SQLite::Statement query(db, "INSERT INTO sda_call_args (call_id, id, value) VALUES(?1, ?2, ?3)");
				query.bind(1, (long long)buffer.m_uid);
				query.bind(2, i + 1);
				query.bind(3, (long long)buffer.m_args[i]);
				query.exec();
			}

			if (buffer.m_hook->isXmmSaved())
			{
				for (int i = 0; i < min(4, buffer.m_hook->getArgCount()); i++) {
					SQLite::Statement query(db, "INSERT INTO sda_call_args (call_id, id, value) VALUES(?1, ?2, ?3)");
					query.bind(1, (long long)buffer.m_uid);
					query.bind(2, -(i + 1));
					query.bind(3, (long long)buffer.m_xmm_args[i]);
					query.exec();
				}
			}
		}

		//transaction.commit();
	}
	catch (std::exception & e) {
		std::cout << "exception: " << e.what() << std::endl;
		Sleep(5000);
	}
}

void CE::Stat::Function::Ret::Garbager::send(Buffer& buffer)
{
	try {
		SQLite::Database& db = getDB();
		{
			SQLite::Statement query(db, "INSERT INTO sda_call_after (id, ret_value, ret_xmm_value, elapsed_time) VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, (long long)buffer.m_uid);
			query.bind(2, (long long)buffer.m_ret);
			query.bind(3, (long long)buffer.m_xmm_ret);
			query.bind(4, 1);
			query.exec();
		}
	}
	catch (std::exception & e) {
		std::cout << "exception: " << e.what() << std::endl;
		Sleep(5000);
	}
}

float gVar = 0;

int setRot(int a, float x, float y, float z, int c)
{
	float result = x + y + z + a + c;
	result = pow(result, 1);
	gVar = rand() % 10;
	return result;
}

//TODO:
/*
	1) проверить систему хука тщательно
	2) сохранять триггеры и фильтры+действия к ним(в виде джсона или типа того)
	3) сделать управление сборщиками статистики. копирование данных из нескольких в общую бд
	4) thift by amazon. проверить и попробовать
	5) разделить по файлам
	6) сделать поиск по функциям с фильтром и тд

	(+)7) сделать анализатор полученной статистики. строить график и тд(мат. стат)
		7.1) создать объект итоговой статистики для каждой функции. в этом объекте находится список объектов для каждого аргумента и возвращаемого значения


	8) сбор статистики для глобальных переменных
	9) система категорий
	10) анализ дерева вызовов и делание выводов о принадлежности функции определенным категориям


	случайно обнаружено ghidra:
	1) 7ff71db368f8 - массив строк, где указывается sp0,sp1,mp0,mp1
*/


void module_sda()
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

	SDA* sda = new SDA(GetModuleHandle(NULL), FS::Directory("SDA\\database"));
	try {
		sda->initDataBase("SDA//database//database.db");
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

			return;
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
			return;
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
			return;
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
	catch (std::exception & e) {
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
}

void CE::Stat::Function::Account::iterateCalls(std::function<void(CallInfo & info)> handler, CE::Trigger::Function::Trigger* trigger, int page, int pageSize)
{
	using namespace SQLite;

	SQLite::Database& db = getDB();
	SQLite::Statement query(db, "SELECT ca.id,ca.ret_value,ca.ret_xmm_value,ca.elapsed_time FROM sda_call_before AS cb JOIN sda_call_after AS ca ON cb.id=ca.id WHERE cb.function_id=?1 AND cb.trigger_id=?2 LIMIT ?3,?4");
	query.bind(1, m_function->getId());
	query.bind(2, trigger->getId());
	query.bind(3, (page - 1) * pageSize);
	query.bind(4, pageSize);

	while (query.executeStep())
	{
		CallInfo info;
		info.m_uid = (long long)query.getColumn("id");
		info.m_ret = (long long)query.getColumn("ret_value");
		info.m_xmm_ret = (long long)query.getColumn("ret_xmm_value");

		SQLite::Statement query_args(db, "SELECT ca.id,ca.value FROM sda_call_before AS cb JOIN sda_call_args AS ca ON cb.id=ca.call_id WHERE ca.call_id=?1");
		query_args.bind(1, (long long)info.m_uid);
		while (query_args.executeStep())
		{
			int id = query_args.getColumn("id");
			if (id > 0) {
				info.m_args[id - 1] = (long long)query_args.getColumn("value");
			}
			else
				info.m_xmm_args[-id - 1] = (long long)query_args.getColumn("value");
		}

		handler(info);
	}
}

CE::Stat::Function::StatInfo* CE::Stat::Function::Account::createStatInfo(CE::Trigger::Function::Trigger* trigger)
{
	using namespace SQLite;
	using namespace CE::Type;

	auto& signature = m_function->getSignature();
	StatInfo* statInfo = new StatInfo;
	SQLite::Database& db = getDB();

	{
		SQLite::Statement query(db, "SELECT ca.ret_value,ca.ret_xmm_value,ca.elapsed_time FROM sda_call_before AS cb JOIN sda_call_after AS ca ON cb.id=ca.id WHERE cb.function_id=?1 AND cb.trigger_id=?2");
		query.bind(1, m_function->getId());
		query.bind(2, trigger->getId());

		Analyser ret;
		Analyser xmm_ret;
		while (query.executeStep())
		{
			ret.addValue((long long)query.getColumn("ret_value"));
			xmm_ret.addValue((long long)query.getColumn("ret_xmm_value"));
		}

		ret.doAnalyse();
		xmm_ret.doAnalyse();

		if (ret.getSet() == SystemType::Integer) {
			ret.setTypeId(SystemType::GetBasicTypeOf(signature.getReturnType()));
		}

		statInfo->setReturnValue(getValueByAnalysers(ret, xmm_ret, signature.getReturnType()));
	}

	{
		auto& argList = signature.getArgList();

		SQLite::Statement query(db, "SELECT ca.id,ca.value FROM sda_call_before AS cb JOIN sda_call_args AS ca ON cb.id=ca.call_id WHERE cb.function_id=?1 AND cb.trigger_id=?2");
		query.bind(1, m_function->getId());
		query.bind(2, trigger->getId());

		Analyser args[12];
		Analyser xmm_args[4];

		while (query.executeStep())
		{
			int arg_id = query.getColumn("id");

			if (arg_id > 0) {
				args[arg_id - 1].addValue((long long)query.getColumn("value"));
			}
			else
				xmm_args[-arg_id - 1].addValue((long long)query.getColumn("value"));
		}

		for (int i = 0; i < min(4, argList.size()); i++)
			xmm_args[i].doAnalyse();
		for (int i = 0; i < argList.size(); i++) {
			args[i].doAnalyse();
			if (args[i].getSet() == SystemType::Integer) {
				args[i].setTypeId(SystemType::GetBasicTypeOf(argList[i]));
			}
		}

		for (int i = 0; i < min(4, argList.size()); i++)
			statInfo->addArgument(getValueByAnalysers(args[i], xmm_args[i], argList[i]));
		for (int i = 4; i < argList.size(); i++)
			statInfo->addArgument(StatInfo::Value(args[i].getSet(), args[i].getTypeId(), args[i].createHistogram()));
	}

	return statInfo;
}
