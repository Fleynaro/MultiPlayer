#pragma once
#include <DB/Transaction.h>
#include <Utility/FileWrapper.h>
#include <Address/ProcessModule.h>
#include <GhidraSync/GhidraSync.h>

using namespace SQLite;

namespace CE
{
	class ProcessModuleManager;
	class TypeManager;
	class GVarManager;
	class FunctionManager;
	class FunctionDeclManager;
	class FunctionTagManager;
	class VtableManager;
	class TriggerManager;
	class TriggerGroupManager;
	class StatManager;

	namespace Ghidra
	{
		class Client;
	};

	class ProgramModule
	{
	public:
		ProgramModule(FS::Directory dir);

		~ProgramModule();

		void initTransaction();

		void load();

		void initManagers();

		void createGeneralDataBase();

		void initDataBase(std::string filename);

		SQLite::Database& getDB();

		ProcessModuleManager* getProcessModuleManager();

		TypeManager* getTypeManager();

		GVarManager* getGVarManager();

		FunctionManager* getFunctionManager();

		FunctionDeclManager* getFunctionDeclManager();

		FunctionTagManager* getFunctionTagManager();

		VtableManager* getVTableManager();

		TriggerManager* getTriggerManager();

		TriggerGroupManager* getTriggerGroupManager();

		StatManager* getStatManager();

		DB::ITransaction* getTransaction();

		FS::Directory& getDirectory();

		Ghidra::Sync* getGhidraSync();

	private:
		DB::ITransaction* m_transaction = nullptr;
		SQLite::Database* m_db = nullptr;
		FS::Directory m_dir;

		ProcessModuleManager* m_processModuleManager = nullptr;
		TypeManager* m_typeManager = nullptr;
		GVarManager* m_gvarManager = nullptr;
		FunctionManager* m_functionManager = nullptr;
		VtableManager* m_vtableManager = nullptr;
		TriggerManager* m_triggerManager = nullptr;
		TriggerGroupManager* m_triggerGroupManager = nullptr;
		StatManager* m_statManager = nullptr;
		Ghidra::Sync* m_ghidraSync;
	};
};