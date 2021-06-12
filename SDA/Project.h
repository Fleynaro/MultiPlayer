#pragma once
#include <DB/Transaction.h>
#include <Address/ProcessModule.h>
#include <GhidraSync/GhidraSync.h>

using namespace SQLite;

namespace CE
{
	class ProcessModuleManager;
	class TypeManager;
	class SymbolManager;
	class SymbolTableManager;
	class FunctionManager;
	class FunctionTagManager;
	class VtableManager;
	class TriggerManager;
	class TriggerGroupManager;
	class StatManager;

	namespace Ghidra {
		class Client;
	};

	namespace Symbol {
		class SymbolTable;
	};

	class Project
	{
	public:
		Project(FS::Directory dir);

		~Project();

		void initTransaction();

		void load();

		void initManagers();

		void createGeneralDataBase();

		void initDataBase(std::string filename);

		SQLite::Database& getDB();

		ProcessModuleManager* getProcessModuleManager();

		TypeManager* getTypeManager();

		SymbolManager* getSymbolManager();

		SymbolTableManager* getMemoryAreaManager();

		FunctionManager* getFunctionManager();

		FunctionTagManager* getFunctionTagManager();

		VtableManager* getVTableManager();

		TriggerManager* getTriggerManager();

		TriggerGroupManager* getTriggerGroupManager();

		StatManager* getStatManager();

		Symbol::SymbolTable* getGlobalMemoryArea();

		DB::ITransaction* getTransaction();

		FS::Directory& getDirectory();

		Ghidra::Sync* getGhidraSync();

	private:
		DB::ITransaction* m_transaction = nullptr;
		SQLite::Database* m_db = nullptr;
		FS::Directory m_dir;

		ProcessModuleManager* m_processModuleManager = nullptr;
		TypeManager* m_typeManager = nullptr;
		SymbolManager* m_symbolManager = nullptr;
		SymbolTableManager* m_memoryAreaManager = nullptr;
		FunctionManager* m_functionManager = nullptr;
		VtableManager* m_vtableManager = nullptr;
		TriggerManager* m_triggerManager = nullptr;
		TriggerGroupManager* m_triggerGroupManager = nullptr;
		StatManager* m_statManager = nullptr;
		Ghidra::Sync* m_ghidraSync;

		bool haveAllManagersBeenLoaded() {
			return m_typeManager != nullptr;
		}
	};
};