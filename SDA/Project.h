#pragma once
#include <DB/Transaction.h>
#include <Address/AddressSpace.h>
#include <GhidraSync/GhidraSync.h>

using namespace SQLite;

namespace CE
{
	class TypeManager;
	class SymbolManager;
	class SymbolTableManager;
	class FunctionManager;
	class AddressSpaceManager;
	class ImageManager;
	class TriggerManager;
	class StatManager;

	namespace Ghidra {
		class Client;
	};

	namespace Symbol {
		class SymbolTable;
	};

	class Project
	{
		bool m_allManagersHaveBeenLoaded = false;
		DB::ITransaction* m_transaction = nullptr;
		SQLite::Database* m_db = nullptr;

		// the directory is an id for a project
		fs::path m_directory;

		TypeManager* m_typeManager = nullptr;
		SymbolManager* m_symbolManager = nullptr;
		SymbolTableManager* m_symbolTableManager = nullptr;
		FunctionManager* m_functionManager = nullptr;
		AddressSpaceManager* m_addrSpaceManager = nullptr;
		ImageManager* m_imageManager = nullptr;
		TriggerManager* m_triggerManager = nullptr;
		StatManager* m_statManager = nullptr;
		Ghidra::Sync* m_ghidraSync;
	public:
		Project(const fs::path& dir);

		~Project();

		void load();

		void save() {
			// save data into database
			m_transaction->commit();
		}

		void initManagers();

		void initDataBase(const fs::path& file);

		SQLite::Database& getDB();

		TypeManager* getTypeManager();

		SymbolManager* getSymbolManager();

		SymbolTableManager* getSymTableManager();

		FunctionManager* getFunctionManager();

		AddressSpaceManager* getAddrSpaceManager();

		ImageManager* getImageManager();

		TriggerManager* getTriggerManager();

		StatManager* getStatManager();

		Symbol::SymbolTable* getGlobalMemoryArea();

		DB::ITransaction* getTransaction();

		const fs::path& getDirectory();

		const fs::path& getImagesDirectory();

		Ghidra::Sync* getGhidraSync();

	private:
		void initTransaction();

		void createTablesInDatabase();
	};
};