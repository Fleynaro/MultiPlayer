#pragma once
#include <DB/Transaction.h>
#include <Utility/FileWrapper.h>

using namespace SQLite;

namespace CE
{
	class TypeManager;
	class GVarManager;
	class FunctionManager;
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
		ProgramModule(void* addr, FS::Directory dir);

		~ProgramModule();

		virtual bool isExe() = 0;

		bool isDll();

		void initTransaction();

		void load();

		void initManagers();

		void initGhidraClient();

		void createGeneralDataBase();

		void initDataBase(std::string filename);

		SQLite::Database& getDB();

		HMODULE getHModule();

		TypeManager* getTypeManager();

		GVarManager* getGVarManager();

		FunctionManager* getFunctionManager();

		VtableManager* getVTableManager();

		TriggerManager* getTriggerManager();

		TriggerGroupManager* getTriggerGroupManager();

		StatManager* getStatManager();

		std::uintptr_t getBaseAddr();

		void* toAbsAddr(int offset);

		int toRelAddr(void* addr);

		DB::ITransaction* getTransaction();

		FS::Directory& getDirectory();

		Ghidra::Client* getGhidraClient();
	private:
		DB::ITransaction* m_transaction = nullptr;
		SQLite::Database* m_db = nullptr;
		std::uintptr_t m_baseAddr;
		FS::Directory m_dir;

		TypeManager* m_typeManager = nullptr;
		GVarManager* m_gvarManager = nullptr;
		FunctionManager* m_functionManager = nullptr;
		VtableManager* m_vtableManager = nullptr;
		TriggerManager* m_triggerManager = nullptr;
		TriggerGroupManager* m_triggerGroupManager = nullptr;
		StatManager* m_statManager = nullptr;
		Ghidra::Client* m_client = nullptr;
	};

	class ProgramDll : public ProgramModule
	{
	public:
		ProgramDll(void* addr, FS::Directory dir);

		bool isExe() override;
	};

	class ProgramExe : public ProgramModule
	{
	public:
		ProgramExe(void* addr, FS::Directory dir);

		bool isExe() override;

		void addDll(ProgramDll* dll);

		std::vector<ProgramDll*>& getDlls();
	private:
		std::vector<ProgramDll*> m_dlls;
	};
};