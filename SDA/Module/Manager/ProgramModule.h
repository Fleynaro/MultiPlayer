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
		ProgramModule(void* addr, FS::Directory dir)
			: m_baseAddr((std::uintptr_t)addr), m_dir(dir)
		{}

		virtual bool isExe() = 0;

		bool isDll() {
			return !isExe();
		}

		void initTransaction() {
			m_transaction = new DB::Transaction(m_db);
		}

		void load();

		void initManagers();

		void initGhidraClient();

		void createGeneralDataBase();

		void initDataBase(std::string filename);

		SQLite::Database& getDB() {
			return *m_db;
		}

		HMODULE getHModule() {
			return HMODULE(m_baseAddr);
		}

		TypeManager* getTypeManager() {
			return m_typeManager;
		}

		GVarManager* getGVarManager() {
			return m_gvarManager;
		}

		FunctionManager* getFunctionManager() {
			return m_functionManager;
		}

		VtableManager* getVTableManager() {
			return m_vtableManager;
		}

		TriggerManager* getTriggerManager() {
			return m_triggerManager;
		}

		TriggerGroupManager* getTriggerGroupManager() {
			return m_triggerGroupManager;
		}

		StatManager* getStatManager() {
			return m_statManager;
		}

		std::uintptr_t getBaseAddr() {
			return m_baseAddr;
		}

		void* toAbsAddr(int offset) {
			return offset == 0 ? nullptr : reinterpret_cast<void*>(getBaseAddr() + (std::uintptr_t)offset);
		}

		int toRelAddr(void* addr) {
			return addr == nullptr ? 0 : static_cast<int>((std::uintptr_t)addr - getBaseAddr());
		}

		DB::ITransaction* getTransaction() {
			return nullptr;
		}

		FS::Directory& getDirectory() {
			return m_dir;
		}

		Ghidra::Client* getGhidraClient() {
			return m_client;
		}
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
		ProgramDll(void* addr, FS::Directory dir)
			: ProgramModule(addr, dir)
		{}

		bool isExe() override {
			return false;
		}
	};

	class ProgramExe : public ProgramModule
	{
	public:
		ProgramExe(void* addr, FS::Directory dir)
			: ProgramModule(addr, dir)
		{}

		bool isExe() override {
			return true;
		}

		void addDll(ProgramDll* dll) {
			m_dlls.push_back(dll);
		}

		std::vector<ProgramDll*>& getDlls() {
			return m_dlls;
		}
	private:
		std::vector<ProgramDll*> m_dlls;
	};
};