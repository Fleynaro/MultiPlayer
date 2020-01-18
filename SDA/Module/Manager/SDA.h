#pragma once
#include <SQLiteCpp/SQLiteCpp.h>
#include <Utility/FileWrapper.h>

using namespace SQLite;

namespace CE
{
	class TypeManager;
	class GVarManager;
	class FunctionManager;
	class VtableManager;
	class TriggerManager;
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

		void load();
		void initManagers();
		void initGhidraClient();
		void initDataBase(std::string filename);

		inline SQLite::Database& getDB() {
			return *m_db;
		}

		inline TypeManager* getTypeManager() {
			return m_typeManager;
		}

		inline GVarManager* getGVarManager() {
			return m_gvarManager;
		}

		inline FunctionManager* getFunctionManager() {
			return m_functionManager;
		}

		inline VtableManager* getVTableManager() {
			return m_vtableManager;
		}

		inline TriggerManager* getTriggerManager() {
			return m_triggerManager;
		}

		inline StatManager* getStatManager() {
			return m_statManager;
		}

		inline std::uintptr_t getBaseAddr() {
			return m_baseAddr;
		}

		void* toAbsAddr(int offset) {
			return offset == 0 ? nullptr : (void*)(getBaseAddr() + (std::uintptr_t)offset);
		}

		int toRelAddr(void* addr) {
			return addr == nullptr ? 0 : (std::uintptr_t)addr - getBaseAddr();
		}

		FS::Directory& getDirectory() {
			return m_dir;
		}

		Ghidra::Client* getGhidraClient() {
			return m_client;
		}
	private:
		SQLite::Database* m_db = nullptr;
		std::uintptr_t m_baseAddr;
		FS::Directory m_dir;

		TypeManager* m_typeManager = nullptr;
		GVarManager* m_gvarManager = nullptr;
		FunctionManager* m_functionManager = nullptr;
		VtableManager* m_vtableManager = nullptr;
		TriggerManager* m_triggerManager = nullptr;
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