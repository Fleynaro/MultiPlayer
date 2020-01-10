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

	class SDA
	{
	public:
		SDA(void* addr, FS::Directory dir)
			: m_baseAddr((std::uintptr_t)addr), m_dir(dir)
		{}

		void load();
		void initManagers();
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
			return (void*)(getBaseAddr() + (std::uintptr_t)offset);
		}

		int toRelAddr(void* addr) {
			return (std::uintptr_t)addr - getBaseAddr();
		}

		FS::Directory& getDirectory() {
			return m_dir;
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
	};
};