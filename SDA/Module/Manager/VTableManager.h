#pragma once
#include "AbstractManager.h"
#include <Code/VTable/VTable.h>

namespace CE
{
	class VtableManager : public AbstractManager
	{
	public:
		using VTableDict = std::map<int, Function::VTable*>;

		VtableManager(ProgramModule* sda)
			: AbstractManager(sda)
		{}

		void saveVTable(Function::VTable* vtable) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_vtables (id, name, offset, desc) VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, vtable->getId());
			query.bind(2, vtable->getName());
			query.bind(3, getProgramModule()->toRelAddr(vtable->getAddress()));
			query.bind(4, vtable->getDesc());
			query.exec();
		}

		void saveFunctionsForVTable(Function::VTable* vtable) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_vtable_funcs WHERE function_id=?1");
				query.bind(1, vtable->getId());
				query.exec();
			}

			{
				int id = 0;
				for (auto method : vtable->getVMethodList()) {
					SQLite::Statement query(db, "INSERT INTO sda_vtable_funcs (vtable_id, function_id, id) VALUES(?1, ?2, ?3)");
					query.bind(1, vtable->getId());
					query.bind(2, method->getId());
					query.bind(3, id);
					query.exec();
					id++;
				}
			}

			transaction.commit();
		}

		void removeVTable(Function::VTable* vtable) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_vtables WHERE id=?1");
			query.bind(1, vtable->getId());
			query.exec();

			auto it = m_vtables.find(vtable->getId());
			if (it != m_vtables.end()) {
				m_vtables.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_vtables.find(id) != m_vtables.end())
				id++;
			return id;
		}

		Function::VTable* createVTable(void* addr, std::string name, std::string desc = "") {
			int id = getNewId();
			auto vtable = new Function::VTable(addr, id, name, desc);
			m_vtables[id] = vtable;
			return vtable;
		}

		void loadVTables()
		{
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_vtables");

			while (query.executeStep())
			{
				Function::VTable* vtable = new Function::VTable(
					getProgramModule()->toAbsAddr(query.getColumn("offset")),
					query.getColumn("id"),
					query.getColumn("name"),
					query.getColumn("desc")
				);

				loadFunctionsForVTable(vtable);
				addVTable(vtable);
			}
		}

		void loadFunctionsForVTable(Function::VTable* vtable)
		{
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT function_id FROM sda_vtable_funcs WHERE vtable_id=?1 GROUP BY id");
			query.bind(1, vtable->getId());

			while (query.executeStep())
			{
				auto function = getProgramModule()->getFunctionManager()->getFunctionById(query.getColumn("function_id"));
				if (function != nullptr && function->getFunction()->isMethod()) {
					vtable->addMethod((Function::Method*)function->getFunction());
				}
			}
		}

		void addVTable(Function::VTable* vtable) {
			m_vtables.insert(std::make_pair(vtable->getId(), vtable));
		}

		inline Function::VTable* getVTableById(int vtable_id) {
			if (m_vtables.find(vtable_id) == m_vtables.end())
				return nullptr;
			return m_vtables[vtable_id];
		}
	private:
		VTableDict m_vtables;
	};
};