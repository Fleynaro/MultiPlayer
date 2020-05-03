#pragma once
#include "AbstractManager.h"
#include "TypeManager.h"

namespace CE
{
	class GVarManager : public AbstractManager
	{
	public:
		using GVarDict = std::map<int, Variable::Global*>;

		GVarManager(ProgramModule* sda)
			: AbstractManager(sda)
		{}

		void saveGVar(Variable::Global* gVar) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_gvars (id, name, offset, type_id, pointer_lvl, array_size, desc) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)");
			query.bind(1, gVar->getId());
			query.bind(2, gVar->getName());
			query.bind(3, getProgramModule()->toRelAddr(gVar->getAddress()));
			query.bind(4, gVar->getType()->getId());
			query.bind(5, gVar->getType()->getPointerLvl());
			query.bind(6, gVar->getType()->getArraySize());
			query.bind(7, gVar->getDesc());
			query.exec();
		}

		void removeGVar(Variable::Global* gVar) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_gvars WHERE id=?1");
			query.bind(1, gVar->getId());
			query.exec();

			auto it = m_gvars.find(gVar->getId());
			if (it != m_gvars.end()) {
				m_gvars.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_gvars.find(id) != m_gvars.end())
				id++;
			return id;
		}

		Variable::Global* createGVar(DataType::Type* type, void* addr, std::string name, std::string desc = "") {
			int id = getNewId();
			auto gvar = new Variable::Global(type, addr, id, name, desc);
			m_gvars[id] = gvar;
			return gvar;
		}

		void loadGVars() {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_gvars");

			while (query.executeStep())
			{
				DataType::Type* type = getProgramModule()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getProgramModule()->getTypeManager()->getDefaultType();
				}

				Variable::Global* gvar = new Variable::Global(
					type,
					getProgramModule()->toAbsAddr(query.getColumn("offset")),
					query.getColumn("id"),
					query.getColumn("name"),
					query.getColumn("desc")
				);

				addGVar(gvar);
			}
		}

		void addGVar(Variable::Global* gvar) {
			m_gvars.insert(std::make_pair(gvar->getId(), gvar));
		}

		inline Variable::Global* getGVarById(int id) {
			return m_gvars[id];
		}
	private:
		GVarDict m_gvars;
	};
};