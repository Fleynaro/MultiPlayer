#pragma once
#include <CallGraph/CallGraph.h>
#include <DB/DomainObject.h>
#include <DB/AbstractMapper.h>

namespace DB
{
	class FunctionBodyMapper : public AbstractMapper
	{
	public:
		FunctionBodyMapper(Database* db)
			: AbstractMapper(db)
		{}
	protected:
		DomainObject* doLoad(SQLite::Statement& query) override {
			BitStream bs;
			bool goToParentNode = false;
			{
				bs.write(query.getColumn("extra").getBlob(), query.getColumn("extra").getBytes());
				bs.resetPointer();
				goToParentNode = bs.readBit();
			}
			Unit::Node* node = nullptr;

			switch ((Unit::Type)(int)query.getColumn("item_group"))
			{
			case Unit::Type::Function:
			{
				auto function = getProgramModule()->getFunctionManager()->getFunctionById(query.getColumn("item_id"));
				if (function != nullptr) {
					node = new Unit::FunctionNode(function, getProgramModule()->toAbsAddr(bs.read<int>()));
				}
				break;
			}

			case Unit::Type::GlobalVar:
			{
				Variable::Global* gvar = getProgramModule()->getGVarManager()->getGVarById(query.getColumn("item_id"));
				if (gvar != nullptr) {
					node = new Unit::GlobalVarNode(gvar, (Unit::GlobalVarNode::Use)bs.readBit(), getProgramModule()->toAbsAddr(bs.read<int>()));
				}
				break;
			}

			case Unit::Type::NodeGroup:
				node = new Unit::NodeGroup;
				break;
			case Unit::Type::Cycle:
				node = new Unit::Cycle;
				break;
			case Unit::Type::Condition:
				node = new Unit::Condition;
				break;
			}

			if (node != nullptr) {
				if (goToParentNode) {
					nodeGroup = nodeGroup->getParent();
				}
				nodeGroup->addNode(node);
				if (node->getGroup() >= Unit::Type::NodeGroup) {
					nodeGroup = static_cast<Unit::NodeGroup*>(node);
				}
			}
		}

		void doInsert(DomainObject* obj) override {
			auto def = *(CE::Function::FunctionDefinition*)obj;

			SQLite::Statement query(*m_db, "INSERT INTO sda_func_defs (decl_id, offset)\
				VALUES(?2, ?3)");
			bind(query, def);
			query.exec();
			setNewId(obj);
		}

		void doUpdate(DomainObject* obj) override {
			auto def = *(CE::Function::FunctionDefinition*)obj;

			SQLite::Statement query(*m_db, "REPLACE INTO sda_func_defs (def_id, decl_id, offset)\
				VALUES(?1, ?2, ?3)");
			query.bind(1, def.getId());
			bind(query, def);
			query.exec();
		}

		void doRemove(DomainObject* obj) override {
			SQLite::Statement query(*m_db, "DELETE FROM sda_func_defs WHERE def_id=?1");
			query.bind(1, obj->getId());
			query.exec();
		}

	private:
		void bind(SQLite::Statement& query, CE::Function::FunctionDefinition& def) {
			query.bind(2, def.getDeclaration().getId());
			query.bind(3, getProgramModule()->toRelAddr(def.getAddress()));
		}
	};
};