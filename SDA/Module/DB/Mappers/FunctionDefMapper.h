#pragma once
#include <Code/Function/FunctionDefinition.h>
#include <Code/Function/Method.h>

namespace DB
{
	class FunctionDefMapper : public AbstractMapper
	{
	public:
		FunctionDefMapper(Database* db, IRepository* repository)
			: AbstractMapper(db, repository)
		{}

		void loadAll() {
			Statement query(*m_db, "SELECT * FROM sda_func_defs");
			load(query);
		}

	protected:
		DomainObject* doLoad(SQLite::Statement& query) override {
			using namespace CE;

			int def_id = query.getColumn("def_id");
			int def_offset = query.getColumn("offset");
			int decl_id = query.getColumn("decl_id");

			auto decl = getFunctionDeclById(decl_id);
			if (decl == nullptr)
				return nullptr;

			auto definition =
				new Function::FunctionDefinition(
					getProgramModule()->toAbsAddr(def_offset),
					Function::AddressRangeList(),
					def_id,
					decl->getFunctionDecl()
				);

			auto function =
				decl->getFunctionDecl()->isFunction() ? new Function::Function(definition) : new Function::Method(definition);

			//addFunction(new API::Function::Function(this, function, decl));
			loadFunctionRanges(function->getDefinition());
			return definition;
		}

		void loadFunctionRanges(CE::Function::FunctionDefinition& definition) {
			using namespace CE;

			SQLite::Statement query(*m_db, "SELECT * FROM sda_func_ranges WHERE def_id=?1 GROUP BY order_id");
			query.bind(1, definition.getId());

			while (query.executeStep())
			{
				definition.addRange(Function::AddressRange(
					getProgramModule()->toAbsAddr(query.getColumn("min_offset")),
					getProgramModule()->toAbsAddr(query.getColumn("max_offset"))
				));
			}
		}

		void saveFunctionRanges(CE::Function::FunctionDefinition& definition) {
			using namespace CE;

			{
				SQLite::Statement query(*m_db, "DELETE FROM sda_func_ranges WHERE def_id=?1");
				query.bind(1, definition.getId());
				query.exec();
			}

			{
				int order_id = 0;
				for (auto& range : definition.getRangeList()) {
					SQLite::Statement query(*m_db, "INSERT INTO sda_func_ranges (def_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
					query.bind(1, definition.getId());
					query.bind(2, order_id);
					query.bind(3, getProgramModule()->toRelAddr(range.getMinAddress()));
					query.bind(4, getProgramModule()->toRelAddr(range.getMaxAddress()));
					query.exec();
					order_id++;
				}
			}
		}

		/*void FunctionManager::saveFunctionNodeGroup(Function::FunctionDefinition& definition, CallGraph::Unit::NodeGroup* nodeGroup, int& id) {
			using namespace SQLite;
			using namespace CallGraph;

			SQLite::Database& db = getProgramModule()->getDB();
			bool goToParent = false;

			for (auto node : nodeGroup->getNodeList())
			{
				{
					SQLite::Statement query(db, "INSERT INTO sda_callnodes (def_id, id, item_group, item_id, extra) VALUES (?1, ?2, ?3, ?4, ?5)");
					query.bind(1, definition.getId());
					query.bind(2, id++);
					query.bind(3, (int)node->getGroup());

					int extra = 0;
					int item_id = 0;
					BitStream bs((BYTE*)&extra, sizeof(int));

					if (goToParent) {
						bs.writeBit(1);
						goToParent = false;
					}
					else {
						bs.writeBit(0);
					}

					switch (node->getGroup())
					{
					case Unit::Type::Function:
					{
						auto funcNode = static_cast<Unit::FunctionNode*>(node);
						item_id = funcNode->getFunction()->getFunction()->getId();
						bs.write(getProgramModule()->toRelAddr(funcNode->getAddressLocation()));
						break;
					}
					case Unit::Type::GlobalVar:
					{
						auto gvarNode = static_cast<Unit::GlobalVarNode*>(node);
						item_id = gvarNode->getGVar()->getId();
						bs.writeBit(gvarNode->getUse());
						bs.write(getProgramModule()->toRelAddr(gvarNode->getAddressLocation()));
						break;
					}
					case Unit::Type::NodeGroup:
						break;
					case Unit::Type::Cycle:
						break;
					case Unit::Type::Condition:
						break;
					case Unit::Type::FunctionBody:
						break;
					}

					query.bind(4, item_id);
					query.bind(5, bs.getData(), bs.getSize());
				}

				if (nodeGroup->getGroup() >= Unit::Type::NodeGroup) {
					goToParent = true;
					saveFunctionNodeGroup(definition, nodeGroup, id);
				}
			}
		}

		void saveFunctionBody(API::Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_callnodes WHERE def_id=?1");
				query.bind(1, function->getDefinition().getId());
				query.exec();
			}

			int id = 0;
			saveFunctionNodeGroup(function->getDefinition(), function->getBody(), id);
			transaction.commit();
		}

		void loadFunctionBody(API::Function::Function* function) {
			using namespace CE;
			using namespace CallGraph;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_callnodes WHERE def_id=?1 GROUP BY id");
			query.bind(1, function->getDefinition().getId());

			auto body = function->getBody();

			Unit::NodeGroup* nodeGroup = body;
			while (query.executeStep())
			{
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
		}*/

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