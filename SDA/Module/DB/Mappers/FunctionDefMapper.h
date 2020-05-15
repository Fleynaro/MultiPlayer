#pragma once
#include <Code/Function/FunctionDefinition.h>

namespace CE {
	class FunctionManager;
};

namespace DB
{
	class FunctionDefMapper : public AbstractMapper
	{
	public:
		FunctionDefMapper(CE::FunctionManager* repository);

		void loadAll();

		Id getNextId() override;

		CE::FunctionManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void loadFunctionRanges(Database* db, CE::Function::FunctionDefinition& definition);

		void saveFunctionRanges(TransactionContext* ctx, CE::Function::FunctionDefinition& definition);

		/*void FunctionManager::saveFunctionNodeGroup(Function::FunctionDefinition& definition, CodeGraph::Unit::NodeGroup* nodeGroup, int& id) {
			using namespace SQLite;
			using namespace CodeGraph;

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
			using namespace CodeGraph;

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

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Function::FunctionDefinition& def);
	};
};