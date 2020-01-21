#pragma once
#include <GhidraSync/FunctionManager.h>
#include "FunctionManager.h"
#include <CallGraph/CallGraph.h>

using namespace CE;

FunctionManager::FunctionManager(ProgramModule* module)
	: AbstractManager(module)
{
	createDefaultFunction();
}

void FunctionManager::saveFunctionNodeGroup(Function::Function* function, CallGraph::Unit::NodeGroup* nodeGroup, int& id) {
	using namespace SQLite;
	using namespace CallGraph;

	SQLite::Database& db = getProgramModule()->getDB();
	bool goToParent = false;

	for (auto node : nodeGroup->getNodeList())
	{
		{
			SQLite::Statement query(db, "INSERT INTO sda_callnodes (function_id, id, item_group, item_id, extra) VALUES (?1, ?2, ?3, ?4, ?5)");
			query.bind(1, function->getId());
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
			saveFunctionNodeGroup(function, nodeGroup, id);
		}
	}
}

void FunctionManager::saveFunctionBody(API::Function::Function* function) {
	using namespace SQLite;

	SQLite::Database& db = getProgramModule()->getDB();
	SQLite::Transaction transaction(db);

	{
		SQLite::Statement query(db, "DELETE FROM sda_callnodes WHERE function_id=?1");
		query.bind(1, function->getFunction()->getId());
		query.exec();
	}

	int id = 0;
	saveFunctionNodeGroup(function->getFunction(), function->getBody(), id);
	transaction.commit();
}

void FunctionManager::loadFunctionBody(API::Function::Function* function) {
	using namespace SQLite;
	using namespace CallGraph;

	SQLite::Database& db = getProgramModule()->getDB();
	SQLite::Statement query(db, "SELECT * FROM sda_callnodes WHERE function_id=?1 GROUP BY id");
	query.bind(1, function->getFunction()->getId());

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
}

void CE::FunctionManager::buildFunctionBodies() {
	for (auto it : m_functions) {
		CallGraph::FunctionBodyBuilder bodyBuilder(it.second);
		bodyBuilder.build();
		it.second->setBody(bodyBuilder.getFunctionBody());
	}
}

void API::Function::Function::save() {
	lock();

	getFunctionManager()->saveFunction(getFunction());
	if (getFunctionManager()->isGhidraManagerWorking()) {
		getFunctionManager()->getGhidraManager()->push({
			getFunctionManager()->getGhidraManager()->buildDesc(getFunction())
			});
	}

	unlock();
}

CallGraph::Unit::FunctionBody* CE::API::Function::Function::getBody() {
	if (m_funcBody == nullptr) {
		m_funcBody = new CallGraph::Unit::FunctionBody(this);
	}
	return m_funcBody;
}