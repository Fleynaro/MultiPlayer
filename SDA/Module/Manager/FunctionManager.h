#pragma once
#include "AbstractManager.h"
#include <Code/Function/Method.h>
#include <CallGraph/CallGraph.h>

namespace CE
{
	class FunctionManager : public IManager
	{
	public:
		using FunctionDict = std::map<int, Function::Function*>;

		FunctionManager(SDA* sda)
			: IManager(sda)
		{
			createDefaultFunction();
		}

		Function::Function* getDefaultFunction() {
			return m_defFunction;
		}
	private:
		Function::Function* m_defFunction = nullptr;
		void createDefaultFunction() {
			m_defFunction = createFunction(nullptr, {}, "DefaultFunction", "This function created automatically.");
		}


		void saveFunctionNodeGroup(Function::Function* function, CallGraph::NodeGroup* nodeGroup, int& id) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
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
					BitStream bs((BYTE*)& extra, sizeof(int));

					if (goToParent) {
						bs.writeBit(1);
						goToParent = false;
					}
					else {
						bs.writeBit(0);
					}

					switch (node->getGroup())
					{
					case CallGraph::Type::Function:
						item_id = ((CallGraph::FunctionNode*)node)->getFunction()->getId();
						break;
					case CallGraph::Type::GlobalVar:
					{
						auto gvarNode = (CallGraph::GlobalVarNode*)node;
						item_id = gvarNode->getGVar()->getId();
						bs.writeBit(gvarNode->getUse());
						break;
					}
					case CallGraph::Type::NodeGroup:
						break;
					case CallGraph::Type::Cycle:
						break;
					case CallGraph::Type::Condition:
						break;
					case CallGraph::Type::FunctionBody:
						break;
					}

					query.bind(4, item_id);
					query.bind(5, extra);
				}

				if (nodeGroup->getGroup() >= CallGraph::Type::NodeGroup) {
					goToParent = true;
					saveFunctionNodeGroup(function, nodeGroup, id);
				}
			}
		}
	public:
		void saveFunctionBody(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_callnodes WHERE function_id=?1");
				query.bind(1, function->getId());
				query.exec();
			}

			int id = 0;
			saveFunctionNodeGroup(function, function->getBody(), id);
			transaction.commit();
		}

		void saveFunctionArguments(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_arguments WHERE function_id=?1");
				query.bind(1, function->getId());
				query.exec();
			}

			{
				int id = 0;
				for (auto type : function->getSignature().getArgList()) {
					SQLite::Statement query(db, "INSERT INTO sda_func_arguments (function_id, id, name, type_id, pointer_lvl, array_size) \
					VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
					query.bind(1, function->getId());
					query.bind(2, id);
					query.bind(3, function->getArgNameList()[id]);
					query.bind(4, type->getId());
					query.bind(5, type->getPointerLvl());
					query.bind(6, type->getArraySize());
					query.exec();
					id++;
				}
			}

			transaction.commit();
		}

		void saveFunctionRanges(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_ranges WHERE function_id=?1");
				query.bind(1, function->getId());
				query.exec();
			}

			{
				int order_id = 0;
				for (auto& range : function->getRangeList()) {
					SQLite::Statement query(db, "INSERT INTO sda_func_ranges (function_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
					query.bind(1, function->getId());
					query.bind(2, order_id);
					query.bind(3, getSDA()->toRelAddr(range.getMinAddress()));
					query.bind(4, getSDA()->toRelAddr(range.getMaxAddress()));
					query.exec();
					order_id++;
				}
			}

			transaction.commit();
		}

		void saveFunction(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_functions (id, name, method, offset, ret_type_id, ret_pointer_lvl, ret_array_size, desc)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
			query.bind(1, function->getId());
			query.bind(2, function->getName());
			query.bind(3, function->isMethod());
			query.bind(4, getSDA()->toRelAddr(function->getAddress()));
			query.bind(5, function->getSignature().getReturnType()->getId());
			query.bind(6, function->getSignature().getReturnType()->getPointerLvl());
			query.bind(7, function->getSignature().getReturnType()->getArraySize());
			query.bind(8, function->getDesc());
			query.exec();
		}

		void saveFunctions() {
			for (auto it : m_functions) {
				auto func = it.second;
				saveFunction(func);
				saveFunctionRanges(func);
				if (func->m_argumentsChanged) {
					saveFunctionArguments(func);
				}
			}
		}

		void removeFunction(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_functions WHERE id=?1");
			query.bind(1, function->getId());
			query.exec();

			auto it = m_functions.find(function->getId());
			if (it != m_functions.end()) {
				m_functions.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_functions.find(id) != m_functions.end())
				id++;
			return id;
		}

		Function::Function* createFunction(void* addr, Function::Function::RangeList ranges, std::string name, std::string desc = "") {
			int id = getNewId();
			auto func = new Function::Function(addr, ranges, id, name, desc);
			m_functions[id] = func;
			func->getSignature().setReturnType(getSDA()->getTypeManager()->getTypeById(Type::SystemType::Void));
			return func;
		}

		Function::Function* createFunction(Function::Function::RangeList ranges, std::string name, std::string desc = "") {
			return createFunction(ranges[0].getMinAddress(), ranges, name, desc);
		}

		Function::Method* createMethod(Type::Class* Class, void* addr, Function::Function::RangeList size, std::string name, std::string desc = "") {
			int id = getNewId();
			auto method = new Function::Method(addr, size, id, name, desc);
			m_functions[id] = method;
			method->getSignature().setReturnType(getSDA()->getTypeManager()->getTypeById(Type::SystemType::Void));
			Class->addMethod(method);
			return method;
		}

		void loadFunctions() {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_functions");

			while (query.executeStep())
			{
				Function::Function* function;
				if ((int)query.getColumn("method") == 0) {
					function = new Function::Function(
						getSDA()->toAbsAddr(query.getColumn("offset")),
						Function::Function::RangeList(),
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
				}
				else {
					function = new Function::Method(
						getSDA()->toAbsAddr(query.getColumn("offset")),
						Function::Function::RangeList(),
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
				}

				Type::Type* type = getSDA()->getTypeManager()->getType(
					query.getColumn("ret_type_id"),
					query.getColumn("ret_pointer_lvl"),
					query.getColumn("ret_array_size")
				);
				if (type == nullptr) {
					type = getSDA()->getTypeManager()->getTypeById(Type::SystemType::Void);
				}
				function->getSignature().setReturnType(type);

				loadFunctionRanges(function);
				loadFunctionArguments(function);
				addFunction(function);
				function->m_argumentsChanged = false;
			}
		}

		void loadFunctionRanges(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_ranges WHERE function_id=?1 GROUP BY order_id");
			query.bind(1, function->getId());

			while (query.executeStep())
			{
				function->addRange(Function::Function::Range(
					getSDA()->toAbsAddr(query.getColumn("min_offset")),
					getSDA()->toAbsAddr(query.getColumn("max_offset"))
				));
			}
		}

		void loadFunctionArguments(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_arguments WHERE function_id=?1 GROUP BY id");
			query.bind(1, function->getId());

			while (query.executeStep())
			{
				Type::Type* type = getSDA()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getSDA()->getTypeManager()->getTypeById(Type::SystemType::Byte);
				}

				function->addArgument(type, query.getColumn("name"));
			}
		}

		void loadFunctionBody(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_callnodes WHERE function_id=?1 GROUP BY id");
			query.bind(1, function->getId());

			CallGraph::FunctionBody* body = new CallGraph::FunctionBody;
			function->setBody(body);

			CallGraph::NodeGroup* nodeGroup = body;
			while (query.executeStep())
			{
				BitStream bs;
				bool goToParentNode = false;
				{
					int extra = query.getColumn("extra");
					bs.setData((BYTE*)& extra, sizeof(extra));
					goToParentNode = bs.readBit();
				}
				CallGraph::Node* node = nullptr;

				switch ((CallGraph::Type)(int)query.getColumn("item_group"))
				{
				case CallGraph::Type::Function:
				{
					Function::Function* function = getSDA()->getFunctionManager()->getFunctionById(query.getColumn("item_id"));
					if (function != nullptr) {
						node = new CallGraph::FunctionNode(function);
					}
					break;
				}

				case CallGraph::Type::GlobalVar:
				{
					Variable::Global* gvar = getSDA()->getGVarManager()->getGVarById(query.getColumn("item_id"));
					if (gvar != nullptr) {
						node = new CallGraph::GlobalVarNode(gvar, (CallGraph::GlobalVarNode::Use)bs.readBit());
					}
					break;
				}

				case CallGraph::Type::NodeGroup:
					node = new CallGraph::NodeGroup;
					break;
				case CallGraph::Type::Cycle:
					node = new CallGraph::Cycle;
					break;
				case CallGraph::Type::Condition:
					node = new CallGraph::Condition;
					break;
				case CallGraph::Type::FunctionBody:
					node = new CallGraph::FunctionBody;
					break;
				}

				if (node != nullptr) {
					if (goToParentNode) {
						nodeGroup = nodeGroup->getParent();
					}
					nodeGroup->addNode(node);
					if (node->getGroup() >= CallGraph::Type::NodeGroup) {
						nodeGroup = (CallGraph::NodeGroup*)node;
					}
				}
			}
		}

		void loadFunctionBodies() {
			for (auto it : m_functions) {
				loadFunctionBody(it.second);
			}
		}

		FunctionDict& getFunctions() {
			return m_functions;
		}

		void addFunction(Function::Function* function) {
			m_functions.insert(std::make_pair(function->getId(), function));
		}

		inline Function::Function* getFunctionById(int id) {
			if (m_functions.find(id) == m_functions.end())
				return nullptr;
			return m_functions[id];
		}

		int getFunctionOffset(Function::Function* function) {
			return getSDA()->toRelAddr(function->getAddress());
		}
	private:
		FunctionDict m_functions;
	};
};