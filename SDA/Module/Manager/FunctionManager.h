#pragma once
#include "AbstractManager.h"
#include "GVarManager.h"
#include <Code/Function/Method.h>
#include <CallGraph/CallGraph.h>
#include <Utils/BitStream.h>
#include <Disassembler/Disassembler.h>

namespace CE
{
	namespace Ghidra
	{
		class FunctionManager;
	};

	namespace API::Function
	{
		class AbstractFunction : public ItemDB
		{
		public:
			AbstractFunction(FunctionManager* funcManager)
				: m_funcManager(funcManager)
			{}

			FunctionManager* getFunctionManager() {
				return m_funcManager;
			}
		private:
			FunctionManager* m_funcManager;
		};

		class Function : public AbstractFunction
		{
		public:
			Function(FunctionManager* funcManager, CE::Function::Function* function)
				: AbstractFunction(funcManager), m_function(function)
			{}

			void save() override;

			CE::Function::Function* getFunction() {
				return m_function;
			}
		private:
			CE::Function::Function* m_function;
		};

		class Method : public Function
		{
		public:
			Method(FunctionManager* funcManager, CE::Function::Method* method)
				: Function(funcManager, method)
			{}

			CE::Function::Method* getMethod() {
				return static_cast<CE::Function::Method*>(getFunction());
			}
		};
	};

	class FunctionManager : public AbstractManager
	{
	public:
		using FunctionDict = std::map<int, API::Function::Function*>;

		FunctionManager(ProgramModule* module);

		API::Function::Function* getDefaultFunction() {
			return m_defFunction;
		}
	private:
		API::Function::Function* m_defFunction = nullptr;
		void createDefaultFunction() {
			m_defFunction = createFunction(nullptr, {}, "DefaultFunction", "This function created automatically.");
			getFunctions().erase(m_defFunction->getFunction()->getId());
		}


		void saveFunctionNodeGroup(Function::Function* function, CallGraph::NodeGroup* nodeGroup, int& id) {
			using namespace SQLite;

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
					{
						auto funcNode = static_cast<CallGraph::FunctionNode*>(node);
						item_id = funcNode->getFunction()->getId();
						bs.write(getProgramModule()->toRelAddr(funcNode->getAddressLocation()));
						break;
					}
					case CallGraph::Type::GlobalVar:
					{
						auto gvarNode = static_cast<CallGraph::GlobalVarNode*>(node);
						item_id = gvarNode->getGVar()->getId();
						bs.writeBit(gvarNode->getUse());
						bs.write(getProgramModule()->toRelAddr(gvarNode->getAddressLocation()));
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
					query.bind(5, bs.getData(), bs.getSize());
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

			SQLite::Database& db = getProgramModule()->getDB();
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

			SQLite::Database& db = getProgramModule()->getDB();
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

			SQLite::Database& db = getProgramModule()->getDB();
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
					query.bind(3, getProgramModule()->toRelAddr(range.getMinAddress()));
					query.bind(4, getProgramModule()->toRelAddr(range.getMaxAddress()));
					query.exec();
					order_id++;
				}
			}

			transaction.commit();
		}

		void saveFunction(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_functions (id, name, method, offset, ret_type_id, ret_pointer_lvl, ret_array_size, desc)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
			query.bind(1, function->getId());
			query.bind(2, function->getName());
			query.bind(3, function->isMethod());
			query.bind(4, getProgramModule()->toRelAddr(function->getAddress()));
			query.bind(5, function->getSignature().getReturnType()->getId());
			query.bind(6, function->getSignature().getReturnType()->getPointerLvl());
			query.bind(7, function->getSignature().getReturnType()->getArraySize());
			query.bind(8, function->getDesc());
			query.exec();
		}

		void saveFunctions() {
			for (auto it : m_functions) {
				auto func = it.second->getFunction();
				saveFunction(func);
				saveFunctionRanges(func);
				if (func->m_argumentsChanged) {
					saveFunctionArguments(func);
				}
			}
		}

		void removeFunction(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
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

		API::Function::Function* createFunction(void* addr, Function::Function::RangeList ranges, std::string name, std::string desc = "") {
			int id = getNewId();
			auto func = m_functions[id] = new API::Function::Function(this, new Function::Function(addr, ranges, id, name, desc));
			func->getFunction()->getSignature().setReturnType(getProgramModule()->getTypeManager()->getDefaultReturnType()->getType());
			return m_functions[id];
		}

		API::Function::Function* createFunction(Function::Function::RangeList ranges, std::string name, std::string desc = "") {
			return createFunction(ranges[0].getMinAddress(), ranges, name, desc);
		}

		API::Function::Method* createMethod(Type::Class* Class, void* addr, Function::Function::RangeList size, std::string name, std::string desc = "") {
			int id = getNewId();
			auto method = new API::Function::Method(this, new Function::Method(addr, size, id, name, desc));
			m_functions[id] = method;
			method->getFunction()->getSignature().setReturnType(getProgramModule()->getTypeManager()->getDefaultReturnType()->getType());
			Class->addMethod(method->getMethod());
			return method;
		}

		void loadFunctions() {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_functions");

			while (query.executeStep())
			{
				Function::Function* function;
				if ((int)query.getColumn("method") == 0) {
					function = new Function::Function(
						getProgramModule()->toAbsAddr(query.getColumn("offset")),
						Function::Function::RangeList(),
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					addFunction(new API::Function::Function(this, function));
				}
				else {
					function = new Function::Method(
						getProgramModule()->toAbsAddr(query.getColumn("offset")),
						Function::Function::RangeList(),
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					addFunction(new API::Function::Method(this, static_cast<Function::Method*>(function)));
				}

				Type::Type* type = getProgramModule()->getTypeManager()->getType(
					query.getColumn("ret_type_id"),
					query.getColumn("ret_pointer_lvl"),
					query.getColumn("ret_array_size")
				);
				if (type == nullptr) {
					type = getProgramModule()->getTypeManager()->getDefaultReturnType()->getType();
				}
				function->getSignature().setReturnType(type);

				loadFunctionRanges(function);
				loadFunctionArguments(function);
				function->m_argumentsChanged = false;
			}
		}

		void loadFunctionRanges(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_ranges WHERE function_id=?1 GROUP BY order_id");
			query.bind(1, function->getId());

			while (query.executeStep())
			{
				function->addRange(Function::Function::Range(
					getProgramModule()->toAbsAddr(query.getColumn("min_offset")),
					getProgramModule()->toAbsAddr(query.getColumn("max_offset"))
				));
			}
		}

		void loadFunctionArguments(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_arguments WHERE function_id=?1 GROUP BY id");
			query.bind(1, function->getId());

			while (query.executeStep())
			{
				Type::Type* type = getProgramModule()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getProgramModule()->getTypeManager()->getDefaultType()->getType();
				}

				function->addArgument(type, query.getColumn("name"));
			}
		}

		void loadFunctionBody(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
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
					bs.write(query.getColumn("extra").getBlob(), query.getColumn("extra").getBytes());
					bs.resetPointer();
					goToParentNode = bs.readBit();
				}
				CallGraph::Node* node = nullptr;

				switch ((CallGraph::Type)(int)query.getColumn("item_group"))
				{
				case CallGraph::Type::Function:
				{
					Function::Function* function = getProgramModule()->getFunctionManager()->getFunctionById(query.getColumn("item_id"))->getFunction();
					if (function != nullptr) {
						node = new CallGraph::FunctionNode(function, getProgramModule()->toAbsAddr(bs.read<int>()));
					}
					break;
				}

				case CallGraph::Type::GlobalVar:
				{
					Variable::Global* gvar = getProgramModule()->getGVarManager()->getGVarById(query.getColumn("item_id"));
					if (gvar != nullptr) {
						node = new CallGraph::GlobalVarNode(gvar, (CallGraph::GlobalVarNode::Use)bs.readBit(), getProgramModule()->toAbsAddr(bs.read<int>()));
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
						nodeGroup = static_cast<CallGraph::NodeGroup*>(node);
					}
				}
			}
		}

		void loadFunctionBodies() {
			for (auto it : m_functions) {
				loadFunctionBody(it.second->getFunction());
			}
		}

		void buildFunctionBodies();

		API::Function::Function* getFunctionAt(void* addr) {
			for (auto& it : getFunctions()) {
				if (it.second->getFunction()->isContainingAddress(addr)) {
					return it.second;
				}
			}
			return nullptr;
		}

		FunctionDict& getFunctions() {
			return m_functions;
		}

		void addFunction(API::Function::Function* function) {
			m_functions.insert(std::make_pair(function->getFunction()->getId(), function));
		}

		inline API::Function::Function* getFunctionById(int id) {
			if (m_functions.find(id) == m_functions.end())
				return nullptr;
			return m_functions[id];
		}

		int getFunctionOffset(Function::Function* function) {
			return getProgramModule()->toRelAddr(function->getAddress());
		}

		void setGhidraManager(Ghidra::FunctionManager* ghidraManager) {
			m_ghidraManager = ghidraManager;
		}

		Ghidra::FunctionManager* getGhidraManager() {
			return m_ghidraManager;
		}

		bool isGhidraManagerWorking() {
			return getGhidraManager() != nullptr;
		}
	private:
		FunctionDict m_functions;
		Ghidra::FunctionManager* m_ghidraManager;
	};

	namespace CallGraph
	{
		class FunctionBodyBuilder
		{
		public:
			FunctionBodyBuilder(API::Function::Function* function)
				: m_function(function)
			{}

			void build()
			{
				m_funcBody = new FunctionBody;
				for (auto& range : m_function->getFunction()->getRangeList()) {
					build(range);
				}
			}

			FunctionBody* getFunctionBody() {
				return m_funcBody;
			}
		private:
			FunctionBody* m_funcBody = nullptr;
			API::Function::Function* m_function;

			void build(Function::Function::Range& range)
			{
				using namespace CE::Disassembler;
				auto nodeGroup = getFunctionBody();

				Decoder decoder(range.getMinAddress(), range.getSize());
				decoder.decode([&](Code::Instruction& instruction)
				{
					void* curAddr = (void*)decoder.getCurrentAddress();

					if (instruction.isGeneric()) {
						auto& instr = (Code::Instructions::Generic&)instruction;
						auto addr = instr.getAbsoluteAddr();
						if (addr != nullptr) {
							nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Read, curAddr));
						}
					}
					else if (instruction.isBasicManipulating()) {
						auto& instr = (Code::Instructions::BasicManipulation&)instruction;
						if (instr.getOperand(0).isCalculatedAddress()) {
							nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Write, curAddr));
						}
						else if (instr.getOperand(1).isCalculatedAddress()) {
							nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Read, curAddr));
						}
					} 
					else if (instruction.isJumping()) {
						auto& instr = (Code::Instructions::JumpInstruction&)instruction;
						if (instr.hasAbsoluteAddr()) {
							auto calledFunc = m_function->getFunctionManager()->getFunctionAt(instr.getAbsoluteAddr());
							
							if (instruction.getMnemonicId() != ZYDIS_MNEMONIC_CALL) {
								if (calledFunc != nullptr) {
									if (calledFunc->getFunction() == m_function->getFunction()) {
										calledFunc = nullptr;
									}
								}
							}
							else {
								if (calledFunc == nullptr) {
									nodeGroup->addNode(new FunctionNode(curAddr));
								}
							}

							if (calledFunc != nullptr) {
								nodeGroup->addNode(new FunctionNode(calledFunc->getFunction(), curAddr));
							}
						}
						else if (instruction.getMnemonicId() == ZYDIS_MNEMONIC_CALL) {
							nodeGroup->addNode(new FunctionNode(curAddr));
						}
					}

					return true;
				});
			}
		};
	};
};