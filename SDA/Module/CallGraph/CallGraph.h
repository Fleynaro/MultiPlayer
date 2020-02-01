#pragma once
#include <Manager/FunctionManager.h>
#include <Disassembler/Disassembler.h>

namespace CE
{
	namespace CallGraph
	{
		namespace Unit
		{
			enum class Type
			{
				Function = 1,
				VMethod,
				GlobalVar,
				NodeGroup = 11,
				Cycle,
				Condition,
				FunctionBody
			};

			class NodeGroup;
			class Node
			{
			public:
				Node() = default;

				virtual Type getGroup() = 0;

				bool isGroup() {
					return getGroup() > Type::GlobalVar;
				}

				bool isFunction() {
					return getGroup() == Type::Function;
				}

				bool isVMethod() {
					return getGroup() == Type::VMethod;
				}

				bool isGlobalVar() {
					return getGroup() == Type::GlobalVar;
				}

				bool isFunctionBody() {
					return getGroup() == Type::FunctionBody;
				}

				NodeGroup* getParent() {
					return m_parent;
				}

				void setParent(NodeGroup* parent) {
					m_parent = parent;
				}
			private:
				NodeGroup* m_parent = nullptr;
			};

			class NodeGroup : public Node
			{
			public:
				using nodeList = std::vector<Node*>;
				NodeGroup() = default;

				Type getGroup() override {
					return Type::NodeGroup;
				}

				nodeList& getNodeList() {
					return m_nodes;
				}

				NodeGroup* getFunctionBody() {
					//throw ex
					if (getGroup() == Type::FunctionBody) {
						return this;
					}
					return getParent();
				}

				void addNode(Node* node);
			private:
				nodeList m_nodes;
			};

			class AbstractNode : public Node
			{
			public:
				AbstractNode(void* addr)
					: m_addr(addr)
				{}

				void* getAddressLocation() {
					return m_addr;
				}
			private:
				void* m_addr;
			};

			class FunctionNode : public AbstractNode
			{
			public:
				FunctionNode(API::Function::Function* function, void* addr)
					: m_function(function), AbstractNode(addr)
				{}

				FunctionNode(void* addr)
					: AbstractNode(addr)
				{}

				Type getGroup() override {
					return Type::Function;
				}

				bool isNotCalculated() {
					return getFunction() == nullptr;
				}

				API::Function::Function* getFunction() {
					return m_function;
				}
			private:
				API::Function::Function* m_function = nullptr;
			};

			class VMethodNode : public AbstractNode
			{
			public:
				VMethodNode(Function::MethodDecl* decl, void* addr)
					: m_decl(decl), AbstractNode(addr)
				{}

				VMethodNode(void* addr)
					: AbstractNode(addr)
				{}

				Type getGroup() override {
					return Type::VMethod;
				}

				bool isNotCalculated() {
					return getDeclaration() == nullptr;
				}

				Function::MethodDecl* getDeclaration() {
					return m_decl;
				}
			private:
				Function::MethodDecl* m_decl = nullptr;
			};

			class GlobalVarNode : public AbstractNode
			{
			public:
				enum Use {
					Read,
					Write
				};

				GlobalVarNode(Variable::Global* gVar, Use use, void* addr)
					: m_gVar(gVar), m_use(use), AbstractNode(addr)
				{}

				Type getGroup() override {
					return Type::GlobalVar;
				}

				Variable::Global* getGVar() {
					return m_gVar;
				}

				Use getUse() {
					return m_use;
				}
			private:
				Variable::Global* m_gVar;
				Use m_use;
			};

			class Condition : public NodeGroup
			{
			public:
				Condition() = default;

				Type getGroup() override {
					return Type::Condition;
				}
			};

			class Cycle : public NodeGroup
			{
			public:
				Cycle() = default;

				Type getGroup() override {
					return Type::Cycle;
				}
			};

			class AbstractBody : public NodeGroup
			{
			public:
				void addReferenceTo(FunctionBody* refFuncBody) {
					m_functionsReferTo.push_back(refFuncBody);
				}

				std::list<FunctionBody*>& getFunctionsReferTo() {
					return m_functionsReferTo;
				}
			private:
				std::list<FunctionBody*> m_functionsReferTo;
			};

			class FunctionBody : public AbstractBody
			{
			public:
				FunctionBody(API::Function::Function* function)
					: m_function(function)
				{}

				bool isSourceTop() {
					return getFunctionsReferTo().size() == 0;
				}

				Type getGroup() override {
					return Type::FunctionBody;
				}

				API::Function::Function* getFunction() {
					return m_function;
				}
			private:
				API::Function::Function* m_function;
			};

			class GlobalVarBody : public AbstractBody
			{
			public:
				GlobalVarBody() = default;

				Type getGroup() override {
					return Type::GlobalVar;
				}

				//MY TODO: доделать GlobalVarBody как FunctionBody сделана
			};
		};

		class CallStack
		{
		public:
			CallStack() = default;

			void push(Unit::FunctionBody* body) {
				m_stack.push_front(body);
			}

			void pop() {
				m_stack.pop_front();
			}

			bool empty() {
				return m_stack.empty();
			}

			int size() {
				return m_stack.size();
			}

			bool has(Unit::FunctionBody* body) {
				for (auto it : m_stack) {
					if (it == body) {
						return true;
					}
				}
				return false;
			}
		private:
			std::list<Unit::FunctionBody*> m_stack;
		};

		class FunctionIterator
		{
		public:
			FunctionIterator(API::Function::Function* function)
				: m_funcBody(function->getBody())
			{}

			FunctionIterator(Unit::FunctionBody* funcBody)
				: m_funcBody(funcBody)
			{}

			template<bool isLeft = true>
			void iterateCallStack(const std::function<bool(Unit::Node*, CallStack&)>& callback)
			{
				CallStack stack;
				iterateCallStack<isLeft>(callback, m_funcBody, stack);
			}

			enum class Filter : int
			{
				FunctionNode = 1,
				GlobalVarNode = 2,
				FunctionBody = 4,
				All = -1
			};

			template<bool isLeft = true>
			void iterateCallStack(const std::function<bool(Unit::Node*, CallStack&)>& callback, Filter filter)
			{
				iterateCallStack([&](Unit::Node* node, CallStack& stack)
				{
					if ((int)filter & (int)Filter::FunctionNode && node->isFunction()
						|| (int)filter & (int)Filter::GlobalVarNode && node->isGlobalVar()
						|| (int)filter & (int)Filter::FunctionBody && node->isFunctionBody()) {
						return callback(node, stack);
					}
					return true;
				});
			}

			std::list<Unit::Node*> getAllNodesInCallTree(Filter filter)
			{
				std::list<Unit::Node*> nodes;
				iterateCallStack([&](Unit::Node* node, CallStack& stack)
				{
					nodes.push_back(node);
					return true;
				}, filter);
				return nodes;
			}
		private:
			template<bool isLeft = true>
			void iterateCallStack(const std::function<bool(Unit::Node*, CallStack&)>& callback, Unit::FunctionBody* body, CallStack& stack)
			{
				stack.push(body);

				FunctionIterator pass(body);
				pass.iterateFunctionBody<isLeft>([&](Unit::Node* node)
				{
					if (node->isFunction()) {
						auto functionNode = static_cast<Unit::FunctionNode*>(node);
						if (!functionNode->isNotCalculated()) {
							auto body = functionNode->getFunction()->getBody();
							if (!stack.has(body)) {
								iterateCallStack(callback, body, stack);
							}
						}
					}
					return callback(node, stack);
				});

				stack.pop();
			}

		public:
			template<bool isLeft = true>
			void iterateFunctionBody(const std::function<bool(Unit::Node*)>& callback)
			{
				IterateNodeGroup<isLeft>(callback, m_funcBody);
			}

			template<bool isLeft = true>
			static void IterateNodeGroup(const std::function<bool(Unit::Node*)>& callback, Unit::Node* node)
			{
				if constexpr (isLeft) {
					if (!callback(node))
						return;
				}

				if (node->isGroup()) {
					auto nodeGroup = static_cast<Unit::NodeGroup*>(node);
					for (auto node : nodeGroup->getNodeList()) {
						IterateNodeGroup(callback, node);
					}
				}
				
				if constexpr (!isLeft) {
					if (!callback(node))
						return;
				}
			}
		private:
			Unit::FunctionBody* m_funcBody;
		};

		class CallGraphIterator
		{
		public:
			CallGraphIterator(FunctionManager* funcManager)
				: m_funcManager(funcManager)
			{}

			template<bool isLeft = true>
			void iterate(const std::function<bool(Unit::Node*, CallStack&)>& callback)
			{
				m_passedFunctions.clear();
				for (auto it : m_funcManager->getFunctions())
				{
					if (it.second->getBody()->isSourceTop())
					{
						FunctionIterator pass(it.second);
						pass.iterateCallStack<isLeft>([&](Unit::Node* node, CallStack& stack)
						{
							if (node->isFunctionBody()) {
								auto funcBody = static_cast<Unit::FunctionBody*>(node);
								auto def_id = funcBody->getFunction()->getDefinition().getId();
								if (m_passedFunctions.find(def_id) == m_passedFunctions.end()) {
									m_passedFunctions.insert(def_id);
								}
								else {
									return false;
								}
							}
							return callback(node, stack);
						});
					}
				}
			}
		private:
			std::set<int> m_passedFunctions;
			FunctionManager* m_funcManager;
		};

		namespace Analyser
		{
			class Generic
			{
			public:
				Generic(API::Function::Function* function)
					: m_funcBody(function->getBody())
				{}

				Generic(Unit::FunctionBody* funcBody)
					: m_funcBody(funcBody)
				{}

				void doAnalyse() {
					FunctionIterator pass(m_funcBody);
					pass.iterateCallStack([this](Unit::Node* node, CallStack& stack)
					{
						if (node->isFunction()) {
							m_stat.funcCount++;
						}

						if (node->isVMethod()) {
							m_stat.vMethodCount++;
						}

						if (node->isGlobalVar()) {
							m_stat.gVarCount++;
							auto varNode = static_cast<Unit::GlobalVarNode*>(node);
							if (varNode->getUse() == Unit::GlobalVarNode::Write) {
								m_stat.gVarWriteCount++;
							}
						}
						return true;
					});
				}

				bool isLeaf() {
					return m_stat.funcCount == 0 && m_stat.vMethodCount == 0;
				}

				bool isReentrant() {
					return m_stat.gVarCount == 0;
				}
			private:
				Unit::FunctionBody* m_funcBody;
				struct {
					int funcCount = 0;
					int vMethodCount = 0;
					int gVarCount = 0;
					int gVarWriteCount = 0;
				} m_stat;
			};

			class CompareFunctionBodies
			{
			public:
				CompareFunctionBodies(Unit::FunctionBody* funcBody1, Unit::FunctionBody* funcBody2) {
					m_funcBody[0] = funcBody1;
					m_funcBody[1] = funcBody2;
				}

				void doAnalyse() {
					std::list<Unit::Node*> nodesInBody[2];

					for (int i = 0; i <= 1; i++) {
						FunctionIterator pass(m_funcBody[i]);
						nodesInBody[i] = pass.getAllNodesInCallTree(FunctionIterator::Filter::FunctionBody);
					}
					
					for (auto node1 : nodesInBody[0]) {
						auto funcBody1 = static_cast<Unit::FunctionBody*>(node1);
						for (auto node2 : nodesInBody[1]) {
							auto funcBody2 = static_cast<Unit::FunctionBody*>(node2);
							if (funcBody1->getFunction()->getDefinition().getId() == funcBody2->getFunction()->getDefinition().getId()) {
								m_mutualFuncBodies.push_back(funcBody1);
							}
						}
					}
				}

				const std::list<Unit::FunctionBody*>& getMutualFuncBodies() {
					return m_mutualFuncBodies;
				}
			private:
				Unit::FunctionBody* m_funcBody[2];
				std::list<Unit::FunctionBody*> m_mutualFuncBodies;
			};

			class ContextDistance
			{
			public:
				ContextDistance(Unit::FunctionBody* funcBody1, Unit::FunctionBody* funcBody2) {
					m_funcBody[0] = funcBody1;
					m_funcBody[1] = funcBody2;
				}

				void doAnalyse() {
					
				}
			private:
				Unit::FunctionBody* m_funcBody[2];
			};
		};

		class FunctionBodyBuilder
		{
		public:
			FunctionBodyBuilder(API::Function::Function* function)
				: m_function(function)
			{}

			void build()
			{
				for (auto& range : m_function->getDefinition().getRangeList()) {
					build(range);
				}
			}

			Unit::FunctionBody* getFunctionBody() {
				if (m_body == nullptr) {
					m_body = new Unit::FunctionBody(m_function);
				}
				return m_body;
			}
		private:
			API::Function::Function* m_function;
			Unit::FunctionBody* m_body = nullptr;

			void build(Function::FunctionDefinition::Range& range)
			{
				using namespace CE::Disassembler;
				using namespace Unit;
				auto nodeGroup = getFunctionBody();

				Decoder decoder(range.getMinAddress(), range.getSize());
				decoder.decode([&](Code::Instruction& instruction)
				{
					void* curAddr = (void*)decoder.getCurrentAddress();

					if (instruction.isGeneric()) {
						auto& instr = (Code::Instructions::Generic&)instruction;
						if (instr.getOperandCount() > 0) {
							auto& instr = (Code::Instructions::GenericWithOperands&)instruction;
							if (instr.getOperand(0).isCalculatedAddress()) {
								nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Write, curAddr));
							}
							else if (instr.getOperand(1).isCalculatedAddress()) {
								nodeGroup->addNode(new GlobalVarNode(nullptr, GlobalVarNode::Read, curAddr));
							}
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
								nodeGroup->addNode(new FunctionNode(calledFunc, curAddr));
							}
						}
						else if (instruction.getMnemonicId() == ZYDIS_MNEMONIC_CALL) {
							nodeGroup->addNode(new VMethodNode(curAddr));
						}
					}

					return true;
				});
			}
		};
	};
};