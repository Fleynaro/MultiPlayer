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

				Type getGroup() override {
					return Type::FunctionBody;
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
			};
		};

		class CallStack
		{
		public:
			CallStack() = default;

			void push(Unit::FunctionBody* body) {
				m_stack.push(body);
			}

			Unit::FunctionBody* pop() {
				m_stack.pop();
			}

			bool empty() {
				return m_stack.empty();
			}
		private:
			std::stack<Unit::FunctionBody*> m_stack;
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

			void iterateCallStack(const std::function<void(Unit::Node*, CallStack&)>& callback)
			{
				CallStack stack;
				iterateCallStack(callback, m_funcBody, stack);
			}

		private:
			void iterateCallStack(const std::function<void(Unit::Node*, CallStack&)>& callback, Unit::FunctionBody* body, CallStack& stack)
			{
				stack.push(body);

				FunctionIterator pass(body);
				pass.iterateFunctionBody([&](Unit::Node* node)
				{
					if (node->isFunction()) {
						auto functionNode = static_cast<Unit::FunctionNode*>(node);
						if (!functionNode->isNotCalculated()) {
							iterateCallStack(callback, functionNode->getFunction()->getBody(), stack);
						}
					}
					callback(node, stack);
				});
			}

		public:
			template<bool isLeft = true>
			void iterateFunctionBody(const std::function<void(Unit::Node*)>& callback)
			{
				IterateNodeGroup<isLeft>(callback, m_funcBody);
			}

			template<bool isLeft = true>
			static void IterateNodeGroup(const std::function<void(Unit::Node*)>& callback, Unit::Node* node)
			{
				if constexpr (isLeft) {
					callback(node);
				}

				if (node->isGroup()) {
					auto nodeGroup = static_cast<Unit::NodeGroup*>(node);
					for (auto node : nodeGroup->getNodeList()) {
						IterateNodeGroup(callback, node);
					}
				}
				
				if constexpr (!isLeft) {
					callback(node);
				}
			}
		private:
			Unit::FunctionBody* m_funcBody;
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

						if (node->isGlobalVar()) {
							m_stat.gVarCount++;
						}
					});
				}
			private:
				Unit::FunctionBody* m_funcBody;
				struct {
					int funcCount = 0;
					int gVarCount = 0;
				} m_stat;
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
				for (auto& range : m_function->getFunction()->getRangeList()) {
					build(range);
				}
			}

			Unit::FunctionBody* getFunctionBody() {
				return m_function->getBody();
			}
		private:
			API::Function::Function* m_function;

			void build(Function::Function::Range& range)
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
								nodeGroup->addNode(new FunctionNode(calledFunc, curAddr));
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