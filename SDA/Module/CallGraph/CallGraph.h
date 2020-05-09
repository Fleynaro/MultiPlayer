#pragma once
#include <Manager/FunctionDefManager.h>
#include <Disassembler/Disassembler.h>

namespace CE::CallGraph
{
	namespace Node
	{
		enum class Type
		{
			Function = 1,
			VMethod,
			GlobalVar,
			NodeGroup = 11,
			Cycle,
			Condition
		};

		class NodeGroup;
		class Node
		{
		public:
			Node() = default;

			virtual Type getGroup() = 0;

			/*bool isGroup() {
				return getGroup() > Type::GlobalVar;
			}

			bool isFunction() {
				return getGroup() == Type::Function;
			}*/

			//bool isVMethod() {
			//	return getGroup() == Type::VMethod;
			//}

			//bool isGlobalVar() {
			//	return getGroup() == Type::GlobalVar;
			//}

			//bool isFunctionBody() {
			//	return getGroup() == Type::FunctionBody;
			//}

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

		class Leaf : public Node
		{
		public:
			Leaf(void* addr)
				: m_addr(addr)
			{}

			void* getAddressLocation() {
				return m_addr;
			}
		private:
			void* m_addr;
		};

		class FunctionNode : public Leaf
		{
		public:
			FunctionNode(Function::Function* function, void* addr)
				: m_function(function), Leaf(addr)
			{}

			FunctionNode(void* addr)
				: Leaf(addr)
			{}

			Type getGroup() override {
				return Type::Function;
			}

			bool isCalculatedFunction() {
				return !isNotCalculated();
			}

			bool isNotCalculated() {
				return getFunction() == nullptr;
			}

			Function::Function* getFunction() {
				return m_function;
			}
		private:
			Function::Function* m_function = nullptr;
		};

		class VMethodNode : public Leaf
		{
		public:
			VMethodNode(Function::MethodDecl* decl, void* addr)
				: m_decl(decl), Leaf(addr)
			{}

			VMethodNode(void* addr)
				: Leaf(addr)
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

		class GlobalVarNode : public Leaf
		{
		public:
			enum Use {
				Read,
				Write
			};

			GlobalVarNode(Variable::Global* gVar, Use use, void* addr)
				: m_gVar(gVar), m_use(use), Leaf(addr)
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

		class AbstractBody
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
			struct BasicInfo {
				int m_stackMaxDepth = 0;
				int m_calculatedFuncCount = 0;
				int m_notCalculatedFuncCount = 0;
				int m_vMethodCount = 0;
				int m_gVarCount = 0;
				int m_gVarWriteCount = 0;
				bool m_inited = false;

				int getAllFunctionsCount() {
					return m_calculatedFuncCount + m_notCalculatedFuncCount + m_vMethodCount;
				}

				void join(BasicInfo info) {
					m_stackMaxDepth = max(m_stackMaxDepth, info.m_stackMaxDepth);
					m_calculatedFuncCount += info.m_calculatedFuncCount;
					m_notCalculatedFuncCount += info.m_notCalculatedFuncCount;
					m_vMethodCount += info.m_vMethodCount;
					m_gVarCount += info.m_gVarCount;
					m_gVarWriteCount += info.m_gVarWriteCount;
				}

				void next() {
					m_stackMaxDepth++;
				}
			};

			FunctionBody(Function::Function* function)
				: m_function(function)
			{}

			bool isSourceTop() {
				return getFunctionsReferTo().size() == 0;
			}

			Function::Function* getFunction() {
				return m_function;
			}

			void setBasicInfo(BasicInfo& info) {
				m_basicInfo = info;
			}

			BasicInfo& getBasicInfo() {
				return m_basicInfo;
			}
		private:
			Function::Function* m_function;
			BasicInfo m_basicInfo;
		};

		class GlobalVarBody : public AbstractBody
		{
		public:
			GlobalVarBody() = default;

			//MY TODO: доделать GlobalVarBody как FunctionBody сделана
		};
	};

	class CallStack
	{
	public:
		CallStack() = default;

		void push(Node::FunctionBody* body) {
			m_stack.push_front(body);
		}

		void pop() {
			m_stack.pop_front();
		}

		bool empty() {
			return m_stack.empty();
		}

		int size() {
			return static_cast<int>(m_stack.size());
		}

		bool has(Node::FunctionBody* body) {
			for (auto it : m_stack) {
				if (it == body) {
					return true;
				}
			}
			return false;
		}
	private:
		std::list<Node::FunctionBody*> m_stack;
	};

	class FunctionIterator
	{
	public:
		FunctionIterator(Function::Function* function)
			: m_funcBody(function->getBody())
		{}

		FunctionIterator(Node::FunctionBody* funcBody)
			: m_funcBody(funcBody)
		{}

		template<bool isLeft = true>
		void iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback)
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
		void iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback, Filter filter)
		{
			iterateCallStack<isLeft>([&](Node::Node* node, CallStack& stack)
			{
				if ((int)filter & (int)Filter::FunctionNode && node->isFunction()
					|| (int)filter & (int)Filter::GlobalVarNode && node->isGlobalVar()
					|| (int)filter & (int)Filter::FunctionBody && node->isFunctionBody()) {
					return callback(node, stack);
				}
				return true;
			});
		}

		std::list<Node::Node*> getAllNodesInCallTree(Filter filter)
		{
			std::list<Node::Node*> nodes;
			iterateCallStack([&](Node::Node* node, CallStack& stack)
			{
				nodes.push_back(node);
				return true;
			}, filter);
			return nodes;
		}
	private:
		template<bool isLeft = true>
		void iterateCallStack(const std::function<bool(Node::Node*, CallStack&)>& callback, Node::FunctionBody* body, CallStack& stack)
		{
			stack.push(body);

			FunctionIterator pass(body);
			pass.iterateFunctionBody<isLeft>([&](Node::Node* node)
			{
				if (node->isCalculatedFunction()) {
					auto body = static_cast<Node::FunctionNode*>(node)->getFunction()->getBody();
					if (!stack.has(body)) {
						iterateCallStack(callback, body, stack);
					}
				}
				return callback(node, stack);
			});

			stack.pop();
		}

	public:
		template<bool isLeft = true>
		void iterateFunctionBody(const std::function<bool(Node::Node*)>& callback)
		{
			IterateNodeGroup<isLeft>(callback, m_funcBody);
		}

		template<bool isLeft = true>
		static void IterateNodeGroup(const std::function<bool(Node::Node*)>& callback, Node::Node* node)
		{
			if constexpr (isLeft) {
				if (!callback(node))
					return;
			}

			if (node->isGroup()) {
				auto nodeGroup = static_cast<Node::NodeGroup*>(node);
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
		Node::FunctionBody* m_funcBody;
	};

	class CallGraphIterator
	{
	public:
		CallGraphIterator(FunctionManager* funcManager)
			: m_funcManager(funcManager)
		{}

		template<bool isLeft = true>
		void iterate(const std::function<bool(Node::Node*, CallStack&)>& callback)
		{
			iterateSourceTops([&](Node::FunctionBody* funcBody) {
				FunctionIterator pass(funcBody);
				pass.iterateCallStack<isLeft>([&](Node::Node* node, CallStack& stack)
				{
					return callback(node, stack);
				});
				return true;
			});
		}

		void iterateSourceTops(const std::function<bool(Node::FunctionBody*)>& callback)
		{
			FunctionManager::Iterator it(m_funcManager);
			while (it.hasNext()) {
				auto func = it.next();
				if (func->getBody()->isSourceTop()) {
					if (!callback(func->getBody())) {
						break;
					}
				}
			}
		}
	private:
		FunctionManager* m_funcManager;
	};

	namespace Analyser
	{
		class GenericAll
		{
		public:
			GenericAll(FunctionManager* funcManager)
				: m_funcManager(funcManager)
			{}

			void doAnalyse() {
				{
					FunctionManager::Iterator it(m_funcManager);
					while (it.hasNext()) {
						auto func = it.next();
						func->getBody()->getBasicInfo().m_inited = false;
					}
				}

				{
					FunctionManager::Iterator it(m_funcManager);
					while (it.hasNext()) {
						auto func = it.next();
						if (func->getBody()->isSourceTop()) {
							CallStack stack;
							iterateCallStack(func->getBody(), stack);
						}
					}
				}
			}
		private:
			Node::FunctionBody::BasicInfo iterateCallStack(Node::FunctionBody* body, CallStack& stack)
			{
				if (body->getBasicInfo().m_inited) {
					auto info = body->getBasicInfo();
					return info;
				}

				Node::FunctionBody::BasicInfo info;
				info.m_inited = true;
				stack.push(body);

				FunctionIterator pass(body);
				pass.iterateFunctionBody([&](Node::Node* node)
				{
					if (auto funcNode = dynamic_cast<Node::FunctionNode*>(node)) {
						if (funcNode->isCalculatedFunction()) {
							auto body = funcNode->getFunction()->getBody();
							if (!stack.has(body)) {
								info.join(
									iterateCallStack(body, stack)
								);
							}
							info.m_calculatedFuncCount++;
						}
						else {
							info.m_notCalculatedFuncCount++;
						}
					}

					if (auto vmethodNode = dynamic_cast<Node::VMethodNode*>(node)) {
						info.m_vMethodCount++;
					}

					if (auto gvarNode = dynamic_cast<Node::GlobalVarNode*>(node)) {
						info.m_gVarCount++;
						if (gvarNode->getUse() == Node::GlobalVarNode::Write) {
							info.m_gVarWriteCount++;
						}
					}
					return true;
				});

				info.next();
				body->setBasicInfo(info);

				stack.pop();
				return info;
			}
		private:
			FunctionManager* m_funcManager;
		};

		class Generic
		{
		public:
			Generic(Function::Function* function)
				: m_funcBody(function->getBody())
			{}

			Generic(Node::FunctionBody* funcBody)
				: m_funcBody(funcBody)
			{}

			void doAnalyse() {
				FunctionIterator pass(m_funcBody);
				pass.iterateCallStack([this](Node::Node* node, CallStack& stack)
				{
					if (dynamic_cast<Node::FunctionNode*>(node)) {
						m_stat.funcCount++;
					}

					if (dynamic_cast<Node::VMethodNode*>(node)) {
						m_stat.vMethodCount++;
					}

					if (auto gvarNode = dynamic_cast<Node::GlobalVarNode*>(node)) {
						m_stat.gVarCount++;
						if (gvarNode->getUse() == Node::GlobalVarNode::Write) {
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
			Node::FunctionBody* m_funcBody;
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
			CompareFunctionBodies(Node::FunctionBody* funcBody1, Node::FunctionBody* funcBody2) {
				m_funcBody[0] = funcBody1;
				m_funcBody[1] = funcBody2;
			}

			//MY TODO: + gVar also
			void doAnalyse() {
				std::list<Node::Node*> nodesInBody[2];

				for (int i = 0; i <= 1; i++) {
					FunctionIterator pass(m_funcBody[i]);
					nodesInBody[i] = pass.getAllNodesInCallTree(FunctionIterator::Filter::FunctionBody);
				}
					
				for (auto node1 : nodesInBody[0]) {
					auto funcBody1 = static_cast<Node::FunctionBody*>(node1);
					for (auto node2 : nodesInBody[1]) {
						auto funcBody2 = static_cast<Node::FunctionBody*>(node2);
						if (funcBody1->getFunction() == funcBody2->getFunction()) {
							m_mutualFuncBodies.push_back(funcBody1);
						}
					}
				}
			}

			const std::list<Node::FunctionBody*>& getMutualFuncBodies() {
				return m_mutualFuncBodies;
			}
		private:
			Node::FunctionBody* m_funcBody[2];
			std::list<Node::FunctionBody*> m_mutualFuncBodies;
		};

		class ContextDistance
		{
		public:
			const static int m_maxDeepth = 100000;

			struct Result {
				Node::FunctionBody* m_topFuncBody = nullptr;
				int m_fromDist = m_maxDeepth;
				int m_toDist = m_maxDeepth;
					
				Result() = default;

				Result(Node::FunctionBody* topFuncBody, int fromDist, int toDist)
					: m_topFuncBody(topFuncBody), m_fromDist(fromDist), m_toDist(toDist)
				{}

				int getDist() {
					return m_fromDist + m_toDist;
				}
			};

			ContextDistance(FunctionManager* funcManager, Node::FunctionBody* funcBody1, Node::FunctionBody* funcBody2)
				: m_funcManager(funcManager)
			{
				m_funcBody[0] = funcBody1;
				m_funcBody[1] = funcBody2;
			}

			void doAnalyse() {
				CallGraphIterator iter(m_funcManager);
				iter.iterateSourceTops([&](Node::FunctionBody* funcBody)
				{
					iterateCallTree(funcBody, 1);
					return true;
				});
			}

			std::pair<int, int> iterateCallTree(Node::FunctionBody* funcBody, int depth) {
				if (funcBody == m_funcBody[0])
					return std::make_pair(depth, m_maxDeepth);
				if (funcBody == m_funcBody[1])
					return std::make_pair(m_maxDeepth, depth);

				std::pair<int, int> result(m_maxDeepth, m_maxDeepth);

				FunctionIterator pass(funcBody);
				pass.iterateFunctionBody([&](Node::Node* node)
				{
					if(auto funcNode = dynamic_cast<Node::FunctionNode*>(node)) {
						if (!funcNode->isNotCalculated()) {
							auto pair = iterateCallTree(funcNode->getFunction()->getBody(), depth + 1);
							if (pair.first < result.first) {
								result.first = pair.first;
							}
							if (pair.second < result.second) {
								result.second = pair.second;
							}
						}
					}
					return true;
				});

				if (result.first != m_maxDeepth && result.second != m_maxDeepth) {
					auto fromDist = result.first - depth;
					auto toDist = result.second - depth;
					if (fromDist + toDist < m_result.getDist()) {
						m_result = Result(funcBody, fromDist, toDist);
					}
				}

				return result;
			}

			Result& getResult() {
				return m_result;
			}
		private:
			FunctionManager* m_funcManager;
			Node::FunctionBody* m_funcBody[2];
			Result m_result;
		};
	};

	class FunctionBodyBuilder
	{
	public:
		FunctionBodyBuilder(Function::Function* function)
			: m_function(function)
		{}

		void build()
		{
			for (auto& range : m_function->getRangeList()) {
				build(range);
			}
		}

		Node::FunctionBody* getFunctionBody() {
			return m_function->getBody();
		}
	private:
		Function::Function* m_function;

		void build(Function::AddressRange& range)
		{
			using namespace CE::Disassembler;
			using namespace Node;
			auto nodeGroup = getFunctionBody();

			Decoder decoder(range.getMinAddress(), static_cast<int>(range.getSize()));
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
						auto calledFunc = m_function->getManager()->getFunctionAt(instr.getAbsoluteAddr());

						if (instruction.getMnemonicId() != ZYDIS_MNEMONIC_CALL) {
							if (calledFunc != nullptr) {
								if (calledFunc == m_function) {
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