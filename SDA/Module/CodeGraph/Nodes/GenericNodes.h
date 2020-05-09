#pragma once
#include "Node.h"

namespace CE {
	namespace Function {
		class FunctionDefinition;
		class MethodDecl;
	};
	namespace Variable {
		class Global;
	};
};

namespace CE::CallGraph::Node
{
	class LeafNode : public Node
	{
	public:
		LeafNode(void* addr);

		void* getAddressLocation();
	private:
		void* m_addr;
	};

	class FunctionNode : public LeafNode
	{
	public:
		FunctionNode(Function::FunctionDefinition* function, void* addr);

		FunctionNode(void* addr);

		Type getGroup() override;

		bool isCalculatedFunction();

		bool isNotCalculated();

		Function::FunctionDefinition* getFunction();
	private:
		Function::FunctionDefinition* m_function = nullptr;
	};

	class VMethodNode : public LeafNode
	{
	public:
		VMethodNode(Function::MethodDecl* decl, void* addr);

		VMethodNode(void* addr);

		Type getGroup() override;

		bool isNotCalculated();

		Function::MethodDecl* getDeclaration();
	private:
		Function::MethodDecl* m_decl = nullptr;
	};

	class GlobalVarNode : public LeafNode
	{
	public:
		enum Use {
			Read,
			Write
		};

		GlobalVarNode(Variable::Global* gVar, Use use, void* addr);

		Type getGroup() override;

		Variable::Global* getGVar();

		Use getUse();
	private:
		Variable::Global* m_gVar;
		Use m_use;
	};

	class Condition : public NodeGroup
	{
	public:
		Type getGroup() override;
	};

	class Cycle : public NodeGroup
	{
	public:
		Type getGroup() override;
	};
};