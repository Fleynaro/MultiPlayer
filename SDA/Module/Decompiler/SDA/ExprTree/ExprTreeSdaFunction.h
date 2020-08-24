#pragma once
#include "ExprTreeSdaNode.h"
#include "../../DecTopNode.h"
#include "../../ExprTree/ExprTreeFuncCallContext.h"

namespace CE::Decompiler::ExprTree
{
	class SdaFunctionNode : public AbstractSdaNode, public INodeAgregator
	{
	public:
		class DestinationTopNode : public TopNode
		{
		public:
			DestinationTopNode(SdaNode* node)
				: TopNode(node)
			{}
		};

		class ParameterTopNode : public TopNode
		{
		public:
			ParameterTopNode(SdaNode* node)
				: TopNode(node)
			{}
		};

		class Parameter
		{
		public:
			CE::Symbol::FuncParameterSymbol* m_symbol;
			ParameterTopNode* m_topNode;

			Parameter(CE::Symbol::FuncParameterSymbol* symbol, SdaNode* node)
				: m_symbol(symbol), m_topNode(new ParameterTopNode(node))
			{}

			~Parameter() {
				delete m_topNode;
			}
		};

		SdaFunctionNode(FunctionCallContext* funcCallCtx, SdaNode* dest)
			: m_funcCallCtx(funcCallCtx)
		{
			m_destination = new DestinationTopNode(dest);
		}

		~SdaFunctionNode() {
			delete m_destination;
			for (auto param : m_parameters) {
				delete param;
			}
		}

		std::list<Parameter*>& getParameters() {
			return m_parameters;
		}

		void replaceNode(Node* node, Node* newNode) override {}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_node };
		}

		DataTypePtr getDataType() override {
			return m_calcDataType;
		}

		BitMask64 getMask() override {
			return m_funcCallCtx->getMask();
		}

		bool isFloatingPoint() override {
			return m_funcCallCtx->isFloatingPoint();
		}

		Node* clone(NodeCloneContext* ctx) override {
			auto sdaNode = new SdaNode(m_node->clone(ctx));
			sdaNode->m_calcDataType = m_calcDataType;
			sdaNode->m_explicitCast = m_explicitCast;
			return sdaNode;
		}

		std::string printDebug() override {
			std::string str = "(" + m_destination->getNode()->printDebug() + ")(";
			for (auto param : m_parameters) {
				str += param->m_symbol->getName() + ", ";
			}
			if (!m_parameters.empty()) {
				str.pop_back();
				str.pop_back();
			}
			return (m_updateDebugInfo = (str + ")"));
		}
	private:
		FunctionCallContext* m_funcCallCtx;
		DestinationTopNode* m_destination;
		std::list<Parameter*> m_parameters;
	};
};