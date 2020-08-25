#pragma once
#include "ExprTreeSdaNode.h"
#include "../../DecTopNode.h"
#include "../../ExprTree/ExprTreeFunctionCall.h"

namespace CE::Decompiler::ExprTree
{
	class SdaFunctionNode : public AbstractSdaNode, public INodeAgregator
	{
	public:
		class DestinationTopNode : public TopNode
		{
		public:
			DestinationTopNode(AbstractSdaNode* node)
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

		SdaFunctionNode(FunctionCall* funcCallCtx, AbstractSdaNode* dest)
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
			std::list<ExprTree::Node*> result;
			for (auto param : m_parameters) {
				result.push_back(param->m_topNode->getNode());
			}
			return result;
		}

		DataTypePtr getDataType() override {
			return m_returnType;
		}

		BitMask64 getMask() override {
			return m_funcCallCtx->getMask();
		}

		bool isFloatingPoint() override {
			return m_funcCallCtx->isFloatingPoint();
		}

		Node* clone(NodeCloneContext* ctx) override {
			return nullptr;
		}

		std::string printDebug() override {
			std::string str = "(" + m_destination->getNode()->printDebug() + ")(";
			for (auto param : m_parameters) {
				str += param->m_topNode->getNode()->printDebug() + ", ";
			}
			if (!m_parameters.empty()) {
				str.pop_back();
				str.pop_back();
			}
			return (m_updateDebugInfo = (str + ")"));
		}
	private:
		FunctionCall* m_funcCallCtx;
		DataTypePtr m_returnType;
		DestinationTopNode* m_destination;
		std::list<Parameter*> m_parameters;
	};
};