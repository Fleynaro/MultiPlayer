#pragma once
#include "ExprTreeOperationalNode.h"

namespace CE::Decompiler::ExprTree
{
	class FunctionCall : public Node, public INodeAgregator
	{
	public:
		Node* m_destination;
		std::vector<Node*> m_paramNodes;
		PCode::Instruction* m_instr;
		Symbol::FunctionResultVar* m_functionResultVar = nullptr;
		
		FunctionCall(Node* destination, PCode::Instruction* instr)
			: m_destination(destination), m_instr(instr)
		{
			m_destination->addParentNode(this);
		}

		~FunctionCall() {
			if (m_destination)
				m_destination->removeBy(this);
			for (auto paramNode : m_paramNodes) {
				paramNode->removeBy(this);
			}
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (m_destination == node) {
				m_destination = newNode;
			}
			else {
				for (auto it = m_paramNodes.begin(); it != m_paramNodes.end(); it ++) {
					if (node == *it) {
						*it = newNode;
					}
				}
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			std::list<ExprTree::Node*> list = { m_destination };
			for (auto paramNode : m_paramNodes) {
				list.push_back(paramNode);
			}
			return list;
		}

		Node* getDestination() {
			return m_destination;
		}

		std::vector<Node*>& getParamNodes() {
			return m_paramNodes;
		}

		void addParamNode(Node* node) {
			node->addParentNode(this);
			m_paramNodes.push_back(node);
		}

		BitMask64 getMask() override {
			return 0x0; //todo
		}

		bool isFloatingPoint() override {
			return false;
		}

		Node* clone(NodeCloneContext* ctx) override {
			auto funcVar = m_functionResultVar ? dynamic_cast<Symbol::FunctionResultVar*>(m_functionResultVar->clone(ctx)) : nullptr;
			auto funcCallCtx = new FunctionCall(m_destination->clone(ctx), m_instr);
			funcCallCtx->m_functionResultVar = funcVar;
			if(funcVar)
				funcVar->m_funcCallContext = funcCallCtx;
			for (auto paramNode : m_paramNodes) {
				funcCallCtx->addParamNode(paramNode->clone(ctx));
			}
			return funcCallCtx;
		}

		std::string printDebug() override {
			std::string str = "(" + getDestination()->printDebug() + ")(";
			for (auto paramNode : m_paramNodes) {
				str += paramNode->printDebug() + ", ";
			}
			if (!m_paramNodes.empty()) {
				str.pop_back();
				str.pop_back();
			}
			return (m_updateDebugInfo = (str + ")"));
		}
	};
};