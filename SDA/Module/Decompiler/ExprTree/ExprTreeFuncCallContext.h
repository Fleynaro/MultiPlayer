#pragma once
#include "ExprTreeOperationalNode.h"

namespace CE::Decompiler::ExprTree
{
	struct FunctionCallInfo {
		std::list<PCode::Register> m_knownRegisters;
		std::list<PCode::Register> m_paramRegisters;
		PCode::Register m_resultRegister;
		PCode::Register m_resultVectorRegister;
	};

	static FunctionCallInfo GetFunctionCallDefaultInfo() {
		FunctionCallInfo info;
		return info;
	}

	class FunctionCallContext : public Node, public INodeAgregator
	{
	public:
		int m_destOffset = 0;
		Node* m_destination;
		std::list<std::pair<PCode::Register, Node*>> m_registerParams;
		
		FunctionCallContext(int destOffset, Node* destination)
			: m_destOffset(destOffset), m_destination(destination)
		{
			m_destination->addParentNode(this);
		}

		void addRegisterParam(PCode::Register reg, Node* node) {
			m_registerParams.push_back(std::make_pair(reg, node));
			node->addParentNode(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (m_destination == node) {
				m_destination = newNode;
			}
			else {
				for (auto& it : m_registerParams) {
					if (it.second == node) {
						it.second = newNode;
					}
				}
			}
		}

		std::list<ExprTree::Node**> getNodePtrsList() override {
			std::list<ExprTree::Node**> list = { &m_destination };
			for (auto& it : m_registerParams) {
				list.push_back(&it.second);
			}
			return list;
		}

		Node* clone() override {
			auto funcCallCtx = new FunctionCallContext(m_destOffset, m_destination->clone());
			for (auto it : m_registerParams) {
				funcCallCtx->addRegisterParam(it.first, it.second->clone());
			}
			return funcCallCtx;
		}

		std::string printDebug() override {
			std::string str = "fun_" + std::to_string(m_destOffset + 50000000) + "(";
			for (auto it : m_registerParams) {
				str += it.second->printDebug() + ", ";
			}
			if (!m_registerParams.empty()) {
				str.pop_back();
				str.pop_back();
			}
			return (m_updateDebugInfo = (str + ")"));
		}
	};
};