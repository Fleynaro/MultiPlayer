#pragma once
#include "ExprTreeOperationalNode.h"

namespace CE::Decompiler::ExprTree
{
	struct FunctionCallInfo {
		std::list<ZydisRegister> m_paramRegisters;
		ZydisRegister m_resultRegister;
		ZydisRegister m_resultVectorRegister;
	};

	static FunctionCallInfo GetFunctionCallDefaultInfo() {
		FunctionCallInfo info;
		info.m_paramRegisters = { ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9 };
		info.m_resultRegister = ZYDIS_REGISTER_RAX;
		info.m_resultVectorRegister = ZYDIS_REGISTER_XMM0;
		return info;
	}

	class FunctionCallContext : public Node, public IParentNode
	{
	public:
		int m_destOffset = 0;
		Node* m_destination;
		std::list<std::pair<ZydisRegister, Node*>> m_registerParams;
		
		FunctionCallContext(int destOffset, Node* destination)
			: m_destOffset(destOffset), m_destination(destination)
		{
			m_destination->addParentNode(this);
		}

		void addRegisterParam(ZydisRegister reg, Node* node) {
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

		std::string printDebug() override {
			std::string str = "fun_" + std::to_string(m_destOffset + 50000000) + "(";
			for (auto it : m_registerParams) {
				str += it.second->printDebug() + ", ";
			}
			str.pop_back();
			str.pop_back();
			return str + ")";
		}
	};
};