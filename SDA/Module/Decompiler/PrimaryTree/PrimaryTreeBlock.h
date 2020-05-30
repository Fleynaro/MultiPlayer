#pragma once
#include "../ExprTree/ExprTreeCondition.h"

namespace CE::Decompiler::PrimaryTree
{
	class Line : public ExprTree::IParentNode
	{
	public:
		ExprTree::Node* m_destAddr;
		ExprTree::Node* m_srcValue;

		Line(ExprTree::Node* destAddr, ExprTree::Node* srcValue)
			: m_destAddr(destAddr), m_srcValue(srcValue)
		{
			destAddr->addParentNode(this);
			srcValue->addParentNode(this);
		}

		void removeNode(ExprTree::Node* node) {
			if (node == m_destAddr) {
				m_destAddr = nullptr;
			}
			if (node == m_srcValue) {
				m_srcValue = nullptr;
			}
		}
	};

	class Block
	{
	public:
		ExprTree::Condition* m_jmpCond = nullptr;

		Block()

		{}

		std::list<Line*>& getLines() {
			return m_lines;
		}

		std::string printDebug() {
			std::string result = "";
			for (auto line : m_lines) {
				result += line->m_destAddr->printDebug() + " = " + line->m_srcValue->printDebug() + "\n";
			}
			if (m_jmpCond != nullptr) {
				result += "\nCondition: " + m_jmpCond->printDebug();
			}
			return result;
		}
	private:
		std::list<Line*> m_lines;
	};
};
