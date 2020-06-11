#pragma once
#include "../ExprTree/ExprTreeCondition.h"

namespace CE::Decompiler::PrimaryTree
{
	class Line : public ExprTree::IParentNode
	{
	public:
		ExprTree::Node* m_destAddr;
		ExprTree::Node* m_srcValue;

		Line(ExprTree::Node* destAddr, ExprTree::Node* srcValue);

		void replaceNode(ExprTree::Node* node, ExprTree::Node * newNode) override {
			if (node == m_destAddr) {
				m_destAddr = newNode;
			}
			if (node == m_srcValue) {
				m_srcValue = newNode;
			}
		}

		std::string printDebug() {
			return m_destAddr->printDebug() + " = " + m_srcValue->printDebug() + "\n";
		}
	};

	class Block : public ExprTree::IParentNode
	{
	public:
		ExprTree::Condition* m_noJmpCond = nullptr;

		Block()
		{}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			if (auto cond = dynamic_cast<ExprTree::Condition*>(node)) {
				if (auto newCond = dynamic_cast<ExprTree::Condition*>(newNode)) {
					if (cond == m_noJmpCond) {
						m_noJmpCond = newCond;
					}
				}
			}
		}

		void setJumpCondition(ExprTree::Condition* noJmpCond) {
			m_noJmpCond = noJmpCond;
			m_noJmpCond->addParentNode(this);
		}

		void addLine(ExprTree::Node* destAddr, ExprTree::Node* srcValue) {
			m_lines.push_back(new Line(destAddr, srcValue));
		}

		std::list<Line*>& getLines() {
			return m_lines;
		}

		void printDebug(bool cond = true, const std::string& tabStr = "") {
			std::string result = "";
			for (auto line : m_lines) {
				result += tabStr + line->printDebug();
			}
			if (cond && m_noJmpCond != nullptr) {
				result += "------> Condition: " + m_noJmpCond->printDebug() + "\n";
			}
			printf("%s", result.c_str());
		}
	private:
		std::list<Line*> m_lines;
	};
};
