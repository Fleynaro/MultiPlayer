#pragma once
#include "main.h"

namespace CE::Decompiler::ExprTree
{
	class Node;
	class IParentNode
	{
	public:
		virtual void removeNode(Node* node) = 0;
	};

	class Node
	{
	public:
		Node()
		{}

		virtual ~Node() {
			for (auto parentNode : m_parentNodes) {
				parentNode->removeNode(this);
			}
		}

		void removeBy(IParentNode* node) {
			m_parentNodes.remove(node);
			if (getUserCount() == 0)
				delete this;
		}

		void addParentNode(IParentNode* node) {
			m_parentNodes.push_back(node);
		}

		void setSigned(bool toggle) {
			m_isSigned = toggle;
		}

		bool isSigned() {
			return m_isSigned;
		}

		int getUserCount() {
			return (int)m_parentNodes.size();
		}

		virtual bool isLeaf() = 0;

		virtual std::string printDebug() = 0;

	private:
		bool m_isSigned = false;
		std::list<IParentNode*> m_parentNodes;
	};
};