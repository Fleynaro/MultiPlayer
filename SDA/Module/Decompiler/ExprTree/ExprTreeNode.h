#pragma once
#include "main.h"

namespace CE::Decompiler::ExprTree
{
	class Node;
	class IParentNode
	{
	public:
		virtual void replaceNode(Node* node, Node * newNode) = 0;
	};

	class Node
	{
	public:
		Node()
		{}

		virtual ~Node() {
			replaceBy(nullptr);
		}

		void replaceBy(Node* newNode) {
			for (auto parentNode : m_parentNodes) {
				if (newNode == dynamic_cast<Node*>(parentNode))
					continue;
				parentNode->replaceNode(this, newNode);
				if (newNode != nullptr) {
					newNode->addParentNode(parentNode);
				}
				m_parentNodes.remove(parentNode);
			}
		}

		void removeBy(IParentNode* node) {
			if (node != nullptr) {
				node->replaceNode(this, nullptr);
			}
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