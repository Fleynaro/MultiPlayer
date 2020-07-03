#pragma once
#include "../DecMask.h"

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
		std::string m_updateDebugInfo;
		void static UpdateDebugInfo(Node* node) {
			if (!node) return;
			node->printDebug();
		}

		Node()
		{}

		virtual ~Node() {
			replaceWith(nullptr);
		}

		void replaceWith(Node* newNode) {
			for (auto it = m_parentNodes.begin(); it != m_parentNodes.end(); it ++) {
				auto parentNode = *it;
				if (newNode == dynamic_cast<Node*>(parentNode))
					continue;
				parentNode->replaceNode(this, newNode);
				if (newNode != nullptr) {
					newNode->addParentNode(parentNode);
				}
				m_parentNodes.erase(it);
			}
		}

		void removeBy(IParentNode* node) {
			if (node != nullptr) {
				node->replaceNode(this, nullptr);
				removeParentNode(node);
			}
			if (getUserCount() == 0)
				delete this;
		}

		void addParentNode(IParentNode* node) {
			if (this == dynamic_cast<Node*>(node))
				return;
			m_parentNodes.push_back(node);
		}

		void removeParentNode(IParentNode* node) {
			m_parentNodes.remove(node);
		}

		void setSigned(bool toggle) {
			m_isSigned = toggle;
		}

		bool isSigned() {
			return m_isSigned;
		}

		virtual bool isLeaf() {
			return false;
		}

		int getUserCount() {
			return (int)m_parentNodes.size();
		}

		virtual std::string printDebug() {
			return "";
		}

	private:
		bool m_isSigned = false;
		std::list<IParentNode*> m_parentNodes;
	};
};