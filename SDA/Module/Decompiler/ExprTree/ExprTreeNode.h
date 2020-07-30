#pragma once
#include "../DecMask.h"
#include "Utils/ObjectHash.h"

namespace CE::Decompiler::ExprTree
{
	class Node;
	class INodeAgregator
	{
	public:
		virtual void replaceNode(Node* node, Node * newNode) = 0;

		virtual std::list<Node**> getNodePtrsList() = 0;

		std::list<Node*> getNodesList() {
			std::list<Node*> list;
			for (auto it : getNodePtrsList()) {
				if (*it != nullptr) {
					list.push_back(*it);
				}
			}
			return list;
		}
	};

	class IFloatingPoint
	{
	public:
		virtual bool IsFloatingPoint() = 0;
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

		void removeBy(INodeAgregator* node) {
			if (node != nullptr) {
				node->replaceNode(this, nullptr);
				removeParentNode(node);
			}
			if (getUserCount() == 0)
				delete this;
		}

		void addParentNode(INodeAgregator* node) {
			if (this == dynamic_cast<Node*>(node))
				return;
			m_parentNodes.push_back(node);
		}

		void removeParentNode(INodeAgregator* node) {
			m_parentNodes.remove(node);
		}

		std::list<INodeAgregator*>& getParentNodes() {
			return m_parentNodes;
		}

		virtual bool isLeaf() {
			return false;
		}

		int getUserCount() {
			return (int)m_parentNodes.size();
		}

		virtual ObjectHash::Hash getHash() {
			ObjectHash hash;
			hash.addValue((int64_t)this);
			return hash.getHash();
		}

		virtual Node* clone() = 0;

		virtual std::string printDebug() {
			return "";
		}

	private:
		std::list<INodeAgregator*> m_parentNodes;
	};
};