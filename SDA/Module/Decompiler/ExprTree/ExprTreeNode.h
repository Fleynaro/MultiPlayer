#pragma once
#include "../DecMask.h"
#include "Utils/ObjectHash.h"
#include "../PCode/DecPCode.h"

namespace CE::Decompiler::Symbol
{
	class Symbol;
};

namespace CE::Decompiler::ExprTree
{
	class Node;
	class INodeAgregator
	{
	public:
		virtual void replaceNode(Node* node, Node* newNode) = 0;

		virtual std::list<Node*> getNodesList() = 0;
	};

	struct NodeCloneContext {
		bool m_cloneSymbols = false;
		std::map<Symbol::Symbol*, Symbol::Symbol*> m_clonedSymbols;
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

		INodeAgregator* getParentNode() {
			if(m_parentNodes.empty())
				return nullptr;
			return *m_parentNodes.begin();
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

		virtual BitMask64 getMask() = 0;

		virtual bool isFloatingPoint() {
			return false;
		}

		Node* clone() {
			NodeCloneContext ctx;
			return clone(&ctx);
		}

		virtual Node* clone(NodeCloneContext* ctx) = 0;

		virtual std::string printDebug() {
			return "";
		}

	private:
		std::list<INodeAgregator*> m_parentNodes;
	};
};