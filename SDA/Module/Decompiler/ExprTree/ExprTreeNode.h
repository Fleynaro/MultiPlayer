#pragma once
#pragma warning( disable : 4250)
#include "../DecMask.h"
#include "Utils/ObjectHash.h"
#include "../PCode/DecPCode.h"

namespace CE::Decompiler::Symbol
{
	class Symbol;
};

namespace CE::Decompiler::ExprTree
{
	struct NodeCloneContext {
		bool m_cloneSymbols = false;
		std::map<Symbol::Symbol*, Symbol::Symbol*> m_clonedSymbols;
	};

	class INodeAgregator;

	class INode
	{
	public:
		virtual ~INode() {}

		virtual void replaceWith(INode* newNode) = 0;

		virtual void removeBy(INodeAgregator* node) = 0;

		virtual void addParentNode(INodeAgregator* node) = 0;

		virtual void removeParentNode(INodeAgregator* node) = 0;

		virtual std::list<INodeAgregator*>& getParentNodes() = 0;

		virtual INodeAgregator* getParentNode() = 0;

		virtual ObjectHash::Hash getHash() = 0;

		virtual BitMask64 getMask() = 0;

		virtual bool isFloatingPoint() = 0;

		INode* clone() {
			NodeCloneContext ctx;
			return clone(&ctx);
		}

		virtual INode* clone(NodeCloneContext* ctx) = 0;

		virtual std::string printDebug() = 0;

		void static UpdateDebugInfo(INode* node) {
			if (!node) return;
			node->printDebug();
		}
	};

	class INodeAgregator
	{
	public:
		virtual void replaceNode(INode* node, INode* newNode) = 0;

		virtual std::list<INode*> getNodesList() = 0;
	};

	class Node : public virtual INode
	{
	public:
		std::string m_updateDebugInfo;

		Node()
		{}

		~Node() {
			replaceWith(nullptr);
		}

		void replaceWith(INode* newNode) override {
			for (auto it = m_parentNodes.begin(); it != m_parentNodes.end(); it ++) {
				auto parentNode = *it;
				if (newNode == dynamic_cast<INode*>(parentNode))
					continue;
				parentNode->replaceNode(this, newNode);
				if (newNode != nullptr) {
					newNode->addParentNode(parentNode);
				}
				m_parentNodes.erase(it);
			}
		}

		void removeBy(INodeAgregator* node) override {
			if (node != nullptr) {
				node->replaceNode(this, nullptr);
				removeParentNode(node);
			}
			if (m_parentNodes.size() == 0)
				delete this;
		}

		void addParentNode(INodeAgregator* node) override {
			if (this == dynamic_cast<INode*>(node))
				return;
			m_parentNodes.push_back(node);
		}

		void removeParentNode(INodeAgregator* node) override {
			m_parentNodes.remove(node);
		}

		std::list<INodeAgregator*>& getParentNodes() override {
			return m_parentNodes;
		}

		INodeAgregator* getParentNode() override {
			if(m_parentNodes.empty())
				return nullptr;
			return *m_parentNodes.begin();
		}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue((int64_t)this);
			return hash.getHash();
		}

		bool isFloatingPoint() override {
			return false;
		}

		std::string printDebug() override {
			return "";
		}

	private:
		std::list<INodeAgregator*> m_parentNodes;
	};
};