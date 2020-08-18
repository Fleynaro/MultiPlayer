#pragma once
#include "ExprTree/ExprTreeNode.h"

namespace CE::Decompiler
{
	class ITopNode : public ExprTree::INodeAgregator {
	public:
		virtual ExprTree::Node* getGenNode() = 0;

		virtual ExprTree::Node** getGenNodePtr() = 0;

		virtual void setGenNode(ExprTree::Node* node) = 0;

		virtual void clear() = 0;

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			if (getGenNode() == node) {
				setGenNode(newNode);
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { getGenNode() };
		}
	};

	template<typename T = ExprTree::Node>
	class TopNode : public ITopNode
	{
		T* m_node;
	public:
		TopNode(T* node) {
			setNode(node);
		}

		~TopNode() {
			clear();
		}

		T* getNode() {
			return m_node;
		}

		T** getNodePtr() {
			return &m_node;
		}

		void setNode(T* node) {
			m_node = node;
			node->addParentNode(this);
		}

		void clear() override {
			if (m_node) {
				m_node->removeBy(this);
				m_node = nullptr;
			}
		}

	private:
		ExprTree::Node* getGenNode() override {
			return m_node;
		}

		ExprTree::Node** getGenNodePtr() override {
			return &m_node;
		}

		void setGenNode(ExprTree::Node* node) override {
			setNode(dynamic_cast<T*>(node));
		}
	};
};