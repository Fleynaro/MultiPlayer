#pragma once
#include "ExprTree/ExprTreeNode.h"

namespace CE::Decompiler
{
	class TopNode : public ExprTree::INodeAgregator
	{
		ExprTree::Node* m_node;
	public:
		TopNode(ExprTree::Node* node) {
			setNode(node);
		}

		~TopNode() {
			clear();
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			if (getNode() == node) {
				setNode(newNode);
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { getNode() };
		}

		ExprTree::Node* getNode() {
			return m_node;
		}

		ExprTree::Node** getNodePtr() {
			return &m_node;
		}

		void setNode(ExprTree::Node* node) {
			m_node = node;
			node->addParentNode(this);
		}

		void clear() {
			if (m_node) {
				m_node->removeBy(this);
				m_node = nullptr;
			}
		}
	};
};