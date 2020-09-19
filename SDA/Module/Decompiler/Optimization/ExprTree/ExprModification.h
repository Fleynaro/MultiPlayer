#pragma once
#include "../../ExprTree/ExprTree.h"

namespace CE::Decompiler
{
	using namespace ExprTree;

	class ExprModification
	{
		INode* m_node;
	public:
		ExprModification(INode* node)
			: m_node(node)
		{}

		virtual void start() = 0;

		INode* getNode() {
			return m_node;
		}

	protected:
		void replace(INode* newNode, bool destroy = true) {
			m_node->replaceWith(newNode);
			if (destroy) {
				delete m_node;
			}
			m_node = newNode;
		}
	};
};