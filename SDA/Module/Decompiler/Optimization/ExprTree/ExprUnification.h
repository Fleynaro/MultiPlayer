#pragma once
#include "ExprModification.h"

namespace CE::Decompiler::Optimization
{
	class ExprUnification : public ExprModification
	{
	public:
		ExprUnification(INode* node)
			: ExprModification(node)
		{}

		void start() override {
			dispatch(getNode());
		}
	private:
		void dispatch(INode* node) {
			if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
				processOpNode(opNode);
			}
		}

		void processOpNode(OperationalNode* opNode) {
			if (IsOperationMoving(opNode->m_operation)) {
				if (IsSwap(opNode->m_leftNode, opNode->m_rightNode)) {
					std::swap(opNode->m_leftNode, opNode->m_rightNode);
				}
			}
		}

		//a
		//a * 5
		static bool IsLeaf(INode* node) {
			if (dynamic_cast<ILeaf*>(node))
				return true;
			if (auto opNode = dynamic_cast<OperationalNode*>(node)) {
				if (opNode->m_operation == Mul) {
					if (dynamic_cast<INumberLeaf*>(opNode->m_rightNode) && IsLeaf(opNode->m_leftNode))
						return true;
				}
			}
			return false;
		}


		static bool IsSwap(INode* node1, INode* node2) {
			return dynamic_cast<INumberLeaf*>(node1) && !dynamic_cast<INumberLeaf*>(node2) || IsLeaf(node1) && !IsLeaf(node2);
		}
	};
};