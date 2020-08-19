#pragma once
#include "../DecPCode.h"
#include "ExprTreeNode.h"

namespace CE::Decompiler::ExprTree
{
	class MirrorNode : public Node, public INodeAgregator, public PCode::IRelatedToInstruction
	{
	public:
		Node* m_node;
		PCode::Instruction* m_instr;

		MirrorNode(Node* node, PCode::Instruction* instr)
			: m_node(node), m_instr(instr)
		{
			m_node->addParentNode(this);
		}

		~MirrorNode() {
			m_node->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (m_node == node) {
				m_node = newNode;
			}
		}

		std::list<ExprTree::Node*> getNodesList() override {
			return { m_node };
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			if (m_instr)
				return { m_instr };
			return {};
		}

		BitMask64 getMask() override {
			return m_node->getMask();
		}

		bool isFloatingPoint() override {
			return m_node->isFloatingPoint();
		}

		Node* clone() override {
			return new MirrorNode(m_node->clone(), m_instr);
		}

		ObjectHash::Hash getHash() override {
			return m_node->getHash();
		}

		std::string printDebug() override {
			return m_node->printDebug();
		}
	};
};