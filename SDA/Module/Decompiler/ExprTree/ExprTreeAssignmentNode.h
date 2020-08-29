#pragma once
#include "../DecPCode.h"
#include "ExprTreeNode.h"

namespace CE::Decompiler::ExprTree
{
	class AssignmentNode : public Node, public INodeAgregator, public PCode::IRelatedToInstruction
	{
		Node* m_dstNode;
		Node* m_srcNode;
	public:
		PCode::Instruction* m_instr;

		AssignmentNode(Node* dstNode, Node* srcNode, PCode::Instruction* instr = nullptr)
			: m_dstNode(dstNode), m_srcNode(srcNode), m_instr(instr)
		{
			m_dstNode->addParentNode(this);
			m_srcNode->addParentNode(this);
		}

		~AssignmentNode() {
			if (m_dstNode)
				m_dstNode->removeBy(this);
			if (m_srcNode)
				m_srcNode->removeBy(this);
		}

		void replaceNode(Node* node, Node* newNode) override {
			if (node == m_dstNode) {
				m_dstNode = newNode;
			}
			if (node == m_srcNode) {
				m_srcNode = newNode;
			}
		}

		std::list<Node*> getNodesList() override {
			return { m_dstNode, m_srcNode };
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			if (m_instr)
				return { m_instr };
			if (auto nodeRelToInstr = dynamic_cast<PCode::IRelatedToInstruction*>(m_dstNode))
				return nodeRelToInstr->getInstructionsRelatedTo();
			if (auto nodeRelToInstr = dynamic_cast<PCode::IRelatedToInstruction*>(m_srcNode))
				return nodeRelToInstr->getInstructionsRelatedTo();
			return {};
		}

		Node* getDstNode() {
			return m_dstNode;
		}

		Node* getSrcNode() {
			return m_srcNode;
		}

		Node** getDstNodePtr() {
			return &m_dstNode;
		}

		Node** getSrcNodePtr() {
			return &m_srcNode;
		}

		BitMask64 getMask() override {
			return m_srcNode->getMask();
		}

		ObjectHash::Hash getHash() override {
			return m_dstNode->getHash() * 31 + m_srcNode->getHash();
		}

		Node* clone(NodeCloneContext* ctx) override {
			return new AssignmentNode(m_dstNode->clone(ctx), m_srcNode->clone(ctx));
		}

		std::string printDebug() override {
			return m_dstNode->printDebug() + " = " + m_srcNode->printDebug() + "\n";
		}
	};
};