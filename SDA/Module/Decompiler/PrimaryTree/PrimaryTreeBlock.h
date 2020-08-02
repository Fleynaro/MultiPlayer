#pragma once
#include "../ExprTree/ExprTreeCondition.h"
#include "../ExprTree/ExprTreeFuncCallContext.h"

namespace CE::Decompiler::PrimaryTree
{
	class Block;
	template<typename T = ExprTree::Node>
	class Line : public ExprTree::INodeAgregator
	{
	public:
		T* m_destAddr;
		ExprTree::Node* m_srcValue;
		Block* m_block;

		Line(T* destAddr, ExprTree::Node* srcValue, Block* block)
			: m_destAddr(destAddr), m_srcValue(srcValue), m_block(block)
		{
			destAddr->addParentNode(this);
			srcValue->addParentNode(this);
		}

		~Line() {
			if (m_destAddr)
				m_destAddr->removeBy(this);
			if (m_srcValue)
				m_srcValue->removeBy(this);
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node * newNode) override {
			if (node == m_destAddr) {
				m_destAddr = static_cast<T*>(newNode);
			}
			if (node == m_srcValue) {
				m_srcValue = newNode;
			}
		}

		std::list<ExprTree::Node**> getNodePtrsList() override {
			return { (ExprTree::Node**)&m_destAddr, &m_srcValue };
		}

		std::string printDebug() {
			return m_destAddr->printDebug() + " = " + m_srcValue->printDebug() + "\n";
		}
	};

	using SeqLine = Line<ExprTree::Node>;
	using SymbolAssignmentLine = Line<ExprTree::SymbolLeaf>;

	class Block : public ExprTree::INodeAgregator
	{
	public:
		int m_level = 0;
		std::list<Block*> m_blocksReferencedTo;
		ExprTree::ICondition* m_noJmpCond = nullptr;
		Block* m_nextNearBlock = nullptr;
		Block* m_nextFarBlock = nullptr;

		Block(int level)
			: m_level(level)
		{}

		~Block() {
			for (auto refBlock : m_blocksReferencedTo) {
				if (refBlock->m_nextNearBlock == this)
					refBlock->m_nextNearBlock = refBlock->m_nextFarBlock;
				else if (refBlock->m_nextFarBlock == this)
					refBlock->m_nextFarBlock = nullptr;
			}

			if (m_noJmpCond) {
				m_noJmpCond->removeBy(this);
			}

			if (m_nextFarBlock) {
				m_nextFarBlock->m_blocksReferencedTo.remove(this);
			}

			if (m_nextNearBlock) {
				m_nextNearBlock->m_blocksReferencedTo.remove(this);
			}
		}

		bool isCondition() {
			return m_nextNearBlock != nullptr && m_nextFarBlock != nullptr;
		}

		bool isCycle() {
			return (int)m_blocksReferencedTo.size() != getRefHighBlocksCount();
		}

		int getRefHighBlocksCount() {
			int count = 0;
			for (auto refBlock : m_blocksReferencedTo) {
				if (refBlock->m_level < m_level)
					count++;
			}
			return count;
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			if (auto cond = dynamic_cast<ExprTree::ICondition*>(node)) {
				if (auto newCond = dynamic_cast<ExprTree::ICondition*>(newNode)) {
					if (m_noJmpCond == cond) {
						m_noJmpCond = newCond;
					}
				}
			}
		}

		std::list<ExprTree::Node**> getNodePtrsList() override {
			return { (ExprTree::Node**)&m_noJmpCond };
		}

		void setNoJumpCondition(ExprTree::ICondition* noJmpCond) {
			if (m_noJmpCond) {
				m_noJmpCond->removeBy(this);
			}
			m_noJmpCond = noJmpCond;
			m_noJmpCond->addParentNode(this);
		}

		void addSeqLine(ExprTree::Node* destAddr, ExprTree::Node* srcValue) {
			m_seqLines.push_back(new SeqLine(destAddr, srcValue, this));
		}

		std::list<SeqLine*>& getSeqLines() {
			return m_seqLines;
		}

		void addSymbolAssignmentLine(ExprTree::SymbolLeaf* symbolLeaf, ExprTree::Node* srcValue) {
			m_symbolAssignmentLines.push_back(new SymbolAssignmentLine(symbolLeaf, srcValue, this));
		}

		std::list<SymbolAssignmentLine*>& getSymbolAssignmentLines() {
			return m_symbolAssignmentLines;
		}

		bool hasNoCode() {
			return m_seqLines.empty() && m_symbolAssignmentLines.empty();
		}

		void printDebug(bool cond = true, const std::string& tabStr = "") {
			std::string result = "";
			for (auto line : m_seqLines) {
				result += tabStr + line->printDebug();
			}
			if(!m_symbolAssignmentLines.empty())
				result += tabStr + "<Symbol assignments>:\n";
			for (auto line : m_symbolAssignmentLines) {
				result += tabStr + "- " + line->printDebug();
			}
			if (cond && m_noJmpCond != nullptr) {
				result += "------> Condition: " + m_noJmpCond->printDebug() + "\n";
			}
			printf("%s", result.c_str());
		}
	private:
		std::list<SeqLine*> m_seqLines;
		std::list<SymbolAssignmentLine*> m_symbolAssignmentLines;
	};

	class EndBlock : public Block
	{
	public:
		ExprTree::Node* m_returnNode = nullptr;

		EndBlock(int level)
			: Block(level)
		{}

		~EndBlock() {
			if (m_returnNode) {
				m_returnNode->removeBy(this);
			}
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			Block::replaceNode(node, newNode);
			if (m_returnNode == node) {
				m_returnNode = newNode;
			}
		}

		std::list<ExprTree::Node**> getNodePtrsList() override {
			return { (ExprTree::Node**) & m_noJmpCond, &m_returnNode };
		}

		void setReturnNode(ExprTree::Node* returnNode) {
			if (m_returnNode) {
				m_returnNode->removeBy(this);
			}
			m_returnNode = returnNode;
			returnNode->addParentNode(this);
		}
	};
};
