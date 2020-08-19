#pragma once
#include "../ExprTree/ExprTreeCondition.h"
#include "../ExprTree/ExprTreeFuncCallContext.h"
#include "../ExprTree/ExprTreeAssignmentNode.h"
#include "../DecTopNode.h"

namespace CE::Decompiler::PrimaryTree
{
	class Block
	{
	public:
		class BlockTopNode : public TopNode
		{
		public:
			Block* m_block;

			BlockTopNode(Block* block, ExprTree::Node* node = nullptr)
				: m_block(block), TopNode(node)
			{}
		};

		class JumpTopNode : public BlockTopNode
		{
		public:
			JumpTopNode(Block* block)
				: BlockTopNode(block)
			{}

			ExprTree::ICondition* getCond() {
				return dynamic_cast<ExprTree::ICondition*>(getNode());
			}

			void setCond(ExprTree::ICondition* cond) {
				setNode(cond);
			}
		};

		class ReturnTopNode : public BlockTopNode
		{
		public:
			ReturnTopNode(Block* block)
				: BlockTopNode(block)
			{}
		};

		class SeqLine : public BlockTopNode
		{
		public:
			SeqLine(Block* block, ExprTree::Node* dstNode, ExprTree::Node* srcNode)
				: BlockTopNode(block, new ExprTree::AssignmentNode(dstNode, srcNode))
			{}

			ExprTree::AssignmentNode* getAssignmentNode() {
				return dynamic_cast<ExprTree::AssignmentNode*>(getNode());
			}

			ExprTree::Node* getDstNode() {
				return getAssignmentNode()->getDstNode();
			}

			ExprTree::Node* getSrcNode() {
				return getAssignmentNode()->getSrcNode();
			}
		};

		class SymbolAssignmentLine : public SeqLine
		{
		public:
			SymbolAssignmentLine(Block* block, ExprTree::SymbolLeaf* dstNode, ExprTree::Node* srcNode)
				: SeqLine(block, dstNode, srcNode)
			{}

			ExprTree::SymbolLeaf* getDstSymbol() {
				return dynamic_cast<ExprTree::SymbolLeaf*>(getAssignmentNode()->getDstNode());
			}
		};

	private:
		JumpTopNode* m_noJmpCond;
	public:
		std::string m_name;
		int m_level = 0;
		int m_maxHeight = 0;
		DecompiledCodeGraph* m_decompiledGraph;

		Block(DecompiledCodeGraph* decompiledGraph, int level)
			: m_decompiledGraph(decompiledGraph), m_level(level)
		{
			m_noJmpCond = new JumpTopNode(this);
		}

		~Block() {
			for (auto refBlock : m_blocksReferencedTo) {
				if (refBlock->m_nextNearBlock == this)
					refBlock->m_nextNearBlock = refBlock->m_nextFarBlock;
				else if (refBlock->m_nextFarBlock == this)
					refBlock->m_nextFarBlock = nullptr;
			}

			delete m_noJmpCond;
			disconnect();
		}

		void disconnect() {
			for (auto nextBlock : getNextBlocks()) {
				nextBlock->removeRefBlock(this);
			}
			m_nextNearBlock = m_nextFarBlock = nullptr;
		}

		void removeRefBlock(Block* block) {
			m_blocksReferencedTo.remove(block);
		}

		void setNextNearBlock(Block* nextBlock) {
			if (nextBlock) {
				nextBlock->removeRefBlock(m_nextNearBlock);
				nextBlock->m_blocksReferencedTo.push_back(this);
			}
			m_nextNearBlock = nextBlock;
		}

		void setNextFarBlock(Block* nextBlock) {
			if (nextBlock) {
				nextBlock->removeRefBlock(m_nextFarBlock);
				nextBlock->m_blocksReferencedTo.push_back(this);
			}
			m_nextFarBlock = nextBlock;
		}

		Block* getNextNearBlock() {
			return m_nextNearBlock;
		}

		Block* getNextFarBlock() {
			return m_nextFarBlock;
		}

		std::list<Block*>& getBlocksReferencedTo() {
			return m_blocksReferencedTo;
		}

		std::list<Block*> getNextBlocks() {
			std::list<Block*> nextBlocks;
			if (m_nextFarBlock) {
				nextBlocks.push_back(m_nextFarBlock);
			}
			if (m_nextNearBlock) {
				nextBlocks.push_back(m_nextNearBlock);
			}
			return nextBlocks;
		}

		Block* getNextBlock() {
			if (m_nextFarBlock) {
				return m_nextFarBlock;
			}
			if (m_nextNearBlock) {
				return m_nextNearBlock;
			}
			return nullptr;
		}

		void swapNextBlocks() {
			std::swap(m_nextNearBlock, m_nextFarBlock);
		}

		bool isCondition() {
			return m_nextNearBlock != nullptr && m_nextFarBlock != nullptr;
		}

		bool isCycle() {
			return (int)m_blocksReferencedTo.size() != getRefHighBlocksCount();
		}

		int getRefBlocksCount() {
			return (int)m_blocksReferencedTo.size();
		}

		int getRefHighBlocksCount() {
			int count = 0;
			for (auto refBlock : m_blocksReferencedTo) {
				if (refBlock->m_level < m_level)
					count++;
			}
			return count;
		}

		virtual std::list<BlockTopNode*> getAllTopNodes() {
			std::list<BlockTopNode*> result;
			for (auto line : getSeqLines()) {
				result.push_back(line);
			}
			for (auto line : getSymbolAssignmentLines()) {
				result.push_back(line);
			}

			if(getNoJumpCondition())
				result.push_back(m_noJmpCond);
			return result;
		}

		ExprTree::ICondition* getNoJumpCondition() {
			return m_noJmpCond->getCond();
		}

		void setNoJumpCondition(ExprTree::ICondition* noJmpCond) {
			if (getNoJumpCondition()) {
				m_noJmpCond->clear();
			}
			m_noJmpCond->setNode(noJmpCond);
		}

		void addSeqLine(ExprTree::Node* destAddr, ExprTree::Node* srcValue) {
			m_seqLines.push_back(new SeqLine(this, destAddr, srcValue));
		}

		std::list<SeqLine*>& getSeqLines() {
			return m_seqLines;
		}

		void addSymbolAssignmentLine(ExprTree::SymbolLeaf* symbolLeaf, ExprTree::Node* srcValue) {
			m_symbolAssignmentLines.push_back(new SymbolAssignmentLine(this, symbolLeaf, srcValue));
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
				result += tabStr + line->getNode()->printDebug();
			}
			if(!m_symbolAssignmentLines.empty())
				result += tabStr + "<Symbol assignments>:\n";
			for (auto line : m_symbolAssignmentLines) {
				result += tabStr + "- " + line->getNode()->printDebug();
			}
			if (cond && getNoJumpCondition() != nullptr) {
				result += "------> Condition: " + getNoJumpCondition()->printDebug() + "\n";
			}
			printf("%s", result.c_str());
		}
	private:
		std::list<Block*> m_blocksReferencedTo;
		Block* m_nextNearBlock = nullptr;
		Block* m_nextFarBlock = nullptr;
		std::list<SeqLine*> m_seqLines;
		std::list<SymbolAssignmentLine*> m_symbolAssignmentLines;
	};

	class EndBlock : public Block
	{
		ReturnTopNode* m_returnNode = nullptr;
	public:
		EndBlock(DecompiledCodeGraph* decompiledGraph, int level)
			: Block(decompiledGraph, level)
		{
			m_returnNode = new ReturnTopNode(this);
		}

		~EndBlock() {
			delete m_returnNode;
		}

		std::list<BlockTopNode*> getAllTopNodes() override {
			auto list = Block::getAllTopNodes();
			if (getReturnNode()) {
				list.push_back(m_returnNode);
			}
			return list;
		}

		ExprTree::Node* getReturnNode() {
			return m_returnNode->getNode();
		}

		void setReturnNode(ExprTree::Node* returnNode) {
			if (getReturnNode()) {
				m_returnNode->clear();
			}
			m_returnNode->setNode(returnNode);
		}
	};
};
