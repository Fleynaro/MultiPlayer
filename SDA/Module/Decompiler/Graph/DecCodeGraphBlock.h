#pragma once
#include "../ExprTree/ExprTree.h"
#include "../DecTopNode.h"

namespace CE::Decompiler::PrimaryTree
{
	class Block;
	struct BlockCloneContext {
		DecompiledCodeGraph* m_graph;
		std::map<Block*, Block*> m_clonedBlocks;
		ExprTree::NodeCloneContext m_nodeCloneContext;
	};

	// Decompiled block which contains the abstract tree
	class Block
	{
	public:
		// here are top nodes which are roots of expression trees

		// top node for a decompiled block
		class BlockTopNode : public TopNode
		{
		public:
			Block* m_block;

			BlockTopNode(Block* block, ExprTree::INode* node = nullptr)
				: m_block(block), TopNode(node)
			{}
		};

		// condition for jumping to another block
		class JumpTopNode : public BlockTopNode
		{
		public:
			JumpTopNode(Block* block)
				: BlockTopNode(block)
			{}

			ExprTree::AbstractCondition* getCond() {
				return dynamic_cast<ExprTree::AbstractCondition*>(getNode());
			}

			void setCond(ExprTree::AbstractCondition* cond) {
				setNode(cond);
			}
		};

		// operator "return" which contains expr. tree that is the result of a function
		class ReturnTopNode : public BlockTopNode
		{
		public:
			ReturnTopNode(Block* block)
				: BlockTopNode(block)
			{}
		};

		// line in high-level present (like code lines in C++), it may be function call or assignment
		class SeqLine : public BlockTopNode
		{
		public:
			SeqLine(Block* block, ExprTree::AssignmentNode* assignmentNode)
				: BlockTopNode(block, assignmentNode)
			{}

			SeqLine(Block* block, ExprTree::INode* dstNode, ExprTree::INode* srcNode, PCode::Instruction* instr)
				: SeqLine(block, new ExprTree::AssignmentNode(dstNode, srcNode, instr))
			{}

			~SeqLine() {
				m_block->m_seqLines.remove(this);
			}

			virtual SeqLine* clone(Block* block, ExprTree::NodeCloneContext* ctx) {
				return new SeqLine(block, dynamic_cast<ExprTree::AssignmentNode*>(getNode()->clone(ctx)));
			}
		};

		class SymbolAssignmentLine : public SeqLine
		{
		public:
			SymbolAssignmentLine(Block* block, ExprTree::AssignmentNode* assignmentNode)
				: SeqLine(block, assignmentNode)
			{}

			SymbolAssignmentLine(Block* block, ExprTree::SymbolLeaf* dstNode, ExprTree::INode* srcNode, PCode::Instruction* instr)
				: SeqLine(block, dstNode, srcNode, instr)
			{}

			~SymbolAssignmentLine() {
				m_block->m_symbolAssignmentLines.remove(this);
			}

			ExprTree::AssignmentNode* getAssignmentNode() {
				return dynamic_cast<ExprTree::AssignmentNode*>(getNode());
			}

			// left node from =
			ExprTree::INode* getDstNode() {
				return getAssignmentNode()->getDstNode();
			}

			// right node from =
			ExprTree::INode* getSrcNode() {
				return getAssignmentNode()->getSrcNode();
			}

			ExprTree::SymbolLeaf* getDstSymbolLeaf() {
				return dynamic_cast<ExprTree::SymbolLeaf*>(getDstNode());
			}

			SeqLine* clone(Block* block, ExprTree::NodeCloneContext* ctx) override {
				return new SymbolAssignmentLine(block, dynamic_cast<ExprTree::AssignmentNode*>(getNode()->clone(ctx)));
			}
		};

	public:
		std::string m_name;
		int m_level = 0;
	private:
		std::list<Block*> m_blocksReferencedTo;
		Block* m_nextNearBlock = nullptr;
		Block* m_nextFarBlock = nullptr;
		std::list<SeqLine*> m_seqLines;
		std::list<SymbolAssignmentLine*> m_symbolAssignmentLines;
		JumpTopNode* m_noJmpCond;
	public:
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

		// make the block independent from the decompiled graph
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

		// get count of blocks which reference to this block
		int getRefBlocksCount() {
			return (int)m_blocksReferencedTo.size();
		}

		// get count of blocks which reference to this block and located higher
		int getRefHighBlocksCount() {
			int count = 0;
			for (auto refBlock : m_blocksReferencedTo) {
				if (refBlock->m_level < m_level)
					count++;
			}
			return count;
		}

		// get all top nodes for this block (assignments, function calls, return) / get all expressions
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

		// condition top node which contains boolean expression to jump to another block
		ExprTree::AbstractCondition* getNoJumpCondition() {
			return m_noJmpCond->getCond();
		}

		void setNoJumpCondition(ExprTree::AbstractCondition* noJmpCond) {
			if (getNoJumpCondition()) {
				m_noJmpCond->clear();
			}
			if (noJmpCond) {
				m_noJmpCond->setNode(noJmpCond);
			}
		}

		void addSeqLine(ExprTree::INode* destAddr, ExprTree::INode* srcValue, PCode::Instruction* instr = nullptr) {
			m_seqLines.push_back(new SeqLine(this, destAddr, srcValue, instr));
		}

		std::list<SeqLine*>& getSeqLines() {
			return m_seqLines;
		}

		void addSymbolAssignmentLine(ExprTree::SymbolLeaf* symbolLeaf, ExprTree::INode* srcValue, PCode::Instruction* instr = nullptr) {
			m_symbolAssignmentLines.push_back(new SymbolAssignmentLine(this, symbolLeaf, srcValue, instr));
		}

		std::list<SymbolAssignmentLine*>& getSymbolAssignmentLines() {
			return m_symbolAssignmentLines;
		}

		// check if this block is empty
		bool hasNoCode() {
			return m_seqLines.empty() && m_symbolAssignmentLines.empty();
		}

		Block* clone(BlockCloneContext* ctx) {
			auto it = ctx->m_clonedBlocks.find(this);
			if (it != ctx->m_clonedBlocks.end())
				return it->second;
			auto newBlock = clone(ctx, m_level);
			ctx->m_clonedBlocks.insert(std::make_pair(this, newBlock));
			newBlock->m_maxHeight = m_maxHeight;
			newBlock->m_name = m_name;
			if(m_nextNearBlock)
				newBlock->setNextNearBlock(m_nextNearBlock->clone(ctx));
			if(m_nextFarBlock)
				newBlock->setNextFarBlock(m_nextFarBlock->clone(ctx));
			if(getNoJumpCondition())
				newBlock->setNoJumpCondition(dynamic_cast<ExprTree::AbstractCondition*>(getNoJumpCondition()->clone(&ctx->m_nodeCloneContext)));
			for (auto line : m_seqLines) {
				newBlock->m_seqLines.push_back(line->clone(newBlock, &ctx->m_nodeCloneContext));
			}
			for (auto line : m_symbolAssignmentLines) {
				auto newLine = dynamic_cast<SymbolAssignmentLine*>(line->clone(newBlock, &ctx->m_nodeCloneContext));
				newBlock->m_symbolAssignmentLines.push_back(newLine);
			}
			return newBlock;
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

		protected:
			virtual Block* clone(BlockCloneContext* ctx, int level) {
				return new Block(ctx->m_graph, level);
			}
	};

	// Block in which the control flow end (the last instruction of these blocks is RET).
	class EndBlock : public Block
	{
		ReturnTopNode* m_returnNode = nullptr; // operator return where the result is
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

		ExprTree::INode* getReturnNode() {
			return m_returnNode->getNode();
		}

		void setReturnNode(ExprTree::INode* returnNode) {
			if (getReturnNode()) {
				m_returnNode->clear();
			}
			m_returnNode->setNode(returnNode);
		}

	protected:
		Block* clone(BlockCloneContext* ctx, int level) override {
			auto newBlock = new EndBlock(ctx->m_graph, level);
			if (getReturnNode())
				newBlock->setReturnNode(getReturnNode()->clone(&ctx->m_nodeCloneContext));
			return newBlock;
		}
	};
};
