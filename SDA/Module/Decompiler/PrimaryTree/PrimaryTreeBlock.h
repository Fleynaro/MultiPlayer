#pragma once
#include "../ExprTree/ExprTreeCondition.h"
#include "../ExprTree/ExprTreeFuncCallContext.h"
#include "../DecTopNode.h"

namespace CE::Decompiler::PrimaryTree
{
	class Block;
	template<typename T = ExprTree::Node>
	class Line : public ExprTree::Node, public ExprTree::INodeAgregator
	{
	public:
		template<typename T = ExprTree::Node>
		class LineTopNode : public TopNode<T>
		{
		public:
			Line* m_line;

			LineTopNode(Line* line, T* node = nullptr)
				: m_line(line), TopNode<T>(node)
			{}
		};

		class DstTopNode : public LineTopNode<T>
		{
		public:
			DstTopNode(Line* line, T* node = nullptr)
				: LineTopNode<T>(line, node)
			{}
		};

		class SrcTopNode : public LineTopNode<ExprTree::Node>
		{
		public:
			SrcTopNode(Line* line, ExprTree::Node* node = nullptr)
				: LineTopNode<ExprTree::Node>(line, node)
			{}
		};

	public:
		DstTopNode* m_destAddr;
		SrcTopNode* m_srcValue;
		Block* m_block;

		Line(T* destAddr, ExprTree::Node* srcValue, Block* block)
			: m_destAddr(destAddr), m_srcValue(srcValue), m_block(block)
		{
			m_destAddr = new DstTopNode(destAddr);
			m_srcValue = new SrcTopNode(srcValue);
		}

		~Line() {
			delete m_destAddr;
			delete m_srcValue;
		}

		void replaceNode(Node* node, Node* newNode) override {}

		std::list<ExprTree::Node*> getNodesList() override {
			return { getDstNode(), getSrcNode() };
		}

		T* getDstNode() {
			return m_destAddr->getNode();
		}

		ExprTree::Node* getSrcNode() {
			return m_srcValue->getNode();
		}

		T** getDstNodePtr() {
			return m_destAddr->getNodePtr();
		}

		ExprTree::Node** getSrcNodePtr() {
			return m_srcValue->getNodePtr();
		}

		BitMask64 getMask() override {
			return m_srcValue->getNode()->getMask();
		}

		ObjectHash::Hash getHash() override {
			return m_destAddr->getNode()->getHash() * 31 + m_srcValue->getNode()->getHash();
		}

		Node* clone() override {
			return new Line<T>(m_destAddr->getNode()->clone(), m_srcValue->getNode()->clone(), m_block);
		}

		std::string printDebug() override {
			return m_destAddr->getNode()->printDebug() + " = " + m_srcValue->getNode()->printDebug() + "\n";
		}
	};

	using SeqLine = Line<ExprTree::Node>;
	using SymbolAssignmentLine = Line<ExprTree::SymbolLeaf>;


	class Block
	{
	public:
		template<typename T = ExprTree::Node>
		class BlockTopNode : public TopNode<T>
		{
		public:
			Block* m_block;

			BlockTopNode(Block* block, ExprTree::Node* node = nullptr)
				: m_block(block), TopNode<T>(node)
			{}
		};

		class JumpTopNode : public BlockTopNode<ExprTree::ICondition>
		{
		public:
			JumpTopNode(Block* block)
				: BlockTopNode(block)
			{}
		};

		class ReturnTopNode : public BlockTopNode<ExprTree::Node>
		{
		public:
			ReturnTopNode(Block* block)
				: BlockTopNode(block)
			{}
		};

		class SeqLineTopNode : public BlockTopNode<SeqLine>
		{
		public:
			SeqLineTopNode(Block* block, SeqLine* line)
				: BlockTopNode(block, line)
			{}
		};

		class SymbolAssignmentLineTopNode : public BlockTopNode<SymbolAssignmentLine>
		{
		public:
			SymbolAssignmentLineTopNode(Block* block, SymbolAssignmentLine* line)
				: BlockTopNode(block, line)
			{}
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

		virtual std::list<ITopNode*> getAllTopNodes() {
			std::list<ITopNode*> result;
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
			return m_noJmpCond->getNode();
		}

		void setNoJumpCondition(ExprTree::ICondition* noJmpCond) {
			if (m_noJmpCond) {
				m_noJmpCond->clear();
			}
			m_noJmpCond->setNode(noJmpCond);
		}

		void addSeqLine(ExprTree::Node* destAddr, ExprTree::Node* srcValue) {
			m_seqLines.push_back(new SeqLineTopNode(this, new SeqLine(destAddr, srcValue, this)));
		}

		std::list<SeqLineTopNode*>& getSeqLines() {
			return m_seqLines;
		}

		void addSymbolAssignmentLine(ExprTree::SymbolLeaf* symbolLeaf, ExprTree::Node* srcValue) {
			m_symbolAssignmentLines.push_back(new SymbolAssignmentLineTopNode(this, new SymbolAssignmentLine(symbolLeaf, srcValue, this)));
		}

		std::list<SymbolAssignmentLineTopNode*>& getSymbolAssignmentLines() {
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
			if (cond && m_noJmpCond != nullptr) {
				result += "------> Condition: " + m_noJmpCond->getNode()->printDebug() + "\n";
			}
			printf("%s", result.c_str());
		}
	private:
		std::list<Block*> m_blocksReferencedTo;
		Block* m_nextNearBlock = nullptr;
		Block* m_nextFarBlock = nullptr;
		std::list<SeqLineTopNode*> m_seqLines;
		std::list<SymbolAssignmentLineTopNode*> m_symbolAssignmentLines;
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

		std::list<ITopNode*> getAllTopNodes() override {
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
			if (m_returnNode) {
				m_returnNode->clear();
			}
			m_returnNode->setNode(returnNode);
		}
	};
};
