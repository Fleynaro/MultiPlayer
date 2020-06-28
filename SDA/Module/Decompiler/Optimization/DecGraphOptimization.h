#pragma once
#include "ExprOptimization.h"
#include "../DecCodeGraph.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	class MemorySymbolization
	{
	public:
		MemorySymbolization(DecompiledCodeGraph* decGraph)
			: m_decGraph(decGraph)
		{}

		void start() {
			for (auto decBlock : m_decGraph->getDecompiledBlocks()) {
				for (auto line : decBlock->getLines()) {
					detectAllStackMemoryAddressesInExpr(line->m_destAddr);
					detectAllStackMemoryAddressesInExpr(line->m_srcValue);
				}
				if (decBlock->m_noJmpCond != nullptr) {
					detectAllStackMemoryAddressesInExpr(decBlock->m_noJmpCond);
				}
			}

			createSymbol(m_stackMemory, [](int offset, int size) { return new Symbol::StackVariable(offset, size); });
			createSymbol(m_stackParameterMemory, [](int offset, int size) { return new Symbol::ParameterVariable(0, size); });
			createSymbol(m_globalMemory, [](int offset, int size) { return new Symbol::GlobalVariable(offset, size); });
		}
	private:
		DecompiledCodeGraph* m_decGraph;

		struct MemoryAddressInfo {
			std::set<ExprTree::OperationalNode*> m_exprs;
		};
		std::map<int, MemoryAddressInfo> m_stackMemory;
		std::map<int, MemoryAddressInfo> m_stackParameterMemory;
		std::map<int, MemoryAddressInfo> m_globalMemory;

		void createSymbol(const std::map<int, MemoryAddressInfo>& memory, const std::function<Symbol::Variable*(int, int)>& constructor) {
			for (const auto& it : memory) {
				auto offset = it.first;
				const auto& memoryAddressInfo = it.second;

				int maxSize = 0;
				for (auto expr : memoryAddressInfo.m_exprs) {
					if (auto readSizeNumber = dynamic_cast<ExprTree::NumberLeaf*>(expr->m_rightNode)) {
						if (readSizeNumber->m_value > maxSize) {
							maxSize = (int)readSizeNumber->m_value;
						}
					}
				}

				auto symbol = constructor(offset, maxSize);
				auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);

				for (auto expr : memoryAddressInfo.m_exprs) {
					ExprTree::Node* newExpr = symbolLeaf;
					if (auto readSizeNumber = dynamic_cast<ExprTree::NumberLeaf*>(expr->m_rightNode)) {
						if (readSizeNumber->m_value < maxSize) {
							auto mask = ((uint64_t)1 << (readSizeNumber->m_value * 8)) - 1;
							newExpr = new ExprTree::OperationalNode(symbolLeaf, new ExprTree::NumberLeaf(mask), ExprTree::And);
						}
					}
					expr->replaceWith(newExpr);
					delete expr;
				}
			}
		}

		void detectAllStackMemoryAddressesInExpr(ExprTree::Node* node) {
			auto list = GetNextOperationalsNodesToOpimize(node);
			for (auto expr : list) {
				detectAllStackMemoryAddressesInExpr(expr);
			}
		}

		void detectAllStackMemoryAddressesInExpr(ExprTree::OperationalNode* expr) {
			using namespace ExprTree;
			auto list = GetNextOperationalsNodesToOpimize(expr);
			for (auto it : list) {
				detectAllStackMemoryAddressesInExpr(it);
			}

			if (expr->m_operation == readValue) {
				if (auto addrExpr = dynamic_cast<ExprTree::OperationalNode*>(expr->m_leftNode)) {
					if (addrExpr->m_operation == Add) {
						if (auto symbolLeaf = dynamic_cast<ExprTree::SymbolLeaf*>(addrExpr->m_leftNode)) {
							if (auto regVarSymbol = dynamic_cast<Symbol::RegisterVariable*>(symbolLeaf->m_symbol)) {
								if (auto offsetNode = dynamic_cast<ExprTree::NumberLeaf*>(addrExpr->m_rightNode)) {
									if (regVarSymbol->m_register == ZYDIS_REGISTER_RSP) {
										auto offset = (int)offsetNode->m_value;
										if (true || offset < 0) {
											if (m_stackMemory.find(offset) == m_stackMemory.end()) {
												m_stackMemory[offset] = MemoryAddressInfo();
											}
											m_stackMemory[offset].m_exprs.insert(expr);
										}
										else if (offset > 0) { //todo: remove?
											if (m_stackParameterMemory.find(offset) == m_stackParameterMemory.end()) {
												m_stackParameterMemory[offset] = MemoryAddressInfo();
											}
											m_stackParameterMemory[offset].m_exprs.insert(expr);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	};

	static void OptimizeConditionDecBlock(Block* block) {
		if (!block->isCondition())
			return;
		auto delta = block->m_nextNearBlock->m_level - block->m_level;
		if (delta >= 1 && delta < block->m_nextFarBlock->m_level - block->m_level)
			return;
		std::swap(block->m_nextNearBlock, block->m_nextFarBlock);
		block->m_noJmpCond->inverse();
	}

	static Block* JoinCondition(Block* block) {
		if (!block->isCondition())
			return nullptr;

		auto removedBlock = block->m_nextNearBlock;
		auto mutualBlock = block->m_nextFarBlock;
		if (!removedBlock->hasNoCode() || !removedBlock->isCondition() || removedBlock->m_blocksReferencedTo.size() != 1)
			return nullptr;

		Block* targetBlock = nullptr;
		auto removedBlockNoJmpCond = removedBlock->m_noJmpCond;
		if (removedBlock->m_nextNearBlock == mutualBlock) {
			targetBlock = removedBlock->m_nextFarBlock;
			removedBlockNoJmpCond->inverse();
		}
		else if (removedBlock->m_nextFarBlock == mutualBlock) {
			targetBlock = removedBlock->m_nextNearBlock;
		}
		if (!targetBlock)
			return nullptr;

		block->setJumpCondition(new ExprTree::CompositeCondition(block->m_noJmpCond, removedBlockNoJmpCond, ExprTree::CompositeCondition::And));
		block->m_nextNearBlock = targetBlock;
		removedBlock->m_blocksReferencedTo.remove(block);
		return removedBlock;
	}

	static void OptimizeDecompiledGraph(DecompiledCodeGraph* decGraph) {
		//join conditions and remove useless blocks
		for (auto it = decGraph->getDecompiledBlocks().rbegin(); it != decGraph->getDecompiledBlocks().rend(); it++) {
			auto block = *it;
			while (auto removedBlock = JoinCondition(block)) {
				OptimizeConditionDecBlock(block);
				decGraph->getDecompiledBlocks().remove(removedBlock);
				delete removedBlock;
			}
		}

		//recalculate levels because some blocks can be removed
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			decBlock->m_level = 0;
		}
		std::list<PrimaryTree::Block*> path;
		DecompiledCodeGraph::CalculateLevelsForDecBlocks(decGraph->getStartBlock(), path);

		//optimize expressions
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto line : decBlock->getLines()) {
				Optimization::Optimize(line->m_destAddr);
				Optimization::Optimize(line->m_srcValue);
			}
			if (decBlock->m_noJmpCond != nullptr) {
				Optimization::Optimize(decBlock->m_noJmpCond);
			}
		}

		MemorySymbolization memorySymbolization(decGraph);
		memorySymbolization.start();
	}
};