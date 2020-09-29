#pragma once
#include "Graph/DecCodeGraph.h"
#include "Graph/DecCodeGraphBlockFlowIterator.h"
#include "PCode/DecRegisterFactory.h"
#include "Decompiler.h"

namespace CE::Decompiler
{
	class GraphBlockLinker
	{
		struct IncompleteBlock {
			ExtBitMask m_canReadMask;
			RegisterParts m_regParts;
			int m_symbolId = 0;
			int m_prevSymbolId = 0;
		};

		struct Request {
			int m_requiestId = 0;
			std::map<PrimaryTree::Block*, IncompleteBlock> m_incompleteBlocks;
			std::list<std::pair<int, ExprTree::SymbolLeaf*>> m_symbols;
		};

		std::map<PCode::RegisterId, Request> m_requests;
		Request* m_currentRequest = nullptr;
		DecompiledCodeGraph* m_decompiledGraph;
		Decompiler* m_decompiler;
	public:
		GraphBlockLinker(DecompiledCodeGraph* decompiledGraph, Decompiler* decompiler)
			: m_decompiledGraph(decompiledGraph), m_decompiler(decompiler)
		{}

		void start() {
			auto startBlock = m_decompiledGraph->getStartBlock();
			std::multiset<PrimaryTree::Block*> visitedBlocks;
			resolveExternalSymbols(startBlock, visitedBlocks);
			createSymbolAssignments();
		}

	private:
		void resolveExternalSymbols(PrimaryTree::Block* block, std::multiset<PrimaryTree::Block*>& visitedBlocks) {
			if (visitedBlocks.count(block) == block->getRefHighBlocksCount()) {
				processBlock(block, m_decompiler->m_decompiledBlocks[block].m_execBlockCtx);

				for (auto nextBlock : block->getNextBlocks()) {
					if (nextBlock->m_level <= block->m_level)
						continue;
					visitedBlocks.insert(nextBlock);
					resolveExternalSymbols(nextBlock, visitedBlocks);
				}
			}
		}

		void processBlock(PrimaryTree::Block* block, ExecutionBlockContext* ctx) {
			auto it = ctx->m_externalSymbols.begin();
			while(it != ctx->m_externalSymbols.end()) {
				auto& externalSymbol = **it;
				auto& reg = externalSymbol.m_regVarnode->m_register;
				initRequestByRegister(reg);

				auto regParts = externalSymbol.m_regParts;
				auto remainToReadMask = externalSymbol.m_needReadMask;
				findRegisterParts(block, reg, remainToReadMask, regParts);
				if (!regParts.empty()) { //mask should be 0 to continue(because requiared register has built well) but special cases could be [1], that's why we check change
					auto expr = CreateExprFromRegisterParts(regParts, reg.m_valueRangeMask);
					externalSymbol.m_symbolLeaf->replaceWith(expr); //todo: remove this, make special node where another replacing method will be implemented. On this step no replaceWith uses!
					delete externalSymbol.m_symbolLeaf->m_symbol;
					delete externalSymbol.m_symbolLeaf;
					it = ctx->m_externalSymbols.erase(it);
					ctx->m_resolvedExternalSymbols.insert(externalSymbol.m_regVarnode);
				}
				else {
					it++;
				}
			}
		}

		void initRequestByRegister(PCode::Register& reg) {
			auto regId = reg.getGenericId();
			if (m_requests.find(regId) == m_requests.end()) {
				m_requests[regId] = Request();
			}
			m_currentRequest = &m_requests[regId];
			m_currentRequest->m_requiestId++;
		}

		Decompiler::DecompiledBlockInfo* getDecompiledBlockInfo(PrimaryTree::Block* block) {
			auto it = m_decompiler->m_decompiledBlocks.find(block);
			if (it != m_decompiler->m_decompiledBlocks.end())
				return &it->second;
			return nullptr;
		}

		void findRegisterParts(PrimaryTree::Block* startBlock, const PCode::Register& reg, ExtBitMask& requestMask, RegisterParts& outRegParts) {
			std::set<PrimaryTree::Block*> handledBlocks;
			ExtBitMask needReadMask;
			ExtBitMask hasReadMask;
			bool isFlowForkState = false;
			PrimaryTree::Block* blockBeforeEnteringFlowForkState = nullptr;

			BlockFlowIterator blockFlowIterator(startBlock);
			while (!requestMask.isZero() && blockFlowIterator.hasNext()) {
				auto& blockInfo = blockFlowIterator.next();
				auto block = blockInfo.m_block;

				if (handledBlocks.find(block) == handledBlocks.end()) { //if not handled yet
					if (!isFlowForkState) {
						if (!blockFlowIterator.isStartBlock()) {
							gatherRegisterPartsInBlock(block, reg, requestMask, outRegParts);
							handledBlocks.insert(block);
						}

						//enter the new state
						if (block->getRefBlocksCount() >= 2) {
							isFlowForkState = true;
							blockBeforeEnteringFlowForkState = block;
							needReadMask = ExtBitMask();
							hasReadMask = ExtBitMask();
						}
					}
					else {
						gatherRegisterPartsInBlock(block, reg, requestMask, needReadMask, hasReadMask, blockInfo.m_notNeedToReadMask, blockInfo.hasMaxPressure());
						if (blockInfo.hasMaxPressure()) {
							hasReadMask = hasReadMask | blockInfo.m_notNeedToReadMask;
							//if we fully read the ambiguous part(=needReadMask) of the register requested or such part is absence(needReadMask=0) then exit the state
							if ((needReadMask & ~hasReadMask).isZero()) {
								if (!needReadMask.isZero()) {
									//(*) "needReadMask" may be != "mask" that results in anything like: localVar32 | (100 << 32)
									auto symbol = createSymbolForRequest(reg, needReadMask);
									if ((requestMask & ~needReadMask) != requestMask) {
										auto regSymbolPart = new RegisterPart(needReadMask, requestMask & needReadMask, symbol);
										outRegParts.push_back(regSymbolPart);
										requestMask = requestMask & ~needReadMask;
									}
								}
								//exit the state
								isFlowForkState = false;
								if (!requestMask.isZero()) {
									//(*) pass this block on another state
									blockFlowIterator.passThisBlockAgain();
									continue;
								}
							}
						}

						if (isFlowForkState) {
							if (block == blockBeforeEnteringFlowForkState)
								blockFlowIterator.m_considerLoop = false;
						}
						handledBlocks.insert(block);
					}
				}
				else {
					blockFlowIterator.m_considerLoop = false;
				}
			}
		}

		void gatherRegisterPartsInBlock(PrimaryTree::Block* block, const PCode::Register& reg, ExtBitMask& requestMask, RegisterParts& outRegParts) {
			if (auto decompiledBlockInfo = getDecompiledBlockInfo(block)) {
				auto regParts = decompiledBlockInfo->m_execBlockCtx->getRegisterParts(reg.getGenericId(), requestMask);
				outRegParts.insert(outRegParts.begin(), regParts.begin(), regParts.end());
			}
		}

		void gatherRegisterPartsInBlock(PrimaryTree::Block* block, const PCode::Register& reg, ExtBitMask requestMask, ExtBitMask& needReadMask, ExtBitMask& hasReadMask, ExtBitMask& notNeedToReadMask, bool hasMaxPressure) {
			int prevSymbolId = 0;
			ExtBitMask remainToReadMask;
			if (hasMaxPressure) {
				remainToReadMask = requestMask;
			}
			else {
				remainToReadMask = needReadMask & ~hasReadMask;
			}
			remainToReadMask = remainToReadMask & ~notNeedToReadMask;
			if (remainToReadMask.isZero())
				return;
			
			auto ctx = getDecompiledBlockInfo(block)->m_execBlockCtx;
			auto regParts = ctx->getRegisterParts(reg.getGenericId(), remainToReadMask, !hasMaxPressure);

			//if the block can be read somehow
			if (!regParts.empty()) {
				//think about that more ???
				if (hasMaxPressure) { //to symbols assignments be less
					exceptLocalVarParts(regParts, remainToReadMask);
				}

				auto incompleteBlock = createNewIncompleteBlock(block, regParts);
				incompleteBlock->m_prevSymbolId = prevSymbolId;
				if (hasMaxPressure) {
					hasReadMask = ~remainToReadMask;
				}
				else {
					needReadMask = needReadMask | incompleteBlock->m_canReadMask;
				}
				notNeedToReadMask = notNeedToReadMask | incompleteBlock->m_canReadMask;
			}
		}

		IncompleteBlock* createNewIncompleteBlock(PrimaryTree::Block* block, RegisterParts& regParts) {
			ExtBitMask canReadMask;
			for (auto regPart : regParts) {
				canReadMask = canReadMask | regPart->m_maskToChange;
			}

			//just mark the block as having been read
			IncompleteBlock incompleteBlock;
			incompleteBlock.m_regParts = regParts;
			incompleteBlock.m_canReadMask = canReadMask; //that is what read
			incompleteBlock.m_symbolId = m_currentRequest->m_requiestId;

			//find old block
			auto it = m_currentRequest->m_incompleteBlocks.find(block);
			if (it != m_currentRequest->m_incompleteBlocks.end()) {
				auto& incompleteOldBlock = it->second;
				incompleteBlock.m_prevSymbolId = incompleteOldBlock.m_symbolId;
			}

			//insert new block
			m_currentRequest->m_incompleteBlocks[block] = incompleteBlock;
			return &m_currentRequest->m_incompleteBlocks[block];
		}

		void exceptLocalVarParts(RegisterParts& regParts, ExtBitMask& remainToReadMask) {
			for (auto it = regParts.begin(); it != regParts.end(); it++) {
				if (auto symbolLeaf = dynamic_cast<ExprTree::SymbolLeaf*>((*it)->m_expr)) {
					if (auto symbol = dynamic_cast<Symbol::LocalVariable*>(symbolLeaf->m_symbol)) {
						remainToReadMask = remainToReadMask | (*it)->m_maskToChange;
						it = std::prev(regParts.erase(it));
					}
				}
			}
		}

		ExprTree::INode* createSymbolForRequest(const PCode::Register& reg, ExtBitMask needReadMask) {
			auto& regSymbol = *m_currentRequest;
			std::set<int> prevSymbolIds;
			for (auto& it : regSymbol.m_incompleteBlocks) {
				if (it.second.m_prevSymbolId) {
					if (prevSymbolIds.find(it.second.m_prevSymbolId) == prevSymbolIds.end()) {
						for (auto& it2 : regSymbol.m_incompleteBlocks) { //if sets intersect
							if (it.second.m_prevSymbolId == it2.second.m_symbolId) { //create method or flag
								it2.second.m_symbolId = it.second.m_symbolId;
							}
						}
						prevSymbolIds.insert(it.second.m_prevSymbolId);
					}
					it.second.m_prevSymbolId = 0;
				}
			}

			auto symbol = new Symbol::LocalVariable(needReadMask);
			m_decompiledGraph->addSymbol(symbol);
			auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
			regSymbol.m_symbols.push_back(std::make_pair(regSymbol.m_requiestId, symbolLeaf));

			if (!prevSymbolIds.empty()) {
				for (auto it = regSymbol.m_symbols.begin(); it != regSymbol.m_symbols.end(); it++) {
					auto prevSymbolId = it->first;
					auto prevSymbolLeaf = it->second;
					if (prevSymbolIds.find(prevSymbolId) != prevSymbolIds.end()) {
						prevSymbolLeaf->replaceWith(symbolLeaf);
						delete prevSymbolLeaf->m_symbol;
						delete prevSymbolLeaf;
						regSymbol.m_symbols.erase(it);
					}
				}
			}

			return symbolLeaf;
		}

		void createSymbolAssignments() {
			for (const auto& it : m_requests) {
				auto& regSymbol = it.second;
				for (auto symbol : regSymbol.m_symbols) {
					for (const auto& it2 : regSymbol.m_incompleteBlocks) {
						auto decBlock = it2.first;
						auto& blockRegSymbol = it2.second;
						if (symbol.first == blockRegSymbol.m_symbolId) {
							auto symbolLeaf = symbol.second;
							auto regParts = blockRegSymbol.m_regParts;

							auto localVar = dynamic_cast<Symbol::LocalVariable*>(symbolLeaf->m_symbol);
							auto maskToChange = localVar->getMask() & ~blockRegSymbol.m_canReadMask;

							if (maskToChange != 0) {
								//localVar1 = (localVar1 & 0xFF00) | 1
								regParts.push_back(new RegisterPart(localVar->getMask(), maskToChange, symbolLeaf));
							}

							auto expr = CreateExprFromRegisterParts(regParts, localVar->getMask());
							decBlock->addSymbolAssignmentLine(symbolLeaf, expr);
						}
					}
				}
			}
		}
	};
};