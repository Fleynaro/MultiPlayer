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
			int m_localVarId = 0;
			int m_prevLocalVarId = 0;
		};

		struct Request {
			int m_requiestId = 0;
			PCode::Register m_register;
			std::map<PrimaryTree::Block*, IncompleteBlock> m_incompleteBlocks;
			std::list<std::pair<int, ExprTree::SymbolLeaf*>> m_localVars;

			Request(PCode::Register reg)
				: m_register(reg)
			{}
		};

		std::list<Request> m_requests;
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
			createLocalVarAssignmentsInIncompleteBlocks();
		}

	private:
		Decompiler::DecompiledBlockInfo* getDecompiledBlockInfo(PrimaryTree::Block* block) {
			auto it = m_decompiler->m_decompiledBlocks.find(block);
			if (it != m_decompiler->m_decompiledBlocks.end())
				return &it->second;
			return nullptr;
		}

		void resolveExternalSymbols(PrimaryTree::Block* block, std::multiset<PrimaryTree::Block*>& visitedBlocks) {
			if (visitedBlocks.count(block) == block->getRefHighBlocksCount()) {
				processBlock(block, getDecompiledBlockInfo(block)->m_execBlockCtx);

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
			while (it != ctx->m_externalSymbols.end()) {
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
			m_currentRequest = nullptr;
			for (auto& request : m_requests) {
				if (request.m_register.intersect(reg)) {
					m_currentRequest = &request;
				}
			}
			if (!m_currentRequest) {
				m_requests.push_back(Request(reg));
				m_currentRequest = &(*std::prev(m_requests.end()));
			}
			m_currentRequest->m_requiestId++;
		}

		void findRegisterParts(PrimaryTree::Block* startBlock, const PCode::Register& reg, ExtBitMask& requestMask, RegisterParts& outRegParts) {
			std::set<PrimaryTree::Block*> handledBlocks;
			ExtBitMask needReadMask;
			ExtBitMask hasReadMask;
			bool isFlowForkState = false;
			PrimaryTree::Block* blockBeforeEnteringFlowForkState = nullptr;

			BlockFlowIterator blockFlowIterator(startBlock, ExtBitMask(BitMask64(), requestMask.getIndex()));
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
							needReadMask = ExtBitMask(BitMask64(), requestMask.getIndex());
							hasReadMask = ExtBitMask(BitMask64(), requestMask.getIndex());
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
									auto localVarLeaf = createLocalVar(needReadMask);
									std::set<int> prevSymbolIds;
									joinIncompleteBlocksOfCurAndPrevRequests(prevSymbolIds);
									replacePrevLocalVars(prevSymbolIds, localVarLeaf);

									if ((requestMask & ~needReadMask) != requestMask) {
										auto regSymbolPart = new RegisterPart(needReadMask, requestMask & needReadMask, localVarLeaf);
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
			ExtBitMask remainToReadMask;
			if (hasMaxPressure) {
				remainToReadMask = needReadMask & ~hasReadMask;
			}
			else {
				remainToReadMask = requestMask;
			}
			remainToReadMask = remainToReadMask & ~notNeedToReadMask;
			if (remainToReadMask.isZero())
				return;

			auto ctx = getDecompiledBlockInfo(block)->m_execBlockCtx;
			auto regParts = ctx->getRegisterParts(reg.getGenericId(), remainToReadMask, !hasMaxPressure);
			if (hasMaxPressure) { //to symbols assignments be less
				exceptLocalVarParts(regParts, remainToReadMask);
			}

			//if the block can be read somehow
			if (!regParts.empty()) {
				auto incompleteBlock = createNewIncompleteBlock(block, regParts, ExtBitMask(BitMask64(), requestMask.getIndex()));
				if (hasMaxPressure) {
					hasReadMask = ~remainToReadMask;
				}
				else {
					needReadMask = needReadMask | incompleteBlock->m_canReadMask;
				}
				notNeedToReadMask = notNeedToReadMask | incompleteBlock->m_canReadMask;
			}
		}

		IncompleteBlock* createNewIncompleteBlock(PrimaryTree::Block* block, RegisterParts& regParts, ExtBitMask canReadMask) {
			for (auto regPart : regParts) {
				canReadMask = canReadMask | regPart->m_maskToChange;
			}

			//just mark the block as having been read
			IncompleteBlock incompleteBlock;
			incompleteBlock.m_regParts = regParts;
			incompleteBlock.m_canReadMask = canReadMask; //that is what read
			incompleteBlock.m_localVarId = m_currentRequest->m_requiestId;

			//find old block
			auto it = m_currentRequest->m_incompleteBlocks.find(block);
			if (it != m_currentRequest->m_incompleteBlocks.end()) {
				auto& incompleteOldBlock = it->second;
				incompleteBlock.m_prevLocalVarId = incompleteOldBlock.m_localVarId;
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

		ExprTree::SymbolLeaf* createLocalVar(ExtBitMask needReadMask) {
			auto symbol = new Symbol::LocalVariable(needReadMask);
			m_decompiledGraph->addSymbol(symbol);
			auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
			m_currentRequest->m_localVars.push_back(std::make_pair(m_currentRequest->m_requiestId, symbolLeaf));
			return symbolLeaf;
		}

		void joinIncompleteBlocksOfCurAndPrevRequests(std::set<int>& prevSymbolIds) {
			for (auto& pair : m_currentRequest->m_incompleteBlocks) {
				auto& incompleteBlock = pair.second;
				auto prevSymbolId = incompleteBlock.m_prevLocalVarId;
				if (prevSymbolId) {
					if (prevSymbolIds.find(prevSymbolId) == prevSymbolIds.end()) {
						for (auto& pair : m_currentRequest->m_incompleteBlocks) {
							auto& incompleteBlock2 = pair.second;
							//if sets intersect
							if (prevSymbolId == incompleteBlock2.m_localVarId) {
								//change old symbold id to new one
								incompleteBlock2.m_localVarId = incompleteBlock.m_localVarId;
							}
						}
						prevSymbolIds.insert(prevSymbolId);
					}
					incompleteBlock.m_prevLocalVarId = 0;
				}
			}
		}

		void replacePrevLocalVars(const std::set<int>& prevSymbolIds, ExprTree::SymbolLeaf* localVarLeaf) {
			for (auto it = m_currentRequest->m_localVars.begin(); it != m_currentRequest->m_localVars.end(); it++) {
				auto prevSymbolId = it->first;
				auto prevSymbolLeaf = it->second;
				if (prevSymbolIds.find(prevSymbolId) != prevSymbolIds.end()) {
					prevSymbolLeaf->replaceWith(localVarLeaf);
					delete prevSymbolLeaf->m_symbol;
					delete prevSymbolLeaf;
					it = std::prev(m_currentRequest->m_localVars.erase(it));
				}
			}
		}

		void createLocalVarAssignmentsInIncompleteBlocks() {
			for (const auto& request : m_requests)
			{
				for (auto pair : request.m_localVars)
				{
					auto localVarId = pair.first;
					auto localVarLeaf = pair.second;

					for (const auto& pair2 : request.m_incompleteBlocks) {
						auto block = pair2.first;
						auto incompleteBlock = &pair2.second;

						if (localVarId == incompleteBlock->m_localVarId) {
							createLocalVarAssignment(block, incompleteBlock, localVarLeaf);
						}
					}
				}
			}
		}

		void createLocalVarAssignment(PrimaryTree::Block* block, const IncompleteBlock* incompleteBlock, ExprTree::SymbolLeaf* localVarLeaf) {
			auto regParts = incompleteBlock->m_regParts;
			auto localVar = dynamic_cast<Symbol::LocalVariable*>(localVarLeaf->m_symbol);
			auto localVarMask = localVar->getMask();

			auto remainingMask = localVarMask & ~incompleteBlock->m_canReadMask;
			if (!remainingMask.isZero()) {
				//localVar1 = (localVar1 & 0xFF00) | 1
				regParts.push_back(new RegisterPart(localVarMask, remainingMask, localVarLeaf));
			}

			auto expr = CreateExprFromRegisterParts(regParts, localVarMask);
			block->addSymbolAssignmentLine(localVarLeaf, expr);
		}
	};
};