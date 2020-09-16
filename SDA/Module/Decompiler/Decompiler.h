#pragma once
#include "Graph/DecCodeGraph.h"
#include "Graph/DecCodeGraphBlockFlowIterator.h"
#include "PCode/Interpreter/PCodeInterpreter.h"
#include "PCode/DecRegisterFactory.h"

namespace CE::Decompiler
{
	class Decompiler
	{
		struct DecompiledBlockInfo {
			AsmGraphBlock* m_asmBlock = nullptr;
			PrimaryTree::Block* m_decBlock = nullptr;
			ExecutionBlockContext* m_execBlockCtx = nullptr;

			DecompiledBlockInfo() = default;

			bool isDecompiled() {
				return m_decBlock != nullptr;
			}
		};
	public:
		DecompiledCodeGraph* m_decompiledGraph;
		std::function<FunctionCallInfo(int, ExprTree::INode*)> m_funcCallInfoCallback;

		Decompiler(DecompiledCodeGraph* decompiledGraph, AbstractRegisterFactory* registerFactory, std::function<FunctionCallInfo(int, ExprTree::INode*)> funcCallInfoCallback)
			: m_decompiledGraph(decompiledGraph), m_registerFactory(registerFactory), m_funcCallInfoCallback(funcCallInfoCallback)
		{
			m_instructionInterpreter = new PCode::InstructionInterpreter;
		}

		~Decompiler() {
			delete m_instructionInterpreter;

			for (auto& it : m_decompiledBlocks) {
				delete it.second.m_execBlockCtx;
			}
		}

		void start() {
			decompileAllBlocks();
			setAllBlocksLinks();
			buildDecompiledGraph();

			GraphBlockLinker graphBlockLinker(this);
			graphBlockLinker.start();
			m_decompiledGraph->generateSymbolIds();
		}

		void buildDecompiledGraph();

		AbstractRegisterFactory* getRegisterFactory() {
			return m_registerFactory;
		}
	private:
		AbstractRegisterFactory* m_registerFactory;
		PCode::InstructionInterpreter* m_instructionInterpreter;
		std::map<AsmGraphBlock*, PrimaryTree::Block*> m_asmToDecBlocks;
		std::map<PrimaryTree::Block*, DecompiledBlockInfo> m_decompiledBlocks;
		
		void decompileAllBlocks() {
			for (auto& pair : m_decompiledGraph->getAsmGraph()->getBlocks()) {
				auto asmBlock = &pair.second;
				DecompiledBlockInfo decompiledBlock;
				decompiledBlock.m_asmBlock = asmBlock;
				if (!asmBlock->getNextNearBlock() && !asmBlock->getNextFarBlock()) {
					decompiledBlock.m_decBlock = new PrimaryTree::EndBlock(m_decompiledGraph, asmBlock->m_level);
				}
				else {
					decompiledBlock.m_decBlock = new PrimaryTree::Block(m_decompiledGraph, asmBlock->m_level);
				}
				decompiledBlock.m_execBlockCtx = new ExecutionBlockContext(this);
				decompiledBlock.m_decBlock->m_name = Generic::String::NumberToHex(asmBlock->ID);

				//execute the instructions and then change the execution context
				for (auto instr : asmBlock->getInstructions()) {
					m_instructionInterpreter->execute(decompiledBlock.m_decBlock, decompiledBlock.m_execBlockCtx, instr);
				}

				m_asmToDecBlocks[asmBlock] = decompiledBlock.m_decBlock;
				m_decompiledBlocks[decompiledBlock.m_decBlock] = decompiledBlock;
			}
		}

		void setAllBlocksLinks() {
			for (const auto& it : m_decompiledBlocks) {
				auto& decBlockInfo = it.second;
				if (auto nextAsmBlock = decBlockInfo.m_asmBlock->getNextNearBlock()) {
					decBlockInfo.m_decBlock->setNextNearBlock(m_asmToDecBlocks[nextAsmBlock]);
				}
				if (auto nextAsmBlock = decBlockInfo.m_asmBlock->getNextFarBlock()) {
					decBlockInfo.m_decBlock->setNextFarBlock(m_asmToDecBlocks[nextAsmBlock]);
				}
			}
		}

		friend class GraphBlockLinker;
		class GraphBlockLinker
		{
			struct BlockRegSymbol {
				ExtBitMask m_canReadMask;
				RegisterParts m_regParts;
				int m_symbolId = 0;
				int m_prevSymbolId = 0;
			};

			struct RegSymbol {
				std::map<PrimaryTree::Block*, BlockRegSymbol> m_blocks;
				std::list<std::pair<int, ExprTree::SymbolLeaf*>> m_symbols;
				int m_requiestId = 0;
			};

			std::map<PCode::RegisterId, RegSymbol> m_registersToSymbol;
			RegSymbol* m_curRegSymbol = nullptr;
			Decompiler* m_decompiler;
		public:
			GraphBlockLinker(Decompiler* decompiler)
				: m_decompiler(decompiler)
			{}

			void start() {
				auto startBlock = m_decompiler->m_decompiledGraph->getStartBlock();
				std::multiset<PrimaryTree::Block*> visitedBlocks;
				resolveExternalSymbols(startBlock, visitedBlocks);
				createSymbolAssignments();
			}

		private:
			void resolveExternalSymbols(PrimaryTree::Block* block, std::multiset<PrimaryTree::Block*>& visitedBlocks) {
				if (visitedBlocks.count(block) == block->getRefHighBlocksCount()) {
					auto ctx = m_decompiler->m_decompiledBlocks[block].m_execBlockCtx;
					for (auto it = ctx->m_externalSymbols.begin(); it != ctx->m_externalSymbols.end(); it++) {
						auto& externalSymbol = **it;
						auto& reg = externalSymbol.m_regVarnode->m_register;
						auto regId = reg.getGenericId(); //ah/al and xmm?
						if (m_registersToSymbol.find(regId) == m_registersToSymbol.end()) {
							m_registersToSymbol[regId] = RegSymbol();
						}
						m_curRegSymbol = &m_registersToSymbol[regId];
						m_curRegSymbol->m_requiestId++;

						auto regParts = externalSymbol.m_regParts;
						auto remainToReadMask = externalSymbol.m_needReadMask;
						requestRegisterParts(block, reg, remainToReadMask, regParts);
						if (remainToReadMask != externalSymbol.m_needReadMask || !regParts.empty()) { //mask should be 0 to continue(because requiared register has built well) but special cases could be [1], that's why we check change
							auto expr = CreateExprFromRegisterParts(regParts, reg.m_valueRangeMask);
							externalSymbol.m_symbolLeaf->replaceWith(expr); //todo: remove this, make special node where another replacing method will be implemented. On this step no replaceWith uses!
							delete externalSymbol.m_symbolLeaf->m_symbol;
							delete externalSymbol.m_symbolLeaf;
							ctx->m_externalSymbols.erase(it);
							ctx->m_resolvedExternalSymbols.insert(externalSymbol.m_regVarnode);
						}
					}

					for (auto nextBlock : block->getNextBlocks()) {
						if (nextBlock->m_level <= block->m_level)
							continue;
						visitedBlocks.insert(nextBlock);
						resolveExternalSymbols(nextBlock, visitedBlocks);
					}
				}
			}

			void requestRegisterParts(PrimaryTree::Block* startBlock, const PCode::Register& reg, ExtBitMask& mask, RegisterParts& outRegParts) {
				std::set<PrimaryTree::Block*> handledBlocks;
				ExtBitMask needReadMask;
				ExtBitMask hasReadMask;
				bool isFlowForkState = false;
				PrimaryTree::Block* blockBeforeEnteringFlowForkState = nullptr;

				BlockFlowIterator blockFlowIterator(startBlock);
				while (!mask.isZero() && blockFlowIterator.hasNext()) {
					auto& blockInfo = blockFlowIterator.next();
					auto block = blockInfo.m_block;

					if (handledBlocks.find(block) == handledBlocks.end()) { //if not handled yet
						if (!isFlowForkState) {
							if (!blockFlowIterator.isStartBlock()) {
								gatherRegisterPartsInBlock(block, reg, mask, outRegParts);
								handledBlocks.insert(block);
							}

							if (block->getRefBlocksCount() >= 2) {
								isFlowForkState = true;
								blockBeforeEnteringFlowForkState = block;
								needReadMask = ExtBitMask();
								hasReadMask = ExtBitMask();
							}
						}
						else {
							gatherRegisterPartsInBlock(block, reg, mask, needReadMask, hasReadMask, blockInfo.m_notNeedToReadMask, blockInfo.hasMaxPressure());
							if (blockInfo.hasMaxPressure()) {
								if ((needReadMask & ~hasReadMask).isZero()) {
									if (!needReadMask.isZero()) {
										//"needReadMask" may be != "mask" that results in anything like: localVar32 | (100 << 32)
										auto symbol = createSymbolForRequest(reg, needReadMask);
										if ((mask & ~needReadMask) != mask) {
											auto regPart = new RegisterPart(needReadMask, mask & needReadMask, symbol);
											outRegParts.push_back(regPart);
											mask = mask & ~needReadMask;
										}
									}
									//exit the state
									isFlowForkState = false;
									if (!mask.isZero()) {
										//pass this block on another state
										blockFlowIterator.passThisBlockRepeatly();
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

			void gatherRegisterPartsInBlock(PrimaryTree::Block* block, const PCode::Register& reg, ExtBitMask& mask, RegisterParts& outRegParts) {
				auto it = m_decompiler->m_decompiledBlocks.find(block);
				if (it != m_decompiler->m_decompiledBlocks.end()) {
					auto ctx = it->second.m_execBlockCtx;
					auto regParts = ctx->getRegisterParts(reg.getGenericId(), mask);
					outRegParts.insert(outRegParts.begin(), regParts.begin(), regParts.end());
					if (mask.isZero()) {
						return;
					}
				}
			}

			void gatherRegisterPartsInBlock(PrimaryTree::Block* block, const PCode::Register& reg, ExtBitMask requestMask, ExtBitMask& needReadMask, ExtBitMask& hasReadMask, ExtBitMask& notNeedToReadMask, bool hasMaxPressure) {
				auto remainToReadMask = needReadMask & ~hasReadMask & ~notNeedToReadMask;
				requestMask = requestMask & ~notNeedToReadMask;
				int prevSymbolId = 0;

				//if the block has been already passed
				auto it = m_curRegSymbol->m_blocks.find(block);
				if (it != m_curRegSymbol->m_blocks.end()) {
					auto& blockRegSymbol = it->second;
					if ((requestMask & blockRegSymbol.m_canReadMask).isZero()) {
						//just change mask
						blockRegSymbol.m_prevSymbolId = blockRegSymbol.m_symbolId;
						blockRegSymbol.m_symbolId = m_curRegSymbol->m_requiestId;
						if (hasMaxPressure) {
							hasReadMask = ~(remainToReadMask & ~blockRegSymbol.m_canReadMask);
						}
						else {
							needReadMask = needReadMask | blockRegSymbol.m_canReadMask;
						}
						return;
					}
					else {
						//it means there're some new parts of registers that have to be read
						prevSymbolId = blockRegSymbol.m_symbolId;
					}
				}

				//handle the block first time
				auto ctx = m_decompiler->m_decompiledBlocks[block].m_execBlockCtx;
				auto mask = hasMaxPressure ? remainToReadMask : requestMask;
				auto regParts = ctx->getRegisterParts(reg.getGenericId(), mask, !hasMaxPressure);

				//think about that more ???
				if (hasMaxPressure) { //to symbols assignments be less
					for (auto it = regParts.begin(); it != regParts.end(); it++) {
						if (auto symbolLeaf = dynamic_cast<ExprTree::SymbolLeaf*>((*it)->m_expr)) {
							if (auto symbol = dynamic_cast<Symbol::LocalVariable*>(symbolLeaf->m_symbol)) {
								mask = mask | (*it)->m_maskToChange;
								regParts.erase(it);
							}
						}
					}
				}

				//if the block can be read somehow
				if (!regParts.empty()) {
					ExtBitMask canReadMask;
					for (auto regPart : regParts) {
						canReadMask = canReadMask | regPart->m_maskToChange;
					}

					if (hasMaxPressure) {
						hasReadMask = ~mask;
					}
					else {
						needReadMask = needReadMask | canReadMask;
					}

					//just mark the block as having been read
					BlockRegSymbol blockRegSymbol;
					blockRegSymbol.m_regParts = regParts;
					blockRegSymbol.m_canReadMask = canReadMask; //that is what read
					blockRegSymbol.m_symbolId = m_curRegSymbol->m_requiestId;
					blockRegSymbol.m_prevSymbolId = prevSymbolId;
					m_curRegSymbol->m_blocks[block] = blockRegSymbol;
					notNeedToReadMask = canReadMask;
				}
			}

			ExprTree::INode* createSymbolForRequest(const PCode::Register& reg, ExtBitMask needReadMask) {
				auto& regSymbol = *m_curRegSymbol;
				std::set<int> prevSymbolIds;
				for (auto& it : regSymbol.m_blocks) {
					if (it.second.m_prevSymbolId) {
						if (prevSymbolIds.find(it.second.m_prevSymbolId) == prevSymbolIds.end()) {
							for (auto& it2 : regSymbol.m_blocks) { //if sets intersect
								if (it2.second.m_symbolId == it.second.m_prevSymbolId) {
									it2.second.m_symbolId = it.second.m_symbolId;
								}
							}
						}
						prevSymbolIds.insert(it.second.m_prevSymbolId);
						it.second.m_prevSymbolId = 0;
					}
				}

				auto symbol = new Symbol::LocalVariable(needReadMask);
				m_decompiler->m_decompiledGraph->addSymbol(symbol);
				auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
				regSymbol.m_symbols.push_back(std::make_pair(regSymbol.m_requiestId, symbolLeaf));

				if (!prevSymbolIds.empty()) {
					for (auto it = regSymbol.m_symbols.begin(); it != regSymbol.m_symbols.end(); it++) {
						auto prevSymbolId = it->first;
						auto prevSymbolLeaf = it->second;
						if (prevSymbolIds.find(prevSymbolId) != prevSymbolIds.end()) {
							it->second->replaceWith(symbolLeaf);
							delete prevSymbolLeaf->m_symbol;
							delete prevSymbolLeaf;
							regSymbol.m_symbols.erase(it);
						}
					}
				}

				return symbolLeaf;
			}

			void createSymbolAssignments() {
				for (const auto& it : m_registersToSymbol) {
					auto& regSymbol = it.second;
					for (auto symbol : regSymbol.m_symbols) {
						for (const auto& it2 : regSymbol.m_blocks) {
							auto decBlock = it2.first;
							auto& blockRegSymbol = it2.second;
							if (symbol.first == blockRegSymbol.m_symbolId) {
								auto symbolLeaf = symbol.second;
								auto regParts = blockRegSymbol.m_regParts;

								auto symbolMask = dynamic_cast<Symbol::Variable*>(symbolLeaf->m_symbol)->getMask();
								auto maskToChange = symbolMask & ~blockRegSymbol.m_canReadMask;

								if (maskToChange != 0) {
									regParts.push_back(new RegisterPart(symbolMask, maskToChange, symbolLeaf));
								}

								auto expr = CreateExprFromRegisterParts(regParts, symbolMask);
								decBlock->addSymbolAssignmentLine(symbolLeaf, expr);
							}
						}
					}
				}
			}
		};
	};
};