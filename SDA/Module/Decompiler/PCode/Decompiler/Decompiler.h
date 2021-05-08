#pragma once
#include "DecExecContext.h"
#include "PCodeInterpreter.h"

namespace CE::Decompiler
{
	class Decompiler
	{
	public:
		struct LocalVarInfo {
			PCode::Register m_register;
			std::set<ExecContext*> m_execCtxs;

			// need to change the size of local var
			int m_countOfInstances = 0;
			BitMask64 m_instanceMask;
		};

		std::map<Symbol::LocalVariable*, LocalVarInfo> m_localVars;

	private:
		struct DecompiledBlockInfo {
			PCodeBlock* m_pcodeBlock = nullptr;
			PrimaryTree::Block* m_decBlock = nullptr;
			ExecContext* m_execCtx = nullptr;
			int m_enterCount = 0;
			int m_versionOfDecompiling = 0;
			bool m_isDecompiled = false;
		};

		AbstractRegisterFactory* m_registerFactory;
		int m_loopsCount = 0;

	public:
		DecompiledCodeGraph* m_decompiledGraph;
		ReturnInfo m_returnInfo;
		std::function<FunctionCallInfo(int, ExprTree::INode*)> m_funcCallInfoCallback;
		std::map<PCodeBlock*, DecompiledBlockInfo> m_decompiledBlocks;

		Decompiler(DecompiledCodeGraph* decompiledGraph, AbstractRegisterFactory* registerFactory, ReturnInfo returnInfo, std::function<FunctionCallInfo(int, ExprTree::INode*)> funcCallInfoCallback)
			: m_decompiledGraph(decompiledGraph), m_registerFactory(registerFactory), m_returnInfo(returnInfo), m_funcCallInfoCallback(funcCallInfoCallback)
		{}

		void start() {
			// prepare
			for (auto pcodeBlock : m_decompiledGraph->getFuncGraph()->getBlocks()) {
				PrimaryTree::Block* newDecBlock;
				if (!pcodeBlock->getNextNearBlock() && !pcodeBlock->getNextFarBlock()) {
					newDecBlock = new PrimaryTree::EndBlock(m_decompiledGraph, pcodeBlock, pcodeBlock->m_level);
				}
				else {
					newDecBlock = new PrimaryTree::Block(m_decompiledGraph, pcodeBlock, pcodeBlock->m_level);
				}

				DecompiledBlockInfo decompiledBlock;
				decompiledBlock.m_pcodeBlock = pcodeBlock;
				decompiledBlock.m_execCtx = new ExecContext(this, pcodeBlock);
				decompiledBlock.m_decBlock = newDecBlock;
				decompiledBlock.m_decBlock->m_name = Generic::String::NumberToHex(pcodeBlock->ID);

				m_decompiledBlocks[pcodeBlock] = decompiledBlock;
			}
			setAllDecBlocksLinks();

			// start decompiling
			interpreteGraph(m_decompiledGraph->getFuncGraph()->getStartBlock());

			// building decompiled graph
			for (auto& it : m_decompiledBlocks) {
				auto& info = it.second;
				m_decompiledGraph->getDecompiledBlocks().push_back(info.m_decBlock);
			}
			m_decompiledGraph->sortBlocksByLevel();

			// create assignments
			createParAssignmentsForLocalVars();
		}

		AbstractRegisterFactory* getRegisterFactory() {
			return m_registerFactory;
		}

	private:
		void interpreteGraph(PCodeBlock* pcodeBlock, int versionOfDecompiling = 1) {
			auto& blockInfo = m_decompiledBlocks[pcodeBlock];

			// todo: redecompile block because of loops

			blockInfo.m_enterCount++;
			auto refHighBlocksCount = blockInfo.m_decBlock->getRefHighBlocksCount();
			if (blockInfo.m_enterCount >= refHighBlocksCount) {
				// save the register context in the begining
				blockInfo.m_execCtx->m_startRegisterExecCtx.copyFrom(&blockInfo.m_execCtx->m_registerExecCtx);

				// execute the instructions and then change the execution context
				blockInfo.m_decBlock->clearCode();
				PCode::InstructionInterpreter instructionInterpreter(this, blockInfo.m_decBlock, blockInfo.m_execCtx);
				for (auto instr : pcodeBlock->getInstructions()) {
					instructionInterpreter.execute(instr);
				}

				auto hasAlreadyDecompiled = blockInfo.m_isDecompiled;
				blockInfo.m_isDecompiled = true;
				blockInfo.m_versionOfDecompiling = versionOfDecompiling;

				for (auto nextPCodeBlock : pcodeBlock->getNextBlocks()) {
					auto nextDecBlockInfo = m_decompiledBlocks[nextPCodeBlock];

					auto nextVersionOfDecompiling = versionOfDecompiling;
					if (nextPCodeBlock->m_level < pcodeBlock->m_level) {
						// if it is a loop
						if (!hasAlreadyDecompiled)
							nextVersionOfDecompiling = ++m_loopsCount + 1;
					}

					if (nextVersionOfDecompiling <= nextDecBlockInfo.m_versionOfDecompiling)
						continue;

					if (nextDecBlockInfo.m_isDecompiled) {
						// delete nextDecBlockInfo.m_execCtx->m_registerExecCtx
						nextDecBlockInfo.m_execCtx->m_registerExecCtx.copyFrom(&nextDecBlockInfo.m_execCtx->m_startRegisterExecCtx);
					}
					nextDecBlockInfo.m_execCtx->join(blockInfo.m_execCtx);
					interpreteGraph(nextPCodeBlock, nextVersionOfDecompiling);
				}	
			}
		}
		
		void setAllDecBlocksLinks() {
			for (const auto& pair : m_decompiledBlocks) {
				auto& decBlockInfo = pair.second;
				if (auto nextPCodeBlock = decBlockInfo.m_pcodeBlock->getNextNearBlock()) {
					decBlockInfo.m_decBlock->setNextNearBlock(m_decompiledBlocks[nextPCodeBlock].m_decBlock);
				}
				if (auto nextPCodeBlock = decBlockInfo.m_pcodeBlock->getNextFarBlock()) {
					decBlockInfo.m_decBlock->setNextFarBlock(m_decompiledBlocks[nextPCodeBlock].m_decBlock);
				}
			}
		}
		
		// iterate over all exprs in dec. graph and find localVar to create par. assignments
		void createParAssignmentsForLocalVars() {
			for (const auto decBlock : m_decompiledGraph->getDecompiledBlocks()) {
				for (auto topNode : decBlock->getAllTopNodes()) {
					std::list<ExprTree::SymbolLeaf*> symbolLeafs;
					GatherSymbolLeafsFromNode(topNode->getNode(), symbolLeafs);
					for (auto symbolLeaf : symbolLeafs) {
						if (auto localVar = dynamic_cast<Symbol::LocalVariable*>(symbolLeaf->m_symbol)) {
							auto& localVarInfo = m_localVars[localVar];

							for (auto parentNode : symbolLeaf->getParentNodes()) {
								if (!dynamic_cast<RegTopNode*>(parentNode))
									continue;

								localVarInfo.m_countOfInstances++;
								if (auto opNode = dynamic_cast<ExprTree::OperationalNode*>(parentNode)) { // need after optimization
									if (opNode->m_operation == ExprTree::And) {
										localVarInfo.m_instanceMask = localVarInfo.m_instanceMask | opNode->m_rightNode->getMask();
									}
								}
							}
						}
					}
				}
			}

			for (auto& pair : m_localVars) {
				auto localVar = pair.first;
				auto& localVarInfo = pair.second;

				if (localVarInfo.m_countOfInstances == 0)
					continue;

				// change the size of local var
				if(!localVarInfo.m_instanceMask.isZero())
					localVar->getMask() = localVarInfo.m_register.m_valueRangeMask = localVarInfo.m_register.m_valueRangeMask & localVarInfo.m_instanceMask;

				// iterate over all ctxs and create assignments: localVar1 = 0x5
				for (auto execCtx : localVarInfo.m_execCtxs) {
					auto expr = execCtx->m_registerExecCtx.requestRegister(localVarInfo.m_register);

					// to avoide: localVar1 = localVar1
					if (auto symbolLeaf = dynamic_cast<ExprTree::SymbolLeaf*>(expr))
						if (symbolLeaf->m_symbol == localVar)
							continue;

					auto& blockInfo = m_decompiledBlocks[execCtx->m_pcodeBlock];
					blockInfo.m_decBlock->addSymbolParallelAssignmentLine(new ExprTree::SymbolLeaf(localVar), expr);
				}

				m_decompiledGraph->addSymbol(localVar);
			}
		}
	};
};