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
			std::list<ExecContext*> m_execCtxs;
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
	};
};