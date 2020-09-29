#pragma once
#include "Graph/DecCodeGraph.h"
#include "PCode/Interpreter/PCodeInterpreter.h"
#include "PCode/DecRegisterFactory.h"

namespace CE::Decompiler
{
	class Decompiler
	{
	public:
		struct DecompiledBlockInfo {
			AsmGraphBlock* m_asmBlock = nullptr;
			PrimaryTree::Block* m_decBlock = nullptr;
			ExecutionBlockContext* m_execBlockCtx = nullptr;

			DecompiledBlockInfo() = default;

			bool isDecompiled() {
				return m_decBlock != nullptr;
			}
		};
		std::map<PrimaryTree::Block*, DecompiledBlockInfo> m_decompiledBlocks;

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

		void start();

		void buildDecompiledGraph();

		AbstractRegisterFactory* getRegisterFactory() {
			return m_registerFactory;
		}
	private:
		AbstractRegisterFactory* m_registerFactory;
		PCode::InstructionInterpreter* m_instructionInterpreter;
		std::map<AsmGraphBlock*, PrimaryTree::Block*> m_asmToDecBlocks;
		
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
	};
};