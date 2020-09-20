#pragma once
#include "DecGraphModification.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	class GraphLinesExpanding : public GraphModification
	{
	public:
		GraphLinesExpanding(DecompiledCodeGraph* decGraph)
			: GraphModification(decGraph)
		{}

		void start() override {
			for (auto decBlock : m_decGraph->getDecompiledBlocks()) {
				processBlock(decBlock);
			}
		}
	private:
		void processBlock(Block* block) {
			auto newSeqLines = block->getSymbolAssignmentLines();
			block->getSymbolAssignmentLines().clear();

			for (auto it = newSeqLines.begin(); it != newSeqLines.end(); it++) {
				auto symbolAssignmentLine = *it;
				//let it be localVar1 
				auto localVar = symbolAssignmentLine->getDstSymbolLeaf()->m_symbol;

				//determine whether does it need a temp symbol to store value for next lines, and if yes then create it
				Symbol::LocalVariable* localTempVar = nullptr;
				for (auto it2 = std::next(it); it2 != newSeqLines.end(); it2++) {
					auto anotherNextSeqLine = *it2;
					std::list<ExprTree::SymbolLeaf*> symbolLeafs;
					gatherSymbolLeafsFromNode(anotherNextSeqLine->getSrcNode(), localVar, symbolLeafs);
					//if we find anything like this: localVar2 = localVar1 + 1
					if (!symbolLeafs.empty()) {
						if (!localTempVar) {
							localTempVar = new Symbol::LocalVariable(localVar->getSize());
							m_decGraph->addSymbol(localTempVar);
						}
						for (auto symbolLeaf : symbolLeafs) {
							symbolLeaf->replaceWith(new ExprTree::SymbolLeaf(localTempVar));
							delete symbolLeaf;
						}
					}
				}

				if (localTempVar) {
					block->addSeqLine(new ExprTree::SymbolLeaf(localTempVar), new ExprTree::SymbolLeaf(localVar));
				}
				block->getSeqLines().push_back(symbolAssignmentLine);
			}
		}
	};
};