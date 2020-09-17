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
				auto symbolLeaf = symbolAssignmentLine->getDstSymbolLeaf();

				//determine whether does it need a temp symbol to store value for next lines, and if yes then create it
				ExprTree::SymbolLeaf* tempVarSymbolLeaf = nullptr;
				for (auto it2 = std::next(it); it2 != newSeqLines.end(); it2++) {
					auto anotherNextSeqLine = *it2;
					std::list<ExprTree::SymbolLeaf*> symbolLeafs;
					gatherSymbolLeafsFromNode(anotherNextSeqLine->getSrcNode(), symbolLeaf->m_symbol, symbolLeafs);
					if (!symbolLeafs.empty()) {
						if (!tempVarSymbolLeaf) {
							auto tempLocalVar = new Symbol::LocalVariable(symbolLeaf->m_symbol->getSize());
							tempVarSymbolLeaf = new ExprTree::SymbolLeaf(tempLocalVar);
						}
						for (auto symbolLeaf : symbolLeafs) {
							symbolLeaf->replaceWith(tempVarSymbolLeaf);
							delete symbolLeaf;
						}
					}
				}

				if (tempVarSymbolLeaf) {
					block->addSeqLine(tempVarSymbolLeaf, symbolLeaf);
				}
				block->getSeqLines().push_back(symbolAssignmentLine);
			}
		}
	};
};