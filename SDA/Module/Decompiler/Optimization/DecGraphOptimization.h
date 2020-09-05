#pragma once
#include "ExprOptimization.h"
#include "../Graph/DecCodeGraph.h"

namespace CE::Decompiler::Optimization
{
	using namespace PrimaryTree;

	static void OptimizeConditionDecBlock(Block* block) {
		if (!block->isCondition())
			return;
		auto delta = block->getNextNearBlock()->m_level - block->m_level;
		if (delta >= 1 && delta < block->getNextFarBlock()->m_level - block->m_level)
			return;
		block->swapNextBlocks();
		block->getNoJumpCondition()->inverse();
	}

	static Block* JoinCondition(Block* block) {
		if (!block->isCondition())
			return nullptr;

		auto removedBlock = block->getNextNearBlock();
		auto mutualBlock = block->getNextFarBlock();
		if (!removedBlock->hasNoCode() || !removedBlock->isCondition() || removedBlock->getRefBlocksCount() != 1)
			return nullptr;

		Block* targetBlock = nullptr;
		auto removedBlockNoJmpCond = removedBlock->getNoJumpCondition();
		if (removedBlock->getNextNearBlock() == mutualBlock) {
			targetBlock = removedBlock->getNextFarBlock();
			removedBlockNoJmpCond->inverse();
		}
		else if (removedBlock->getNextFarBlock() == mutualBlock) {
			targetBlock = removedBlock->getNextNearBlock();
		}
		if (!targetBlock)
			return nullptr;

		block->setNoJumpCondition(new CompositeCondition(block->getNoJumpCondition(), removedBlockNoJmpCond, CompositeCondition::And));
		block->setNextNearBlock(targetBlock);
		removedBlock->removeRefBlock(block);
		return removedBlock;
	}

	static void OptimizeExprInDecompiledGraph(DecompiledCodeGraph* decGraph) {
		//optimize expressions
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto topNode : decBlock->getAllTopNodes()) {
				INode::UpdateDebugInfo(topNode->getNode());
				Optimization::Optimize(*topNode->getNodePtr());

				if (auto jmpTopNode = dynamic_cast<Block::JumpTopNode*>(topNode)) {
					INode::UpdateDebugInfo(jmpTopNode->getCond());
					Optimization::OptimizeConstCondition(jmpTopNode->getCond());
					INode::UpdateDebugInfo(jmpTopNode->getCond());
					Optimization::OptimizeCondition(*jmpTopNode->getNodePtr());
				}
			}
		}
	}

	static void FindRelatedInstructionsForLocalVars(DecompiledCodeGraph* decGraph) {
		for (auto symbol : decGraph->getSymbols()) {
			//find related instructions for local vars
			if (auto localVarSymbol = dynamic_cast<Symbol::LocalVariable*>(symbol)) {
				for (auto symbolLeaf : localVarSymbol->m_symbolLeafs) {
					if (auto assignmentNode = dynamic_cast<ExprTree::AssignmentNode*>(symbolLeaf->getParentNode())) {
						if (symbolLeaf == assignmentNode->getDstNode()) {
							for(auto instr : assignmentNode->getInstructionsRelatedTo())
								localVarSymbol->m_instructionsRelatedTo.push_back(instr);
						}
					}
				}
			}
		}
	}

	static bool IsMemLocIntersected(ReadValueNode* memValueNode1, ReadValueNode* memValueNode2) {
		TermsDict terms1;
		TermsDict terms2;
		int64_t constTerm1 = 0;
		int64_t constTerm2 = 0;
		GetTermsInExpr(memValueNode1->getAddress(), terms1, constTerm1);
		GetTermsInExpr(memValueNode2->getAddress(), terms2, constTerm2);
		if (!AreTermsEqual(terms1, terms2))
			return true;
		auto delta = constTerm2 - constTerm1;
		return !(delta >= memValueNode1->getSize() || -delta >= memValueNode2->getSize());
	}
	
	static void GetReadValueNodes(INode* node, std::list<ReadValueNode*>& readValueNodes) {
		IterateChildNodes(node, [&](INode* childNode) {
			GetReadValueNodes(childNode, readValueNodes);
			});
		if (auto readValueNode = dynamic_cast<ReadValueNode*>(node)) {
			readValueNodes.push_back(readValueNode);
		}
	}

	static void GetReadValueNodes(Block::SeqLine* line, std::list<ReadValueNode*>& readValueNodes) {
		auto destAddr = line->getDstNode();
		if (auto readValueNode = dynamic_cast<ReadValueNode*>(line->getDstNode())) {
			destAddr = readValueNode->getAddress();
		}
		GetReadValueNodes(destAddr, readValueNodes);
		GetReadValueNodes(line->getSrcNode(), readValueNodes);
	}

	static bool AreSeqLinesInterconnected(Block::SeqLine* line1, Block::SeqLine* line2) {
		//case 1: function call
		if (dynamic_cast<FunctionCall*>(line1->getSrcNode()) || dynamic_cast<FunctionCall*>(line2->getSrcNode())) {
			return true;
		}
		
		//case 2: read-write or write-read
		for (auto linePair : { std::pair(line1, line2), std::pair(line2, line1) }) {
			if (auto writeValueNode = dynamic_cast<ReadValueNode*>(linePair.first->getDstNode())) {
				std::list<ReadValueNode*> readValueNodes;
				GetReadValueNodes(linePair.second, readValueNodes);

				for (auto readValueNode : readValueNodes) {
					if (IsMemLocIntersected(readValueNode, writeValueNode)) {
						return true;
					}
				}
			}
		}

		//case 3: write-write
		auto writeValueNode1 = dynamic_cast<ReadValueNode*>(line1->getDstNode());
		auto writeValueNode2 = dynamic_cast<ReadValueNode*>(line2->getDstNode());
		if (!writeValueNode1 || !writeValueNode2) {
			return false;
		}
		return IsMemLocIntersected(writeValueNode1, writeValueNode2);
	}

	static bool DoesLineHavePathToOtherLine(std::list<Block::SeqLine*>::iterator lineIt, std::list<Block::SeqLine*>& lines, std::list<Block::SeqLine*>& pushedOutLines, bool isTop = true) {
		if (!isTop && lineIt == prev(lines.end()))
			return false;
		while (lineIt != (isTop ? prev(prev(lines.end())) : prev(lines.end()))) {
			auto curLineIt = lineIt;
			auto nextLineIt = std::next(lineIt);

			bool areSeqLinesInterconnected = AreSeqLinesInterconnected(*curLineIt, *nextLineIt);
			if (areSeqLinesInterconnected) {
				if (DoesLineHavePathToOtherLine(nextLineIt, lines, pushedOutLines, false)) {
					continue;
				}
				else {
					return false;
				}
			}

			//move wall further
			std::iter_swap(curLineIt, nextLineIt);
			lineIt++;
		}
		if (!isTop) {
			pushedOutLines.push_back(*std::prev(lines.end()));
			lines.pop_back();
		}
		return true;
	}

	static bool DoesLineHavePathToOtherLine(Block::SeqLine* firstSeqLine, std::list<Block::SeqLine*>::iterator lineIt1, std::list<Block::SeqLine*>::iterator lineIt2, std::list<Block::SeqLine*>& pushedOutLines) {
		std::list<Block::SeqLine*> lines;
		lines.push_back(firstSeqLine);
		for (auto it = lineIt1; it != std::next(lineIt2); it++) {
			INode::UpdateDebugInfo((*it)->getDstNode());
			INode::UpdateDebugInfo((*it)->getSrcNode());
			lines.push_back(*it);
		}

		auto result = DoesLineHavePathToOtherLine(lines.begin(), lines, pushedOutLines);
		return result;
	}

	static void GetConstantParentsOfNode(INode* node, std::list<INodeAgregator*>& parentNodes) {
		for (auto it : node->getParentNodes()) {
			if (auto parentNode = dynamic_cast<INode*>(it)) {
				GetConstantParentsOfNode(parentNode, parentNodes);
			}
			if (dynamic_cast<Block::BlockTopNode*>(it)) {
				parentNodes.push_back(it);
			}
		}
	}

	static void RemoveSeqLinesWithNotUsedMemVarDecompiledGraph(DecompiledCodeGraph* decGraph) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto it = decBlock->getSeqLines().begin(); it != decBlock->getSeqLines().end(); it++) {
				if (auto memSymbolLeaf = dynamic_cast<SymbolLeaf*>((*it)->getDstNode())) {
					if (auto memVariable = dynamic_cast<Symbol::MemoryVariable*>(memSymbolLeaf->m_symbol))
					{
						std::list<INodeAgregator*> parentNodes;
						for (auto symbolLeaf : memVariable->m_symbolLeafs) {
							GetConstantParentsOfNode(symbolLeaf, parentNodes);
						}

						//mem var must be in seq lines only of the same block
						if (parentNodes.size() == 1)
						{
							decBlock->getSeqLines().erase(it);
							delete* it;
						}
					}
				}
			}
		}
	}

	static void OptimizeSeqLinesOrderInDecompiledGraph(DecompiledCodeGraph* decGraph) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto it1 = decBlock->getSeqLines().begin(); it1 != decBlock->getSeqLines().end(); it1 ++) {
				if (auto memSymbolLeaf = dynamic_cast<SymbolLeaf*>((*it1)->getDstNode())) {
					if (auto memVariable = dynamic_cast<Symbol::MemoryVariable*>(memSymbolLeaf->m_symbol))
					{
						std::list<INodeAgregator*> parentNodes;
						std::list<Block::SeqLine*> seqLinesWithMemVar;
						for (auto symbolLeaf : memVariable->m_symbolLeafs) {
							if (symbolLeaf == memSymbolLeaf)
								continue;
							GetConstantParentsOfNode(symbolLeaf, parentNodes);
						}
						
						for (auto parentNode : parentNodes) {
							if (auto seqLineWithMemVar = dynamic_cast<Block::SeqLine*>(parentNode)) {
								if (seqLineWithMemVar->m_block == decBlock && seqLineWithMemVar != *it1) {
									seqLinesWithMemVar.push_back(seqLineWithMemVar);
								}
							}
						}

						//mem var must be in seq lines only of the same block
						if (seqLinesWithMemVar.size() == parentNodes.size())
						{
							//store pushed out of the bound wall lines that are in conflict with *it1
							std::list<std::pair<std::list<Block::SeqLine*>::iterator, std::list<Block::SeqLine*>>> pushedOutlines;

							bool isRemove = true;
							auto curNextSeqLineIt = std::next(it1);
							for (auto it2 = std::next(it1); it2 != decBlock->getSeqLines().end() && !seqLinesWithMemVar.empty(); it2++) {
								bool isSuit = false;
								for (auto seqLineIt = seqLinesWithMemVar.begin(); seqLineIt != seqLinesWithMemVar.end(); seqLineIt++) {
									if (*it2 == *seqLineIt) {
										isSuit = true;
										seqLinesWithMemVar.erase(seqLineIt);
										break;
									}
								}

								if (isSuit) {
									std::list<Block::SeqLine*> pushedOutLines_;
									if (!DoesLineHavePathToOtherLine(*it1, curNextSeqLineIt, it2, pushedOutLines_)) {
										isRemove = false;
										break;
									}
									if (!pushedOutLines_.empty()) {
										pushedOutlines.push_back(std::pair(it2, pushedOutLines_));
									}
									curNextSeqLineIt = std::next(it2);
								}
							}

							if (isRemove) {
								for (auto it : pushedOutlines) {
									auto boundLineIt = it.first;
									for (auto pushedOutline : it.second) {
										decBlock->getSeqLines().remove(pushedOutline);
										boundLineIt = decBlock->getSeqLines().insert(std::next(boundLineIt), pushedOutline);
									}
								}

								for (auto symbolLeaf : memVariable->m_symbolLeafs) {
									if (symbolLeaf == memSymbolLeaf)
										continue;
									symbolLeaf->replaceWith((*it1)->getSrcNode());
								}
								decBlock->getSeqLines().erase(it1);
								delete* it1;
							}
						}
					}
				}
			}
		}
	}

	static bool HasUndefinedRegister(INode* node, FunctionCallInfo& funcCallInfo) {
		if (dynamic_cast<FunctionCall*>(node))
			return false;
		
		bool result = false;
		IterateChildNodes(node, [&](INode* childNode) {
			if(!result)
				result = HasUndefinedRegister(childNode, funcCallInfo);
			});
		if (result)
			return true;

		if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node)) {
			if (auto regVar = dynamic_cast<Symbol::RegisterVariable*>(symbolLeaf->m_symbol)) {
				if (regVar->m_register.isPointer())
					return false;

				bool isFound = false;
				for (auto paramInfo : funcCallInfo.getParamInfos()) {
					if (regVar->m_register.getGenericId() == paramInfo.m_storage.getRegisterId()) {
						isFound = true;
						break;
					}
				}
				if (!isFound) {
					return true;
				}
			}
		}
		return false;
	}

	static void RemoveSeqLinesWithUndefinedRegisters(DecompiledCodeGraph* decGraph) {
		auto& funcCallInfo = decGraph->getFunctionCallInfo();
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			for (auto it = decBlock->getSeqLines().begin(); it != decBlock->getSeqLines().end(); it++) {
				auto seqLine = *it;
				if (HasUndefinedRegister(seqLine->getDstNode(), funcCallInfo) || HasUndefinedRegister(seqLine->getSrcNode(), funcCallInfo)) {
					decBlock->getSeqLines().erase(it);
					delete seqLine;
				}
			}
		}
	}

	static void GetSymbolLeafs(INode* node, Symbol::Symbol* symbol, std::list<ExprTree::SymbolLeaf*>& symbolLeafs) {
		IterateChildNodes(node, [&](INode* childNode) {
			GetSymbolLeafs(childNode, symbol, symbolLeafs);
			});

		if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(node)) {
			if (symbolLeaf->m_symbol == symbol) {
				symbolLeafs.push_back(symbolLeaf);
			}
		}
	}

	static bool FixSymbolAssignmentLineAndConditionOrder(INode* node, std::map<ObjectHash::Hash, Symbol::LocalVariable*>& localVars) {
		auto it = localVars.find(node->getHash());
		if (it != localVars.end()) {
			node->replaceWith(new SymbolLeaf(it->second));
			delete node;
			return true;
		}

		bool result = false;
		IterateChildNodes(node, [&](INode* childNode) {
			if(!result)
				result = FixSymbolAssignmentLineAndConditionOrder(childNode, localVars);
			});
		return result;
	}

	static void FixSymbolAssignmentLineAndConditionOrder(DecompiledCodeGraph* decGraph) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			if (decBlock->getNoJumpCondition()) {
				std::map<ObjectHash::Hash, Symbol::LocalVariable*> localVars;
				for (auto symbolAssignmentLine : decBlock->getSymbolAssignmentLines()) {
					if (auto localVar = dynamic_cast<Symbol::LocalVariable*>(symbolAssignmentLine->getDstSymbol()->m_symbol)) {
						std::list<ExprTree::SymbolLeaf*> symbolLeafs;
						GetSymbolLeafs(symbolAssignmentLine->getSrcNode(), localVar, symbolLeafs);
						if (!symbolLeafs.empty()) {
							CalculateHashes(symbolAssignmentLine->getSrcNode());
							localVars.insert(std::make_pair(symbolAssignmentLine->getSrcNode()->getHash(), localVar));
						}
					}
				}
				CalculateHashes(decBlock->getNoJumpCondition());
				FixSymbolAssignmentLineAndConditionOrder(decBlock->getNoJumpCondition(), localVars);
			}
		}
	}

	static void ExpandSymbolAssignmentLines(DecompiledCodeGraph* decGraph) {
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			auto newSeqLines = decBlock->getSymbolAssignmentLines();
			decBlock->getSymbolAssignmentLines().clear();

			for (auto it = newSeqLines.begin(); it != newSeqLines.end(); it ++) {
				auto seqLine = *it;
				auto symbolLeaf = dynamic_cast<ExprTree::SymbolLeaf*>(seqLine->getDstNode());
				
				ExprTree::SymbolLeaf* tempVarSymbolLeaf = nullptr;
				for (auto it2 = std::next(it); it2 != newSeqLines.end(); it2++) {
					auto otherSeqLine = *it2;
					std::list<ExprTree::SymbolLeaf*> symbolLeafs;
					GetSymbolLeafs(otherSeqLine->getSrcNode(), symbolLeaf->m_symbol, symbolLeafs);
					if (!symbolLeafs.empty()) {
						if (!tempVarSymbolLeaf) {
							tempVarSymbolLeaf = new ExprTree::SymbolLeaf(new Symbol::LocalVariable(symbolLeaf->m_symbol->getSize()));
						}
						for (auto symbolLeaf : symbolLeafs) {
							symbolLeaf->replaceWith(tempVarSymbolLeaf);
							delete symbolLeaf;
						}
					}
				}

				if (tempVarSymbolLeaf) {
					decBlock->addSeqLine(tempVarSymbolLeaf, symbolLeaf);
				}
				decBlock->getSeqLines().push_back(seqLine);
			}
		}
	}

	static void OptimizeDecompiledGraph(DecompiledCodeGraph* decGraph)
	{
		//join conditions and remove useless blocks
		for (auto it = decGraph->getDecompiledBlocks().rbegin(); it != decGraph->getDecompiledBlocks().rend(); it++) {
			auto block = *it;
			while (auto removedBlock = JoinCondition(block)) {
				OptimizeConditionDecBlock(block);
				decGraph->removeDecompiledBlock(removedBlock);
				it = decGraph->getDecompiledBlocks().rbegin();
			}
		}

		//recalculate levels because some blocks can be removed
		for (const auto decBlock : decGraph->getDecompiledBlocks()) {
			decBlock->m_level = 0;
		}
		std::list<PrimaryTree::Block*> path;
		DecompiledCodeGraph::CalculateLevelsForDecBlocks(decGraph->getStartBlock(), path);

		FixSymbolAssignmentLineAndConditionOrder(decGraph);
		FindRelatedInstructionsForLocalVars(decGraph);
		OptimizeExprInDecompiledGraph(decGraph);
		ExpandSymbolAssignmentLines(decGraph);
		RemoveSeqLinesWithUndefinedRegisters(decGraph);
		//RemoveSeqLinesWithNotUsedMemVarDecompiledGraph(decGraph);

		decGraph->generateSymbolIds();
		DecompiledCodeGraph::CalculateHeightForDecBlocks(decGraph->getStartBlock());

		//MemorySymbolization memorySymbolization(decGraph);
		//memorySymbolization.start();
		//optimize expressions again after memory symbolization
		//OptimizeExprInDecompiledGraph(decGraph);
	}
};