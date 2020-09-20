#pragma once
#include "../SdaGraphModification.h"
#include "../../Graph/DecCodeGraphBlockFlowIterator.h"

namespace CE::Decompiler::Optimization
{
	using namespace ExprTree;

	class SdaGraphMemoryOptimization : public SdaGraphModification
	{
		class MemoryContext
		{
			struct MemoryValue {
				MemLocation* m_location;
				ISdaNode* m_node;
			};
			std::list<MemoryValue> m_memValues;
		public:
			struct MemVarInfo {
				SdaSymbolLeaf* m_symbolLeaf;
				Symbol::MemoryVariable* m_memVar;
				ISdaNode* m_locatableNode = nullptr;
				int m_lastUsedMemLocIdx;
			};

			struct MemSnapshot {
				MemLocation* m_location;
				ILocatable* m_locatableNode;
				ISdaNode* m_snapshotValue;
			};

			//the result of memory copy working
			std::list<MemVarInfo> m_memVars;
			//locations in memory that are affected within the block(this ctx reffers to) in one or another way
			std::list<MemLocation> m_usedMemLocations;
			std::map<Symbol::MemoryVariable*, MemSnapshot> m_memVarSnapshots;

			ISdaNode* getMemValue(const MemLocation& location) const {
				for (auto it = m_memValues.begin(); it != m_memValues.end(); it++) {
					if (it->m_location->equal(location)) {
						return it->m_node;
					}
				}
				return nullptr;
			}

			MemLocation* addMemValue(const MemLocation& location, ISdaNode* sdaNode) {
				auto newLocation = createNewLocation(location);
				MemoryValue memoryValue;
				memoryValue.m_location = newLocation;
				memoryValue.m_node = sdaNode;
				m_memValues.push_back(memoryValue);
				return newLocation;
			}

			MemLocation* createNewLocation(const MemLocation& location) {
				//clear all location that are intersecting this one
				for (auto it = m_memValues.begin(); it != m_memValues.end(); it ++) {
					if (it->m_location->intersect(location)) {
						m_memValues.erase(it);
					}
				}
				//mark the input location as used within the current context
				m_usedMemLocations.push_back(location);
				return &(*m_usedMemLocations.rbegin()); //dangerous: important no to copy the mem ctx anywhere
			}

			bool hasUsed(const MemLocation& location, int lastUsedMemLocIdx = -1) {
				for (const auto& loc : m_usedMemLocations) {
					if (lastUsedMemLocIdx-- == -1)
						break;
					if (loc.intersect(location)) {
						return true;
					}
				}
				return false;
			}
		};
		
		std::map<PrimaryTree::Block*, MemoryContext> m_memoryContexts;
	public:
		SdaGraphMemoryOptimization(SdaCodeGraph* sdaCodeGraph)
			: SdaGraphModification(sdaCodeGraph)
		{}

		void start() override {
			initEveryMemCtxForEachBlocks();
			optimizeAllBlocksUsingMemCtxs();
		}

	private:
		//just fill every memory context up for each block
		void initEveryMemCtxForEachBlocks() {
			for (auto block : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				m_memoryContexts[block] = MemoryContext();
				MemoryContextInitializer memoryContextInitializer(block, &m_memoryContexts[block]);
				memoryContextInitializer.start();
			}
		}

		//optimize all blocks using filled up memory contexts on prev step
		void optimizeAllBlocksUsingMemCtxs() {
			for (auto block : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				optimizeBlock(block, &m_memoryContexts[block]);
			}
		}

		void optimizeBlock(PrimaryTree::Block* block, MemoryContext* memCtx) {
			for (auto& memVarInfo : memCtx->m_memVars) {
				auto newNode = memVarInfo.m_locatableNode;
				auto memSnapshot = findMemSnapshotByMemVar(memVarInfo.m_memVar);
				if (memSnapshot) {
					if (memSnapshot->m_snapshotValue) {
						newNode = memSnapshot->m_snapshotValue;
					}
					else if (!memCtx->hasUsed(*memSnapshot->m_location, memVarInfo.m_lastUsedMemLocIdx)) {
						if (auto foundNode = findValueNodeInBlocksAbove(block, memSnapshot->m_location)) {
							newNode = foundNode;
						}
					}
				}

				if (newNode) {
					//replace the symbol with the concrete value (e.g. reading some memory location)
					auto newClonedNode = newNode->clone();
					memVarInfo.m_symbolLeaf->replaceWith(newClonedNode);
					delete memVarInfo.m_symbolLeaf;
				}
			}
		}

		MemoryContext::MemSnapshot* findMemSnapshotByMemVar(Symbol::MemoryVariable* memVar) {
			for (auto block : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				auto& memVarToMemLocation = m_memoryContexts[block].m_memVarSnapshots;
				auto it = memVarToMemLocation.find(memVar);
				if (it != memVarToMemLocation.end()) {
					return &it->second;
				}
			}
			return nullptr;
		}

		ISdaNode* findValueNodeInBlocksAbove(PrimaryTree::Block* startBlock, MemLocation* memLoc) {
			BlockFlowIterator blockFlowIterator(startBlock);
			while (blockFlowIterator.hasNext()) {
				blockFlowIterator.m_considerLoop = false;
				if (blockFlowIterator.isStartBlock())
					continue;
				auto& blockInfo = blockFlowIterator.next();
				auto memCtx = &m_memoryContexts[blockInfo.m_block];
				if (blockInfo.hasMaxPressure()) {
					if (auto valueNode = memCtx->getMemValue(*memLoc))
						return valueNode;
				}
				if (memCtx->hasUsed(*memLoc))
					break;
			}

			return nullptr;
		}

		class MemoryContextInitializer
		{
			PrimaryTree::Block* m_block;
			MemoryContext* m_memCtx;
		public:
			MemoryContextInitializer(PrimaryTree::Block* block, MemoryContext* memCtx)
				: m_block(block), m_memCtx(memCtx)
			{}

			void start() {
				for (auto topNode : m_block->getAllTopNodes()) {
					auto node = topNode->getNode();
					INode::UpdateDebugInfo(node);
					passNode(node);
				}
			}

		private:
			void passNode(INode* node) {
				if (auto assignmentNode = dynamic_cast<AssignmentNode*>(node)) {
					if (dynamic_cast<SdaSymbolLeaf*>(assignmentNode->getDstNode())) {
						passNode(assignmentNode->getSrcNode());
						return;
					}
				}
				node->iterateChildNodes([&](INode* childNode) {
					passNode(childNode);
					});

				if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(node)) {
					if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaGenNode->getNode())) {
						auto dstSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getDstNode());
						auto srcSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getSrcNode());

						if (dstSdaNode && srcSdaNode) {
							//when writing some stuff into memory
							if (auto dstSdaLocNode = dynamic_cast<ILocatable*>(dstSdaNode)) {
								try {
									MemLocation dstLocation;
									dstSdaLocNode->getLocation(dstLocation);
									m_memCtx->addMemValue(dstLocation, srcSdaNode);
								}
								catch (std::exception&) {}
							}
							else {
								if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(assignmentNode->getDstNode())) {
									if (auto memVar = dynamic_cast<Symbol::MemoryVariable*>(sdaSymbolLeaf->getDecSymbol())) {
										//when reading from memory into the symbol
										if (auto srcSdaLocNode = dynamic_cast<ILocatable*>(srcSdaNode)) {
											try {
												MemLocation srcLocation;
												srcSdaLocNode->getLocation(srcLocation);
												MemoryContext::MemSnapshot memSnapshot;
												memSnapshot.m_snapshotValue = m_memCtx->getMemValue(srcLocation);
												memSnapshot.m_location = m_memCtx->addMemValue(srcLocation, srcSdaNode);
												memSnapshot.m_locatableNode = srcSdaLocNode;
												m_memCtx->m_memVarSnapshots[memVar] = memSnapshot;
											}
											catch (std::exception&) {}
										}
									}
								}
							}
						}
					}
				}

				//replace the internal memVar with a node value stored on some location for this memVar
				if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(node)) {
					if (auto memVar = dynamic_cast<Symbol::MemoryVariable*>(sdaSymbolLeaf->getDecSymbol())) {
						MemoryContext::MemVarInfo memVarInfo;
						memVarInfo.m_symbolLeaf = sdaSymbolLeaf;
						memVarInfo.m_memVar = memVar;
						memVarInfo.m_lastUsedMemLocIdx = (int)m_memCtx->m_usedMemLocations.size() - 1;

						//if the symbol not found within block then it means to be declared in the blocks above
						auto it = m_memCtx->m_memVarSnapshots.find(memVar);
						if (it != m_memCtx->m_memVarSnapshots.end()) {
							auto& memSnapshot = it->second;
							if (memSnapshot.m_locatableNode == m_memCtx->getMemValue(*it->second.m_location)) {
								memVarInfo.m_locatableNode = memSnapshot.m_locatableNode;
							}
						}
						m_memCtx->m_memVars.push_back(memVarInfo);
					}
				}

				//if the function call appeared then clear nearly all location as we dont know what memory this function affected
				if (auto sdaFunctionNode = dynamic_cast<SdaFunctionNode*>(node)) {
					MemLocation memAllLoc;
					memAllLoc.m_type = MemLocation::ALL;
					m_memCtx->createNewLocation(memAllLoc);
				}
			}
		};
	};
};