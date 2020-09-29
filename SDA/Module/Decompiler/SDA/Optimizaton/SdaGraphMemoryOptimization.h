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
				SdaTopNode* m_topNode;
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
				MemLocation m_location;
				ILocatable* m_locatableNode = nullptr;
				SdaTopNode* m_snapshotValue = nullptr;
			};

			//the result of memory copy working
			std::list<MemVarInfo> m_memVars;
			//locations in memory that are affected within the block(this ctx reffers to) in one or another way
			std::list<MemLocation> m_usedMemLocations;
			std::map<Symbol::MemoryVariable*, MemSnapshot> m_memVarSnapshots;

			void clear() {
				for (auto& memValue : m_memValues) {
					delete memValue.m_topNode;
				}

				for (auto& pair : m_memVarSnapshots) {
					auto& memSnapshot = pair.second;
					delete memSnapshot.m_snapshotValue;
				}
			}

			SdaTopNode* getMemValue(const MemLocation& location) const {
				for (auto it = m_memValues.begin(); it != m_memValues.end(); it++) {
					if (it->m_location->equal(location)) {
						return it->m_topNode;
					}
				}
				return nullptr;
			}

			void addMemValue(const MemLocation& location, ISdaNode* sdaNode) {
				auto newLocation = createNewLocation(location);
				MemoryValue memoryValue;
				memoryValue.m_location = newLocation;
				memoryValue.m_topNode = new SdaTopNode(sdaNode);
				m_memValues.push_back(memoryValue);
			}

			MemLocation* createNewLocation(const MemLocation& location) {
				//clear all location that are intersecting this one
				auto it = m_memValues.begin();
				while(it != m_memValues.end()) {
					if (it->m_location->intersect(location)) {
						delete it->m_topNode;
						it = m_memValues.erase(it);
					}
					else {
						it++;
					}
				}
				for (auto& pair : m_memVarSnapshots) {
					auto& snapshot = pair.second;
					if (snapshot.m_locatableNode) {
						if (snapshot.m_location.intersect(location)) {
							snapshot.m_locatableNode = nullptr;
						}
					}
					if (snapshot.m_snapshotValue) {
						if (auto locSnapshotValue = dynamic_cast<ILocatable*>(snapshot.m_snapshotValue->getNode())) {
							try {
								MemLocation snapshotValueLocation;
								locSnapshotValue->getLocation(snapshotValueLocation);
								if (snapshotValueLocation.intersect(location)) {
									delete snapshot.m_snapshotValue;
									snapshot.m_snapshotValue = nullptr;
								}
							}
							catch (std::exception&) {}
						}
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
		std::list<SdaSymbolLeaf*> m_removedSymbolLeafs;
	public:
		SdaGraphMemoryOptimization(SdaCodeGraph* sdaCodeGraph)
			: SdaGraphModification(sdaCodeGraph)
		{}

		void start() override {
			initEveryMemCtxForEachBlocks();
			optimizeAllBlocksUsingMemCtxs();

			for (auto symbolLeaf : m_removedSymbolLeafs) {
				delete symbolLeaf;
			}

			for (auto& pair : m_memoryContexts) {
				auto& memCtx = pair.second;
				memCtx.clear();
			}
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
						newNode = memSnapshot->m_snapshotValue->getSdaNode();
					}
					else if (!memCtx->hasUsed(memSnapshot->m_location, memVarInfo.m_lastUsedMemLocIdx)) {
						if (auto foundNode = findValueNodeInBlocksAbove(block, &memSnapshot->m_location)) {
							newNode = foundNode;
						}
					}
				}

				if (newNode) {
					//replace the symbol with the concrete value (e.g. reading some memory location)
					auto newClonedNode = newNode->clone();
					memVarInfo.m_symbolLeaf->replaceWith(newClonedNode);
					m_removedSymbolLeafs.push_back(memVarInfo.m_symbolLeaf);
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
					if (auto valueTopNode = memCtx->getMemValue(*memLoc))
						return valueTopNode->getSdaNode();
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
												memSnapshot.m_location = srcLocation;
												memSnapshot.m_locatableNode = srcSdaLocNode;
												auto snapshotValueTopNode = m_memCtx->getMemValue(srcLocation);
												if (snapshotValueTopNode) {
													memSnapshot.m_snapshotValue = new SdaTopNode(snapshotValueTopNode->getSdaNode());
												}
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
							memVarInfo.m_locatableNode = memSnapshot.m_locatableNode;
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