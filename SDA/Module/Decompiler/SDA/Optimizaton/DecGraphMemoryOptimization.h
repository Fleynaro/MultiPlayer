#pragma once
#include "../DecGraphModification.h"
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
				ISdaNode* m_node = nullptr;
				int m_lastUsedMemLocIdx;
			};

			std::list<MemVarInfo> m_memVars;
			std::list<MemLocation> m_usedMemLocations;
			std::map<Symbol::MemoryVariable*, MemLocation*> m_memVarToMemLocation;

			MemoryContext()
			{}

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
				for (auto it = m_memValues.begin(); it != m_memValues.end(); it ++) {
					if (it->m_location->intersect(location)) {
						m_memValues.erase(it);
					}
				}
				//mark the input location as used within the current context
				m_usedMemLocations.push_back(location);
				return &(*m_usedMemLocations.rbegin());
			}

			bool hasUsed(const MemLocation& location, int lastUsedMemLocIdx = -1) {
				for (auto& loc : m_usedMemLocations) {
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
			optimizeAllBlocks();
		}

	private:
		void initEveryMemCtxForEachBlocks() {
			for (auto block : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				MemoryContext memCtx;
				MemoryContextInitializer memoryContextInitializer(block, &memCtx);
				memoryContextInitializer.start();
				m_memoryContexts[block] = memCtx;
			}
		}

		void optimizeAllBlocks() {
			for (auto block : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				optimizeBlock(block, &m_memoryContexts[block]);
			}
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
				node->iterateChildNodes([&](INode* childNode) {
					passNode(childNode);
					});
				
				if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(node)) {
					if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaGenNode->getNode())) {
						auto dstSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getDstNode());
						auto srcSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getSrcNode());

						if (dstSdaNode && srcSdaNode) {
							//writing some stuff into memory
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
										//reading from memory into the symbol
										if (auto srcSdaLocNode = dynamic_cast<ILocatable*>(srcSdaNode)) {
											try {
												MemLocation srcLocation;
												srcSdaLocNode->getLocation(srcLocation);
												auto newLocation = m_memCtx->addMemValue(srcLocation, srcSdaNode);
												m_memCtx->m_memVarToMemLocation[memVar] = newLocation;
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
						memVarInfo.m_lastUsedMemLocIdx = m_memCtx->m_usedMemLocations.size() - 1;

						//if the symbol not found within block then it means to be declared in the blocks above
						auto it = m_memCtx->m_memVarToMemLocation.find(memVar);
						if (it != m_memCtx->m_memVarToMemLocation.end()) {
							//if find the location of the internal memVar then recieve a value
							auto valueNode = m_memCtx->getMemValue(*it->second);
							if (valueNode) {
								memVarInfo.m_node = valueNode;
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

		void optimizeBlock(PrimaryTree::Block* block, MemoryContext* memCtx) {
			for (auto& memVarInfo : memCtx->m_memVars) {
				auto newNode = memVarInfo.m_node;
				if (!newNode) {
					auto memLocation = findLocationByMemVar(memVarInfo.m_memVar);
					if (memLocation) {
						if (!memCtx->hasUsed(*memLocation, memVarInfo.m_lastUsedMemLocIdx)) {
							newNode = findValueNodeInBlocksAbove(block, memLocation);
						}
					}
				}

				if (newNode) {
					//replace the symbol with the concrete value (e.g. reading some memory location)
					memVarInfo.m_symbolLeaf->replaceWith(newNode->clone());
					delete memVarInfo.m_symbolLeaf;
				}
			}
		}

		MemLocation* findLocationByMemVar(Symbol::MemoryVariable* memVar) {
			for (auto block : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				auto& memVarToMemLocation = m_memoryContexts[block].m_memVarToMemLocation;
				auto it = memVarToMemLocation.find(memVar);
				if (it != memVarToMemLocation.end()) {
					return it->second;
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
	};
};