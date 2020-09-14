#pragma once
#include "../DecSdaMisc.h"

namespace CE::Decompiler::Optimization
{
	using namespace ExprTree;

	class MemoryOptimization
	{
		class MemoryContext
		{
			struct MemoryValue {
				MemLocation m_location;
				ISdaNode* m_node;
			};

			std::list<MemoryValue> m_memValues;
			std::list<MemLocation> m_usedMemLocations;
		public:
			std::map<Symbol::MemoryVariable*, MemLocation> m_memVarToMemLocation;

			MemoryContext()
			{}

			ISdaNode* getMemValue(const MemLocation& location) const {
				for (auto it = m_memValues.begin(); it != m_memValues.end(); it++) {
					if (it->m_location.equal(location)) {
						return it->m_node;
					}
				}
				return nullptr;
			}

			void addMemValue(const MemLocation& location, ISdaNode* sdaNode) {
				clearLocation(location);
				MemoryValue memoryValue;
				memoryValue.m_location = location;
				memoryValue.m_node = sdaNode;
				m_memValues.push_back(memoryValue);
			}

			void clearLocation(const MemLocation& location) {
				m_usedMemLocations.push_back(location);
				for (auto it = m_memValues.begin(); it != m_memValues.end(); it ++) {
					if (it->m_location.intersect(location)) {
						m_memValues.erase(it);
					}
				}
			}
		};

		SdaCodeGraph* m_sdaCodeGraph;
		std::map<PrimaryTree::Block*, MemoryContext> m_memoryContexts;
	public:
		MemoryOptimization(SdaCodeGraph* sdaCodeGraph)
			: m_sdaCodeGraph(sdaCodeGraph)
		{}

		void start() {
			passAllBlocks();
		}

	private:
		void passAllBlocks() {
			for (auto block : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				MemoryContext memCtx;
				FirstPassOfBlock firstPassOfBlock(block, &memCtx);
				firstPassOfBlock.start();
				m_memoryContexts[block] = memCtx;
			}
		}

		class FirstPassOfBlock
		{
			PrimaryTree::Block* m_block;
			MemoryContext* m_memCtx;
		public:
			FirstPassOfBlock(PrimaryTree::Block* block, MemoryContext* memCtx)
				: m_block(block), m_memCtx(memCtx)
			{}

			void start() {
				for (auto topNode : m_block->getAllTopNodes()) {
					auto node = topNode->getNode();
					INode::UpdateDebugInfo(node);
					optimizeNode(node);
				}
			}

		private:
			void optimizeNode(INode* node) {
				node->iterateChildNodes([&](INode* childNode) {
					optimizeNode(childNode);
					});

				if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(node)) {
					if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaGenNode->getNode())) {
						auto dstSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getDstNode());
						auto srcSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getSrcNode());

						if (dstSdaNode && srcSdaNode) {
							if (auto dstSdaLocNode = dynamic_cast<ILocatable*>(dstSdaNode)) {
								MemLocation dstLocation;
								dstSdaLocNode->getLocation(dstLocation);
								m_memCtx->addMemValue(dstLocation, srcSdaNode);
							}
							else {
								if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(assignmentNode->getDstNode())) {
									if (auto memVar = dynamic_cast<Symbol::MemoryVariable*>(sdaSymbolLeaf->getDecSymbol())) {
										if (auto srcSdaLocNode = dynamic_cast<ILocatable*>(srcSdaNode)) {
											MemLocation srcLocation;
											srcSdaLocNode->getLocation(srcLocation);
											m_memCtx->addMemValue(srcLocation, srcSdaNode);
											m_memCtx->m_memVarToMemLocation[memVar] = srcLocation;
										}
									}
								}
							}
						}
					}
				}

				if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(node)) {
					if (auto memVar = dynamic_cast<Symbol::MemoryVariable*>(sdaSymbolLeaf->getDecSymbol())) {
						auto it = m_memCtx->m_memVarToMemLocation.find(memVar);
						if (it != m_memCtx->m_memVarToMemLocation.end()) {
							auto valueNode = m_memCtx->getMemValue(it->second);
							if (valueNode) {
								sdaSymbolLeaf->replaceWith(valueNode->clone());
								delete sdaSymbolLeaf;
							}
						}
					}
				}

				if (auto sdaFunctionNode = dynamic_cast<SdaFunctionNode*>(node)) {
					m_memCtx->clearLocation(MemLocation::ALL());
				}
			}
		};
	};
};