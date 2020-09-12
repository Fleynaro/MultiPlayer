#pragma once
#include "../DecSdaMisc.h"

namespace CE::Decompiler::Optimization
{
	using namespace ExprTree;

	class MemoryOptimization
	{
		class MemoryContext
		{
			struct Location {
				enum LOCATION_TYPE {
					STACK,
					GLOBAL,
					IMPLICIT
				};
				LOCATION_TYPE m_type;
				ObjectHash::Hash m_baseAddrHash;
				int64_t m_offset;
				int m_locSize;
				int m_valueSize;

				Location() = default;

				Location(LOCATION_TYPE type, ObjectHash::Hash baseAddrHash, int64_t offset, int locSize, int valueSize)
					: m_type(type), m_baseAddrHash(baseAddrHash), m_offset(offset), m_locSize(locSize), m_valueSize(valueSize)
				{}
			};

			struct MemoryValue {
				Location m_location;
				INode* m_node;
			};

			struct ReadSnapshot {
				Location m_location;
				Symbol::MemoryVariable* m_memVar;
			};

			std::list<MemoryValue> m_memValues;
			std::list<ReadSnapshot> m_memReadSnapshots;
		public:
			MemoryContext()
			{}

			void addMemReadSnapshot(Symbol::MemoryVariable* memVar) {
				ReadSnapshot readSnapshot;
				readSnapshot.m_location = getLocation(memVar->m_loadValueExpr);
				readSnapshot.m_memVar = memVar;
				m_memReadSnapshots.push_back(readSnapshot);
			}
			
			bool tryToGetLocation(ISdaNode* sdaNode, Location& location) {
				bool result = false;
				if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(sdaNode)) {
					if (auto readValueNode = dynamic_cast<ReadValueNode*>(sdaGenNode->getNode())) {
						//*{uint32_t*}(&stack_0x30 + param1 * 0x4)
						if (auto addrSdaGenNode = dynamic_cast<SdaGenericNode*>(readValueNode->getAddress())) {
							if (auto linearExpr = dynamic_cast<LinearExpr*>(addrSdaGenNode->getNode())) {
								ISdaNode* baseSdaNode = nullptr;
								for (auto term : linearExpr->getTerms()) {
									if (auto sdaTermNode = dynamic_cast<ISdaNode*>(term)) {
										if (sdaTermNode->getDataType()->isPointer()) {
											baseSdaNode = sdaTermNode;
											break;
										}
									}
								}
								if (baseSdaNode) {
									if (tryToGetLocation(baseSdaNode, location)) {
										location.m_locSize = -1;
										result = true;
									}
								}
							}
						}

					}
				}
				else if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(sdaNode)) {
					if (auto sdaSymbol = dynamic_cast<SdaSymbolLeaf*>(sdaSymbolLeaf->getSdaSymbol())) {

					}
				}

				if (result) {
					location.m_valueSize = sdaNode->getDataType()->getSize();
				}
				return result;
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

				if (auto assignmentNode = dynamic_cast<AssignmentNode*>(node)) {
					if (auto symbolLeaf = dynamic_cast<SymbolLeaf*>(assignmentNode->getDstNode())) {
						if (auto memVar = dynamic_cast<Symbol::MemoryVariable*>(symbolLeaf->m_symbol)) {

						}
					}
				}
			}
		};
	};
};