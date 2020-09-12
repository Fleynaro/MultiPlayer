#pragma once
#include "../DecSdaMisc.h"

namespace CE::Decompiler::Optimization
{
	using namespace ExprTree;

	class MemoryOptimization
	{
		struct Location {
			enum LOCATION_TYPE {
				STACK,
				GLOBAL,
				IMPLICIT
			};
			LOCATION_TYPE m_type;
			ObjectHash::Hash m_baseAddrHash = 0x0;
			int64_t m_offset = 0x0;
			int m_locSize = 0x0;
			int m_valueSize = 0x0;

			Location() = default;

			Location(LOCATION_TYPE type, ObjectHash::Hash baseAddrHash, int64_t offset, int locSize, int valueSize)
				: m_type(type), m_baseAddrHash(baseAddrHash), m_offset(offset), m_locSize(locSize), m_valueSize(valueSize)
			{}

			bool intersect(const Location& location) {
				if (m_type != location.m_type)
					return false;
				if (m_baseAddrHash != location.m_baseAddrHash)
					return false;
				return !(m_offset + m_locSize <= location.m_offset || location.m_offset + location.m_locSize <= m_offset);
			}

			bool equal(const Location& location) {
				return m_type == location.m_type
					&& m_baseAddrHash == location.m_baseAddrHash
					&& m_offset == location.m_offset
					&& m_locSize == location.m_locSize;
			}
		};

		class MemoryContext
		{
			struct MemoryValue {
				Location m_location;
				ISdaNode* m_node;
			};

			struct ReadSnapshot {
				Location m_location;
				CE::Symbol::AutoSdaSymbol* m_memVar;
			};

			std::list<MemoryValue> m_memValues;
			std::map<CE::Symbol::AutoSdaSymbol*, ReadSnapshot> m_memReadSnapshots;
		public:
			MemoryContext()
			{}

			ISdaNode* getMemValue(Location location) {
				for (auto it = m_memValues.begin(); it != m_memValues.end(); it++) {
					if (it->m_location.equal(location)) {
						if (it->m_location.m_valueSize == it->m_location.m_locSize) {
							return it->m_node;
						}
						return nullptr;
					}
				}
				return nullptr;
			}

			void addMemValue(Location location, ISdaNode* sdaNode) {
				clearLocation(location);
				MemoryValue memoryValue;
				memoryValue.m_location = location;
				memoryValue.m_node = sdaNode;
				m_memValues.push_back(memoryValue);
			}

			ReadSnapshot* getMemReadSnapshot(CE::Symbol::AutoSdaSymbol* memVar) {
				auto it = m_memReadSnapshots.find(memVar);
				if (it == m_memReadSnapshots.end())
					return nullptr;
				return &it->second;
			}

			void addMemReadSnapshot(CE::Symbol::AutoSdaSymbol* memVar, Location location) {
				ReadSnapshot readSnapshot;
				readSnapshot.m_location = location;
				readSnapshot.m_memVar = memVar;
				m_memReadSnapshots[memVar] = readSnapshot;
			}

			void clearLocation(Location location) {
				for (auto it = m_memValues.begin(); it != m_memValues.end(); it ++) {
					if (it->m_location.intersect(location)) {
						m_memValues.erase(it);
					}
				}
				for (auto it = m_memReadSnapshots.begin(); it != m_memReadSnapshots.end(); it ++) {
					if (it->second.m_location.intersect(location)) {
						m_memReadSnapshots.erase(it);
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
						if (auto dstSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getDstNode())) {
							if (auto srcSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getSrcNode())) {
								Location dstLocation;
								if (TryToGetLocation(dstSdaNode, dstLocation)) {
									m_memCtx->addMemValue(dstLocation, srcSdaNode);
								}
								else {
									if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(assignmentNode->getDstNode())) {
										if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(sdaSymbolLeaf->getSdaSymbol())) {
											if (autoSdaSymbol->getType() == CE::Symbol::LOCAL_INSTR_VAR) {
												Location srcLocation;
												if (TryToGetLocation(srcSdaNode, srcLocation)) {
													m_memCtx->addMemValue(srcLocation, srcSdaNode);
													m_memCtx->addMemReadSnapshot(autoSdaSymbol, srcLocation);
												}
											}
										}
									}
								}
							}
						}
					}
				}

				if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(node)) {
					if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(sdaSymbolLeaf->getSdaSymbol())) {
						if (autoSdaSymbol->getType() == CE::Symbol::LOCAL_INSTR_VAR) {
							auto readSnapshot = m_memCtx->getMemReadSnapshot(autoSdaSymbol);
							if (readSnapshot) {
								auto valueNode = m_memCtx->getMemValue(readSnapshot->m_location);
								if (valueNode) {
									sdaSymbolLeaf->replaceWith(valueNode->clone());
									delete sdaSymbolLeaf;
								}
							}
						}
					}
				}
			}
		};

		static bool TryToGetLocation(ISdaNode* sdaNode, Location& location) {
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
								if (TryToGetLocation(baseSdaNode, location)) {
									location.m_locSize = -1;
									result = true;
								}
							}
						}
					}

				}
			}
			else if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(sdaNode)) {
				if (auto sdaMemSymbol = dynamic_cast<CE::Symbol::IMemorySymbol*>(sdaSymbolLeaf->getSdaSymbol())) {
					location.m_type = (sdaMemSymbol->getType() == CE::Symbol::LOCAL_STACK_VAR ? Location::STACK : Location::GLOBAL);
					location.m_offset = sdaMemSymbol->getOffset();
					result = true;
				}
			}

			if (result) {
				location.m_valueSize = sdaNode->getDataType()->getSize();
				if (!location.m_locSize)
					location.m_locSize = location.m_valueSize;
			}
			return result;
		}
	};
};