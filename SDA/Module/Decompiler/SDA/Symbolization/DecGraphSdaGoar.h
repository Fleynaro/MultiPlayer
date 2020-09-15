#pragma once
#include "../DecSdaMisc.h"

namespace CE::Decompiler::Symbolization
{
	class SdaGoarBuilding
	{
		DataTypeFactory* m_dataTypeFactory;
		ISdaNode* m_baseSdaNode;
		int64_t m_bitOffset;
		std::list<ISdaNode*> m_sdaTerms;
	public:
		SdaGoarBuilding(DataTypeFactory* dataTypeFactory, ISdaNode* baseSdaNode, int64_t bitOffset = 0x0, std::list<ISdaNode*> sdaTerms = {})
			: m_dataTypeFactory(dataTypeFactory), m_baseSdaNode(baseSdaNode), m_bitOffset(bitOffset), m_sdaTerms(sdaTerms)
		{}

		SdaGoarBuilding(DataTypeFactory* dataTypeFactory, UnknownLocation* unknownLocation)
			: m_dataTypeFactory(dataTypeFactory), m_baseSdaNode(unknownLocation->getBaseSdaNode()), m_bitOffset(unknownLocation->getConstTermValue() * 0x8)
		{
			for (auto term : unknownLocation->getArrTerms()) {
				m_sdaTerms.push_back(term.m_node);
			}
		}

		ISdaNode* create() {
			auto resultSdaNode = m_baseSdaNode;
			auto resultBitOffset = m_bitOffset;
			while (buildSingleGoar(resultSdaNode, resultBitOffset, m_sdaTerms));

			if (dynamic_cast<GoarNode*>(resultSdaNode)) {
				bool isPointer = m_baseSdaNode->getDataType()->isPointer();
				if (isPointer) {
					if (auto addrGetting = dynamic_cast<IMappedToMemory*>(m_baseSdaNode)) {
						addrGetting->setAddrGetting(false);
					}
				}
				resultSdaNode = new GoarTopNode(resultSdaNode, m_baseSdaNode, m_bitOffset, isPointer);

				if (resultBitOffset != 0x0 || !m_sdaTerms.empty()) {
					//remaining offset and terms (maybe only in case of node being as LinearExpr)
					auto linearExpr = new LinearExpr(resultBitOffset / 0x8);
					linearExpr->addTerm(resultSdaNode);
					for (auto castTerm : m_sdaTerms) {
						linearExpr->addTerm(castTerm);
					}
					resultSdaNode = new UnknownLocation(linearExpr, 0);
				}
				return resultSdaNode;
			}
			return nullptr;
		}

	private:
		bool buildSingleGoar(ISdaNode*& sdaNode, int64_t& bitOffset, std::list<ISdaNode*>& terms) {
			auto dataType = sdaNode->getDataType();
			auto ptrLevels = dataType->getPointerLevels();
			auto baseDataType = dataType->getBaseType();

			//if is a structure and not a pointer or one-level pointer
			if (ptrLevels.empty() || ptrLevels.size() == 1 && *ptrLevels.begin() == 1) {
				//try making a field
				if (auto structure = dynamic_cast<DataType::Structure*>(baseDataType)) {
					auto field = structure->getField((int)bitOffset);
					if (field->isDefault())
						return false;
					sdaNode = new GoarFieldNode(sdaNode, field);
					bitOffset -= field->getAbsBitOffset();
					return true;
				}

				//if no a pointer or an array
				if (ptrLevels.empty())
					return false;
			}
			
			//if is a pointer(int*) or an array(int[2]) that supported addressing with [index] then try making an array
			//important: array is like a structure with stored items can be linearly addressed (an array item like a field)
			if (ptrLevels.size() >= 2 && *ptrLevels.begin() == 1 && *std::next(ptrLevels.begin()) != 1) {
				//in C++ no declaration statements like this: int*[2][3] pArr;	(pointer to an array)
				//then remove pointer
				ptrLevels.pop_front();
			}
			int arrItemsMaxCount = *ptrLevels.begin();
			ptrLevels.pop_front();
			auto arrItemDataType = DataType::GetUnit(baseDataType, ptrLevels);
			auto arrItemSize = arrItemDataType->getSize();

			ISdaNode* indexNode = nullptr;
			int indexSize = 0x4; //todo: long long(8 bytes) index?
			for (auto it = terms.begin(); it != terms.end(); it++) {
				auto sdaNode = *it;
				int64_t defMultiplier = 1;
				int64_t* multiplier = &defMultiplier;
				bool hasMultiplier = false;
				if (auto sdaGenTermNode = dynamic_cast<SdaGenericNode*>(sdaNode)) {
					if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenTermNode->getNode())) {
						if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(opNode->m_rightNode)) {
							if (opNode->m_operation == Mul) {
								multiplier = (int64_t*)&sdaNumberLeaf->m_value;
								hasMultiplier = true;
							}
						}
					}
				}
				if (*multiplier % arrItemSize == 0x0) {
					*multiplier /= arrItemSize;
					if (*multiplier == 1 && hasMultiplier) {
						//optimization: remove operational node (add)
						if (auto sdaGenTermNode = dynamic_cast<SdaGenericNode*>(sdaNode)) {
							if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenTermNode->getNode())) {
								if (auto leftSdaNode = dynamic_cast<ISdaNode*>(opNode->m_leftNode)) {
									sdaGenTermNode->replaceWith(sdaNode = leftSdaNode);
									delete sdaGenTermNode;
								}
							}
						}
					}

					if (indexNode) {
						auto indexNodeDataType = indexNode->getDataType();
						indexNode = new SdaGenericNode(new OperationalNode(indexNode, sdaNode, Add, BitMask64(indexSize)), indexNodeDataType); //todo: linear expr, another type
					}
					else {
						indexNode = sdaNode;
					}
					terms.erase(it);
				}
			}

			if (bitOffset != 0x0) {
				auto arrItemBitSize = arrItemSize * 0x8;
				auto constIndex = bitOffset / arrItemBitSize;
				if (constIndex != 0x0 || !indexNode) {
					bitOffset = bitOffset % arrItemBitSize;
					auto constIndexNode = new SdaNumberLeaf(uint64_t(constIndex));
					constIndexNode->setDataType(m_dataTypeFactory->getDefaultType(indexSize)); //need?
					if (indexNode) {
						auto indexNodeDataType = indexNode->getDataType();
						indexNode = new SdaGenericNode(new OperationalNode(indexNode, constIndexNode, Add, BitMask64(indexSize)), indexNodeDataType);
					}
					else {
						indexNode = constIndexNode;
					}
				}
			}

			if (indexNode) {
				sdaNode = new GoarArrayNode(sdaNode, indexNode, arrItemDataType, arrItemsMaxCount);
				return true;
			}
			return false;
		}
	};
};