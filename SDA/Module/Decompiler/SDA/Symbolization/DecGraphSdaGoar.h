#pragma once
#include "../DecSdaMisc.h"

namespace CE::Decompiler::Symbolization
{
	class SdaGoarBuilding
	{
	public:
		SdaGoarBuilding(DataTypeFactory* dataTypeFactory)
			: m_dataTypeFactory(dataTypeFactory)
		{}

		GoarTopNode* createGoar(ISdaNode* baseSdaNode, int64_t bitOffset = 0x0, std::list<ISdaNode*> sdaTerms = {}) {
			auto resultSdaNode = baseSdaNode;
			while (buildSingleGoar(resultSdaNode, bitOffset, sdaTerms));
			if (dynamic_cast<GoarNode*>(resultSdaNode)) {
				if (bitOffset != 0x0 || !sdaTerms.empty()) {
					//remaining offset and terms (maybe only in case of node being as LinearExpr)
					auto linearExpr = new LinearExpr(bitOffset / 0x8);
					for (auto castTerm : sdaTerms) {
						linearExpr->addTerm(castTerm);
					}
					resultSdaNode = new SdaGenericNode(linearExpr, resultSdaNode->getDataType());
				}

				bool isPointer = baseSdaNode->getDataType()->isPointer();
				if (isPointer) {
					if (auto addrGetting = dynamic_cast<IAddressGetting*>(baseSdaNode)) {
						addrGetting->setAddrGetting(false);
					}
				}
				return new GoarTopNode(resultSdaNode, isPointer);
			}
			return nullptr;
		}
	private:
		DataTypeFactory* m_dataTypeFactory;

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
			ptrLevels.pop_front();
			auto arrItemDataType = DataType::GetUnit(baseDataType, ptrLevels);
			auto arrItemSize = arrItemDataType->getSize();

			ISdaNode* indexNode = nullptr;
			int indexSize = 0x4; //todo: long long(8 bytes) index?
			for (auto it = terms.begin(); it != terms.end(); it++) {
				auto sdaNode = *it;
				int64_t defMultiplier = 1;
				int64_t* multiplier = &defMultiplier;
				if (auto sdaGenTermNode = dynamic_cast<SdaGenericNode*>(sdaNode)) {
					if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenTermNode->getNode())) {
						if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(opNode->m_rightNode)) {
							if (opNode->m_operation == Mul) {
								multiplier = (int64_t*)&sdaNumberLeaf->m_value;
							}
						}
					}
				}
				if (*multiplier % arrItemSize == 0x0) {
					*multiplier /= arrItemSize;
					if (*multiplier == 1) {
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
				sdaNode = new GoarArrayNode(sdaNode, indexNode, arrItemDataType);
				return true;
			}
			return false;
		}
	};
};