#pragma once
#include "DecSdaMisc.h"

namespace CE::Decompiler::Symbolization
{
	class SdaDataTypesCalculating
	{
	public:
		SdaDataTypesCalculating(SdaCodeGraph* sdaCodeGraph, Signature* signature, DataTypeFactory* dataTypeFactory)
			: m_sdaCodeGraph(sdaCodeGraph), m_signature(signature), m_dataTypeFactory(dataTypeFactory)
		{}

		void start() {
			std::list<Block::BlockTopNode*> allTopNodes;
			for (const auto decBlock : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				auto list = decBlock->getAllTopNodes();
				allTopNodes.insert(allTopNodes.end(), list.begin(), list.end());
			}
			do {
				m_nextPassRequiared = false;
				pass(allTopNodes);
			} while (m_nextPassRequiared);
		}
	private:
		SdaCodeGraph* m_sdaCodeGraph;
		Signature* m_signature;
		DataTypeFactory* m_dataTypeFactory;
		bool m_nextPassRequiared = false;

		void pass(const std::list<Block::BlockTopNode*>& allTopNodes) {
			for (auto topNode : allTopNodes) {
				auto node = topNode->getNode();
				Node::UpdateDebugInfo(node);
				calculateDataTypes(node);
			}
		}

		bool buildGoar(AbstractSdaNode*& sdaNode, int64_t& bitOffset, std::list<AbstractSdaNode*>& terms) {
			auto dataType = sdaNode->getDataType();
			auto ptrLevels = dataType->getPointerLevels();
			//check to see if the data type is a pointer
			if (ptrLevels.empty())
				return false;
			if (*ptrLevels.begin() != 1)
				return false;
			ptrLevels.pop_front();

			//remove the pointer and see what we have
			auto baseDataType = dataType->getBaseType();
			if (ptrLevels.empty()) {
				//try making a field
				if (auto structure = dynamic_cast<DataType::Structure*>(baseDataType)) {
					auto field = structure->getField((int)bitOffset);
					auto dataType = DataType::CloneUnit(field->getDataType());
					dataType->addPointerLevelInFront();
					sdaNode = new GoarNode(dataType, sdaNode, field->getAbsBitOffset(), nullptr, 0x0);
					bitOffset -= field->getAbsBitOffset();
					return true;
				}
				return false;
			}

			//try making an array
			//important: array is like a structure with stored items can be linearly addressed
			//if it is array, not pointer (like a structure, an array item like a field)
			if (*ptrLevels.begin() != 1)
				ptrLevels.pop_front();
			auto arrItemDataType = DataType::GetUnit(baseDataType, ptrLevels);
			auto arrItemSize = arrItemDataType->getSize();

			AbstractSdaNode* indexNode = nullptr;
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
								if (auto leftSdaNode = dynamic_cast<AbstractSdaNode*>(opNode->m_leftNode)) {
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
				arrItemDataType->addPointerLevelInFront();
				sdaNode = new GoarNode(arrItemDataType, sdaNode, 0x0, indexNode, 0x0);
				return true;
			}
			return false;
		}

		void buildGoar(AbstractSdaNode* node) {
			AbstractSdaNode* baseSdaNode = node;
			int64_t bitOffset = 0x0;
			std::list<AbstractSdaNode*> sdaTerms;
			if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(node)) {
				if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaGenNode->getNode())) {
					baseSdaNode = nullptr;
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTerm = dynamic_cast<AbstractSdaNode*>(term)) {
							if (!baseSdaNode && sdaTerm->getSrcDataType()->isPointer()) {
								baseSdaNode = sdaTerm;
							}
							else {
								sdaTerms.push_back(sdaTerm);
							}
						}
					}
					bitOffset = linearExpr->getConstTermValue() * 0x8;
				}
			}

			if (baseSdaNode) {
				auto resultSdaNode = baseSdaNode;
				while (buildGoar(resultSdaNode, bitOffset, sdaTerms));
				if (auto resultGoarNode = dynamic_cast<GoarNode*>(resultSdaNode)) {
					if (bitOffset != 0x0 || !sdaTerms.empty()) {
						//remaining offset and terms (maybe only in case of node being as LinearExpr)
						auto linearExpr = new LinearExpr(bitOffset / 0x8);
						for (auto castTerm : sdaTerms) {
							linearExpr->addTerm(castTerm);
						}
						resultSdaNode = new SdaGenericNode(linearExpr, node->getDataType());
					}

					node->replaceWith(resultSdaNode);
					delete node;
				}
			}
		}

		void calculateDataTypes(Node* node) {
			IterateChildNodes(node, [&](Node* childNode) {
				calculateDataTypes(childNode);
				});

			auto sdaNode = dynamic_cast<AbstractSdaNode*>(node);
			if (!sdaNode)
				return;
			sdaNode->clearCast();

			if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(sdaNode))
			{
				if (auto castNode = dynamic_cast<CastNode*>(sdaGenNode->getNode())) {
					if (auto srcSdaNode = dynamic_cast<AbstractSdaNode*>(castNode->getNode())) {
						auto srcDataType = srcSdaNode->getDataType();
						auto srcBaseDataType = srcDataType->getBaseType();
						auto castDataType = m_dataTypeFactory->getDefaultType(castNode->getSize(), castNode->isSigned());
						sdaGenNode->setDataType(castDataType);
						if (srcDataType->isPointer() || castNode->isSigned() != srcBaseDataType->isSigned() || castNode->getSize() != srcBaseDataType->getSize()) {
							cast(srcSdaNode, castDataType);
						}
					}
				}
				else if (auto readValueNode = dynamic_cast<ReadValueNode*>(sdaGenNode->getNode())) {
					if (auto addrSdaNode = dynamic_cast<AbstractSdaNode*>(readValueNode->getAddress())) {
						auto addrDataType = addrSdaNode->getDataType();
						if (addrDataType->isPointer() && readValueNode->getSize() == addrDataType->getBaseType()->getSize()) {
							auto resultDataType = DataType::CloneUnit(addrDataType);
							resultDataType->removePointerLevelOutOfFront();
							if (auto addrGoarNode = dynamic_cast<GoarNode*>(addrSdaNode)) {
								addrGoarNode->m_isReading = true;
								addrGoarNode->setDataType(resultDataType);
								sdaGenNode->replaceWith(addrGoarNode);
								delete sdaGenNode;
								return;
							}
							else {
								sdaGenNode->setDataType(resultDataType);
							}
						}
						else {
							auto defDataType = m_dataTypeFactory->getDefaultType(readValueNode->getSize());
							auto defPtrDataType = DataType::CloneUnit(defDataType);
							defPtrDataType->addPointerLevelInFront();
							cast(addrSdaNode, defPtrDataType);
							sdaGenNode->setDataType(defDataType);
						}
					}
				}
				else if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenNode->getNode())) {
					auto maskSize = opNode->getMask().getSize();
					if (auto sdaLeftSdaNode = dynamic_cast<AbstractSdaNode*>(opNode->m_leftNode)) {
						if (auto sdaRightSdaNode = dynamic_cast<AbstractSdaNode*>(opNode->m_rightNode)) {
							DataTypePtr leftNodeDataType = sdaLeftSdaNode->getDataType();
							DataTypePtr rightNodeDataType;
							if (opNode->m_operation == Shr || opNode->m_operation == Shl) {
								rightNodeDataType = leftNodeDataType;
							}
							else {
								rightNodeDataType = sdaRightSdaNode->getDataType();
							}
							auto calcDataType = getDataTypeToCastTo(sdaLeftSdaNode->getDataType(), sdaRightSdaNode->getDataType());
							if (maskSize != calcDataType->getSize())
								calcDataType = m_dataTypeFactory->getDefaultType(maskSize);
							cast(sdaLeftSdaNode, calcDataType);
							cast(sdaRightSdaNode, calcDataType);
							sdaGenNode->setDataType(calcDataType);
						}
					}
				}
				else if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaGenNode->getNode())) {
					auto maskSize = linearExpr->getMask().getSize();
					auto sdaConstTerm = dynamic_cast<AbstractSdaNode*>(linearExpr->getConstTerm());

					//calculate the data type
					DataTypePtr calcDataType = sdaConstTerm->getDataType();
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTermNode = dynamic_cast<AbstractSdaNode*>(term)) {
							calcDataType = getDataTypeToCastTo(calcDataType, sdaTermNode->getDataType());
						}
					}
					if (maskSize != calcDataType->getSize())
						calcDataType = m_dataTypeFactory->getDefaultType(maskSize);

					//cast to the data type
					cast(sdaConstTerm, calcDataType);
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTermNode = dynamic_cast<AbstractSdaNode*>(term)) {
							cast(sdaTermNode, calcDataType);
						}
					}
					sdaGenNode->setDataType(calcDataType);
				}
				else if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaGenNode->getNode())) {
					if (auto dstSdaNode = dynamic_cast<AbstractSdaNode*>(assignmentNode->getDstNode())) {
						if (auto srcSdaNode = dynamic_cast<AbstractSdaNode*>(assignmentNode->getSrcNode())) {
							auto dstNodeDataType = dstSdaNode->getDataType();
							auto srcNodeDataType = srcSdaNode->getDataType();

							if (canDataTypeBeChangedTo(dstSdaNode, srcNodeDataType)) {
								dstSdaNode->setDataType(srcNodeDataType);
								m_nextPassRequiared = true;
							}
							else {
								cast(srcSdaNode, dstNodeDataType);
								sdaGenNode->setDataType(dstNodeDataType);
							}
						}
					}
				}
				else if (auto condNode = dynamic_cast<ICondition*>(sdaGenNode->getNode())) {
					auto boolType = m_dataTypeFactory->getType(SystemType::Bool);
					sdaGenNode->setDataType(boolType);
				}
			}
			else if (auto sdaFunctionNode = dynamic_cast<SdaFunctionNode*>(sdaNode)) {
				if (auto dstCastNode = dynamic_cast<AbstractSdaNode*>(sdaFunctionNode->getDestination())) {
					if (auto signature = dynamic_cast<DataType::Signature*>(dstCastNode->getDataType()->getType())) {
						if (!sdaFunctionNode->getSignature()) {
							sdaFunctionNode->setSignature(signature);
						}
					}
				}

				int paramIdx = 1;
				for (auto paramNode : sdaFunctionNode->getParamNodes()) {
					if (auto paramSdaNode = dynamic_cast<AbstractSdaNode*>(paramNode)) {
						auto paramNodeDataType = paramSdaNode->getDataType();
						if (sdaFunctionNode->getSignature()) {
							auto paramNodeProperDataType = sdaFunctionNode->getParamDataType(paramIdx);
							cast(paramSdaNode, paramNodeProperDataType);
						}
						sdaFunctionNode->getTypeContext()->setParamDataTypeWithPriority(paramIdx, paramNodeDataType);
					}
					paramIdx++;
				}
			}
			else if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(sdaNode)) {
				auto valueMask = sdaNumberLeaf->getMask();
				sdaNumberLeaf->setDataType(m_dataTypeFactory->getDataTypeByNumber(sdaNumberLeaf->m_value));
			}
			else if (auto goarNode = dynamic_cast<GoarNode*>(sdaNode)) {
				//...
				return;
			}

			if (dynamic_cast<LinearExpr*>(sdaNode->getParentNode()))
				return;
			//if it is a pointer, see to make sure it could'be transformed to an array or a class field
			if (sdaNode->getDataType()->isPointer()) {
				buildGoar(sdaNode);
			}

			//for return statement
			if (auto returnTopNode = dynamic_cast<Block::ReturnTopNode*>(sdaNode->getParentNode())) {
				if (auto returnNode = dynamic_cast<AbstractSdaNode*>(returnTopNode->getNode())) {
					auto retDataType = m_signature->getReturnType();
					cast(returnNode, retDataType);
				}
			}
		}

		void cast(AbstractSdaNode* sdaNode, DataTypePtr toDataType) {
			//exception (change rather number view between HEX and non-HEX than do the cast)
			if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(sdaNode)) {
				if (!toDataType->isPointer()) {
					if (toDataType->getSize() >= sdaNumberLeaf->getDataType()->getSize()) {
						sdaNumberLeaf->setDataType(toDataType);
						return;
					}
				}
			}
			//the cast itself
			sdaNode->setCastDataType(toDataType, isExplicitCast(sdaNode->getDataType(), toDataType));
			if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaNode)) {
				if (toDataType->isPointer()) {
					SdaSymbolLeaf* sdaTermLeafToChange = nullptr;
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTermLeaf = dynamic_cast<SdaSymbolLeaf*>(term)) {
							if (canDataTypeBeChangedTo(sdaTermLeaf, toDataType)) {
								sdaTermLeafToChange = sdaTermLeaf;
								if (sdaTermLeaf->getSdaSymbol()->getDataType()->isPointer())
									break;
							}
						}
					}
					if (sdaTermLeafToChange) {
						sdaTermLeafToChange->setDataType(toDataType);
						m_nextPassRequiared = true;
					}
				}
			}
			else {
				if (canDataTypeBeChangedTo(sdaNode, toDataType)) {
					sdaNode->setDataType(toDataType);
					m_nextPassRequiared = true;
				}
			}
		}

		bool canDataTypeBeChangedTo(AbstractSdaNode* sdaNode, DataTypePtr toDataType) {
			if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(sdaNode)) {
				if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(sdaSymbolLeaf->getSdaSymbol())) {
					auto symbolDataType = autoSdaSymbol->getDataType();
					return symbolDataType->getSize() == toDataType->getSize() && symbolDataType->getPriority() < toDataType->getPriority();
				}
			}
			return false;
		}

		bool isExplicitCast(DataTypePtr fromType, DataTypePtr toType) {
			auto fromBaseType = fromType->getBaseType();
			auto toBaseType = toType->getBaseType();
			if (auto fromSysType = dynamic_cast<SystemType*>(fromBaseType)) {
				if (auto toSysType = dynamic_cast<SystemType*>(toBaseType)) {
					if (fromSysType->isSigned() != toSysType->isSigned())
						return true;
					if (fromBaseType->getSize() > toBaseType->getSize())
						return true;
				}
			}
			auto ptrList1 = fromType->getPointerLevels();
			auto ptrList2 = toType->getPointerLevels();
			if (ptrList1.empty() && ptrList2.empty())
				return false;
			if (fromBaseType != toBaseType)
				return true;
			return !Unit::EqualPointerLvls(ptrList1, ptrList2);
		}

		DataTypePtr getDataTypeToCastTo(DataTypePtr type1, DataTypePtr type2) {
			auto priority1 = type1->getConversionPriority();
			auto priority2 = type2->getConversionPriority();
			if (priority1 == 0 && priority2 == 0)
				return m_dataTypeFactory->getType(SystemType::Int32);
			if (priority2 > priority1)
				return type2;
			return type1;
		}
	};
};