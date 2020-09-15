#pragma once
#include "../DecGraphModification.h"
#include "DecGraphSdaGoar.h"

namespace CE::Decompiler::Symbolization
{
	class SdaDataTypesCalculating : public SdaGraphModification
	{
	public:
		SdaDataTypesCalculating(SdaCodeGraph* sdaCodeGraph, Signature* signature, DataTypeFactory* dataTypeFactory)
			: SdaGraphModification(sdaCodeGraph), m_signature(signature), m_dataTypeFactory(dataTypeFactory)
		{}

		void start() override {
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
		Signature* m_signature;
		DataTypeFactory* m_dataTypeFactory;
		bool m_nextPassRequiared = false;

		void pass(const std::list<Block::BlockTopNode*>& allTopNodes) {
			for (auto topNode : allTopNodes) {
				auto node = topNode->getNode();
				INode::UpdateDebugInfo(node);
				calculateDataTypes(node);

				//for return statement
				if (auto returnTopNode = dynamic_cast<Block::ReturnTopNode*>(topNode)) {
					if (auto returnNode = dynamic_cast<ISdaNode*>(returnTopNode->getNode())) {
						auto retDataType = m_signature->getReturnType();
						cast(returnNode, retDataType);
					}
				}
			}
		}

		void calculateDataTypes(INode* node) {
			IterateChildNodes(node, [&](INode* childNode) {
				calculateDataTypes(childNode);
				});
			calculateDataType(node);
		}

		void calculateDataType(INode* node) {
			auto sdaNode = dynamic_cast<ISdaNode*>(node);
			if (!sdaNode)
				return;
			sdaNode->getCast()->clearCast();

			if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(sdaNode))
			{
				/*
				TODO: for operation >> and & of not-pointer object with size up to 8 bytes
				Create SUBPIECE node combined both >> and & operation to extract a field of a object
				Next call createGoar passing object and offset
				*/
				if (auto castNode = dynamic_cast<CastNode*>(sdaGenNode->getNode())) {
					if (auto srcSdaNode = dynamic_cast<ISdaNode*>(castNode->getNode())) {
						auto srcDataType = srcSdaNode->getDataType();
						auto srcBaseDataType = srcDataType->getBaseType();
						auto castDataType = m_dataTypeFactory->getDefaultType(castNode->getSize(), castNode->isSigned());
						sdaGenNode->setDataType(castDataType);
						if (srcDataType->isPointer() || castNode->isSigned() != srcBaseDataType->isSigned() || castNode->getSize() != srcBaseDataType->getSize()) {
							cast(srcSdaNode, castDataType);
						}
					}
				}
				else if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenNode->getNode())) {
					auto maskSize = opNode->getMask().getSize();
					if (auto sdaLeftSdaNode = dynamic_cast<ISdaNode*>(opNode->m_leftNode)) {
						if (auto sdaRightSdaNode = dynamic_cast<ISdaNode*>(opNode->m_rightNode)) {
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
					auto sdaConstTerm = dynamic_cast<SdaNumberLeaf*>(linearExpr->getConstTerm());

					//calculate the data type
					DataTypePtr calcDataType = sdaConstTerm->getDataType();
					ISdaNode* baseSdaNode = nullptr;
					int baseNodeIdx = 0;
					int idx = 0;
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTermNode = dynamic_cast<ISdaNode*>(term)) {
							calcDataType = getDataTypeToCastTo(calcDataType, sdaTermNode->getDataType());
							if (sdaTermNode->getDataType()->isPointer()) {
								baseSdaNode = sdaTermNode;
								baseNodeIdx = idx;
								break;
							}
						}
						idx++;
					}
					if (maskSize != calcDataType->getSize())
						calcDataType = m_dataTypeFactory->getDefaultType(maskSize);
					//cast to the data type
					cast(sdaConstTerm, calcDataType);
					for (auto termNode : linearExpr->getTerms()) {
						if (auto sdaTermNode = dynamic_cast<ISdaNode*>(termNode)) {
							cast(sdaTermNode, calcDataType);
						}
					}
					sdaGenNode->setDataType(calcDataType);

					if (baseSdaNode) {
						auto unknownLocation = new UnknownLocation(linearExpr, baseNodeIdx);
						linearExpr->addParentNode(unknownLocation);
						sdaGenNode->replaceWith(unknownLocation);
						delete sdaGenNode;
						calculateDataType(unknownLocation);
					}
				}
				else if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaGenNode->getNode())) {
					if (auto dstSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getDstNode())) {
						if (auto srcSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getSrcNode())) {
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
				else if (auto condNode = dynamic_cast<AbstractCondition*>(sdaGenNode->getNode())) {
					auto boolType = m_dataTypeFactory->getType(SystemType::Bool);
					sdaGenNode->setDataType(boolType);
				}
			}
			else if (auto sdaReadValueNode = dynamic_cast<SdaReadValueNode*>(sdaNode)) {
				auto addrSdaNode = sdaReadValueNode->getAddress();
				if (addrSdaNode->getDataType()->isPointer()) {
					auto addrDataType = DataType::CloneUnit(addrSdaNode->getDataType());
					addrDataType->removePointerLevelOutOfFront();
					if (sdaReadValueNode->getSize() == addrDataType->getSize()) {
						if (auto addrGettingNode = dynamic_cast<IMappedToMemory*>(addrSdaNode)) {
							if (addrGettingNode->isAddrGetting()) {
								addrGettingNode->setAddrGetting(false);
								sdaReadValueNode->replaceWith(addrGettingNode);
								delete sdaReadValueNode;
								return;
							}
						}
						sdaReadValueNode->setDataType(addrDataType);
						return;
					}
				}
				auto defDataType = sdaReadValueNode->getDataType();
				auto defPtrDataType = DataType::CloneUnit(defDataType);
				defPtrDataType->addPointerLevelInFront();
				cast(addrSdaNode, defPtrDataType);
			}
			else if (auto sdaFunctionNode = dynamic_cast<SdaFunctionNode*>(sdaNode)) {
				if (auto dstCastNode = dynamic_cast<ISdaNode*>(sdaFunctionNode->getDestination())) {
					if (auto signature = dynamic_cast<DataType::Signature*>(dstCastNode->getDataType()->getType())) {
						if (!sdaFunctionNode->getSignature()) {
							sdaFunctionNode->setSignature(signature);
						}
					}
				}

				int paramIdx = 1;
				for (auto paramNode : sdaFunctionNode->getParamNodes()) {
					if (auto paramSdaNode = dynamic_cast<ISdaNode*>(paramNode)) {
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
			else if (auto unknownLocation = dynamic_cast<UnknownLocation*>(sdaNode)) {
				//if it is a pointer, see to make sure it could'be transformed to an array or a class field
				if (auto goarNode = SdaGoarBuilding(m_dataTypeFactory, unknownLocation).create()) {
					unknownLocation->replaceWith(goarNode);
					delete unknownLocation;
				}
			}
		}

		void cast(ISdaNode* sdaNode, DataTypePtr toDataType) {
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
			sdaNode->getCast()->setCastDataType(toDataType, isExplicitCast(sdaNode->getDataType(), toDataType));
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

		bool canDataTypeBeChangedTo(ISdaNode* sdaNode, DataTypePtr toDataType) {
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