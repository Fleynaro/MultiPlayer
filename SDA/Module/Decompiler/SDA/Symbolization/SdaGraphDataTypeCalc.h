#pragma once
#include "../SdaGraphModification.h"
#include "SdaGoarBuilder.h"

namespace CE::Decompiler::Symbolization
{
	//Calculating data types for all nodes and building GOAR structures
	class SdaDataTypesCalculater : public SdaGraphModification
	{
		Signature* m_signature;
		DataTypeFactory* m_dataTypeFactory;
		//used to proceed passing
		bool m_nextPassRequired = false;
	public:
		SdaDataTypesCalculater(SdaCodeGraph* sdaCodeGraph, Signature* signature, DataTypeFactory* dataTypeFactory)
			: SdaGraphModification(sdaCodeGraph), m_signature(signature), m_dataTypeFactory(dataTypeFactory)
		{}

		void start() override {
			std::list<Block::BlockTopNode*> allTopNodes;
			//gather all top nodes within the entire graph
			for (const auto decBlock : m_sdaCodeGraph->getDecGraph()->getDecompiledBlocks()) {
				auto list = decBlock->getAllTopNodes();
				allTopNodes.insert(allTopNodes.end(), list.begin(), list.end());
			}

			do {
				do {
					m_nextPassRequired = false;
					pass_up(allTopNodes);
				} while (m_nextPassRequired);
				pass_down(allTopNodes);
			} while (m_nextPassRequired);
		}

	private:
		//make a pass up through the specified top nodes
		void pass_up(const std::list<Block::BlockTopNode*>& topNodes) {
			for (auto topNode : topNodes) {
				auto node = topNode->getNode();
				INode::UpdateDebugInfo(node);
				calculateDataTypes(node);

				//for return statement
				if (m_signature) {
					if (auto returnTopNode = dynamic_cast<Block::ReturnTopNode*>(topNode)) {
						if (auto returnNode = dynamic_cast<ISdaNode*>(returnTopNode->getNode())) {
							auto retDataType = m_signature->getReturnType();
							cast(returnNode, retDataType);
						}
					}
				}
			}
		}

		//make a pass down through the specified top nodes
		void pass_down(const std::list<Block::BlockTopNode*>& topNodes) {
			for (auto topNode : topNodes) {
				auto node = topNode->getNode();
				INode::UpdateDebugInfo(node);
				moveExplicitCastsDown(node);
			}
		}

		void moveExplicitCastsDown(INode* node) {
			auto sdaNode = dynamic_cast<ISdaNode*>(node);
			if (!sdaNode || !sdaNode->getCast()->hasExplicitCast())
				return;
			auto castDataType = sdaNode->getCast()->getCastDataType();

			if (auto sdaGenNode = dynamic_cast<SdaGenericNode*>(sdaNode))
			{
				if (auto opNode = dynamic_cast<OperationalNode*>(sdaGenNode->getNode())) {
					if (!IsOperationUnsupportedToCalculate(opNode->m_operation)
						&& opNode->m_operation != Concat && opNode->m_operation != Subpiece) {
						if (auto sdaLeftSdaNode = dynamic_cast<ISdaNode*>(opNode->m_leftNode)) {
							if (auto sdaRightSdaNode = dynamic_cast<ISdaNode*>(opNode->m_rightNode)) {
								cast(sdaLeftSdaNode, castDataType);
								cast(sdaRightSdaNode, castDataType);
								sdaGenNode->setDataType(castDataType);
								sdaNode->getCast()->clearCast();
							}
						}
					}
				}
				// read value, assignments...
			}

			// last iterate over all childs
			node->iterateChildNodes([&](INode* childNode) {
				moveExplicitCastsDown(childNode);
				});
		}

	protected:
		virtual void calculateDataTypes(INode* node) {
			// first iterate over all childs
			node->iterateChildNodes([&](INode* childNode) {
				calculateDataTypes(childNode);
				});

			auto sdaNode = dynamic_cast<ISdaNode*>(node);
			if (!sdaNode)
				return;
			sdaNode->getCast()->clearCast();

			// method <cast> called for child nodes
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
					if (!IsOperationUnsupportedToCalculate(opNode->m_operation)
						&& opNode->m_operation != Concat && opNode->m_operation != Subpiece) {
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

								auto calcDataType = calcDataTypeForOperands(sdaLeftSdaNode->getDataType(), rightNodeDataType);
								if (opNode->isFloatingPoint()) { // floating operation used?
									calcDataType = calcDataTypeForOperands(calcDataType, m_dataTypeFactory->getDefaultType(maskSize, true, true));
								}
								if (maskSize != calcDataType->getSize()) {
									// todo: print warning
									calcDataType = m_dataTypeFactory->getDefaultType(maskSize);
								}
								cast(sdaLeftSdaNode, calcDataType);
								cast(sdaRightSdaNode, calcDataType);
								sdaGenNode->setDataType(calcDataType);
							}
						}
					}
				}
				else if (auto linearExpr = dynamic_cast<LinearExpr*>(sdaGenNode->getNode())) { // or it is a pointer with offset, or it is some linear operation
					auto sdaConstTerm = dynamic_cast<SdaNumberLeaf*>(linearExpr->getConstTerm());
					DataTypePtr calcPointerDataType = sdaConstTerm->getDataType();
					
					//finding a pointer among terms (base term)
					ISdaNode* sdaPointerNode = nullptr; // it is a pointer
					int baseNodeIdx = 0;
					int idx = 0;
					for (auto term : linearExpr->getTerms()) {
						if (auto sdaTermNode = dynamic_cast<ISdaNode*>(term)) {
							if (sdaTermNode->getDataType()->isPointer()) {
								sdaPointerNode = sdaTermNode;
								baseNodeIdx = idx;
								calcPointerDataType = m_dataTypeFactory->getDefaultType(0x8);
								break;
							}
							calcPointerDataType = calcDataTypeForOperands(calcPointerDataType, sdaTermNode->getDataType());
						}
						idx++;
					}

					//set the default data type (usually size of 8 bytes) for all terms (including the base)
					cast(sdaConstTerm, calcPointerDataType);
					for (auto termNode : linearExpr->getTerms()) {
						if (auto sdaTermNode = dynamic_cast<ISdaNode*>(termNode)) {
							cast(sdaTermNode, calcPointerDataType);
						}
					}

					//if we figure out a pointer then we guarantee it is always some unk location
					if (sdaPointerNode) {
						auto unknownLocation = new UnknownLocation(linearExpr, baseNodeIdx); //wrap LinearExpr 
						linearExpr->addParentNode(unknownLocation);
						sdaGenNode->replaceWith(unknownLocation);
						delete sdaGenNode;

						// should be (float*)((uint64_t)param1 + 0x10)
						//cast(unknownLocation, sdaPointerNode->getDataType());
						//then build a goar or anything
						handleUnknownLocation(unknownLocation);
					}
					else {
						// not a pointer, just some linear operation
						sdaGenNode->setDataType(calcPointerDataType);
					}
				}
				else if (auto assignmentNode = dynamic_cast<AssignmentNode*>(sdaGenNode->getNode())) {
					if (auto dstSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getDstNode())) {
						if (auto srcSdaNode = dynamic_cast<ISdaNode*>(assignmentNode->getSrcNode())) {
							auto dstNodeDataType = dstSdaNode->getDataType();
							auto srcNodeDataType = srcSdaNode->getDataType();

							if (dstNodeDataType->getSize() == srcNodeDataType->getSize() && dstNodeDataType->getPriority() < srcNodeDataType->getPriority()) {
								cast(dstSdaNode, srcNodeDataType);
								dstSdaNode->getCast()->clearCast();
								dstNodeDataType = dstSdaNode->getDataType();
							}

							cast(srcSdaNode, dstNodeDataType);
							sdaGenNode->setDataType(dstNodeDataType);
						}
					}
				}
				else if (auto condNode = dynamic_cast<AbstractCondition*>(sdaGenNode->getNode())) {
					// any condition returns BOOLEAN value
					auto boolType = m_dataTypeFactory->getType(SystemType::Bool);
					sdaGenNode->setDataType(boolType);
				}
			}
			else if (auto sdaReadValueNode = dynamic_cast<SdaReadValueNode*>(sdaNode)) {
				// example: *(float*)(&globalVar)
				auto addrSdaNode = sdaReadValueNode->getAddress();
				if (addrSdaNode->getDataType()->isPointer()) { // &globalVar is a pointer (type: float*)
					auto addrDataType = DataType::CloneUnit(addrSdaNode->getDataType());
					addrDataType->removePointerLevelOutOfFront(); // float*(8 bytes) -> float(4 bytes)
					if (sdaReadValueNode->getSize() == addrDataType->getSize()) {
						if (auto mappedToMemory = dynamic_cast<IMappedToMemory*>(addrSdaNode)) {
							if (mappedToMemory->isAddrGetting()) {
								// *(float*)(&globalVar) -> globalVar
								mappedToMemory->setAddrGetting(false); // &globalVar -> globalVar
								sdaReadValueNode->replaceWith(mappedToMemory);
								delete sdaReadValueNode;
								return;
							}
						}

						//*(float*)(&globalVar) have to return a value of <float> type
						sdaReadValueNode->setDataType(addrDataType);
						return;
					}
				}

				// cast &globalVar/stackVar/0x1000 to default type uint32_t* (because reading of 4 bytes)
				auto defDataType = sdaReadValueNode->getDataType(); // any sda node have already had a default type
				auto defPtrDataType = DataType::CloneUnit(defDataType);
				defPtrDataType->addPointerLevelInFront();
				cast(addrSdaNode, defPtrDataType);
			}
			else if (auto sdaFunctionNode = dynamic_cast<SdaFunctionNode*>(sdaNode)) {
				// example: (world->vtable->func_get_player)(player_id) where {world->vtable->func_get_player} has a signature type calculated through the step of goar building
				if (auto dstCastNode = dynamic_cast<ISdaNode*>(sdaFunctionNode->getDestination())) {
					if (auto signature = dynamic_cast<DataType::Signature*>(dstCastNode->getDataType()->getType())) {
						if (!sdaFunctionNode->getSignature()) {
							// assign a signature that calculated in function destination (world->vtable->func_get_player)
							sdaFunctionNode->setSignature(signature);
						}
					}
				}

				// cast {player_id} to int type if it has float type
				int paramIdx = 1;
				for (auto paramNode : sdaFunctionNode->getParamNodes()) {
					if (auto paramSdaNode = dynamic_cast<ISdaNode*>(paramNode)) {
						auto paramNodeDataType = paramSdaNode->getDataType();
						sdaFunctionNode->getTypeContext()->setParamDataTypeWithPriority(paramIdx, paramNodeDataType);
						if (sdaFunctionNode->getSignature()) {
							auto paramNodeProperDataType = sdaFunctionNode->getParamDataType(paramIdx);
							cast(paramSdaNode, paramNodeProperDataType);
						}
					}
					paramIdx++;
				}
			}
			else if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(sdaNode)) {
				// example: *(float*)(param1) where <param1> is <float*>
				if (sdaSymbolLeaf->getDataType()->isPointer()) {
					auto g = sdaSymbolLeaf->getDataType()->getGroup();
					if (g == Type::Group::Structure || g == Type::Group::Class) {
						if (dynamic_cast<ReadValueNode*>(sdaSymbolLeaf->getParentNode())) {
							// just add offset: *(float*)(param1) -> *(float*)(param1 + 0x0)
							auto linearExpr = new LinearExpr(int64_t(0));
							auto unknownLocation = new UnknownLocation(linearExpr, 0);
							linearExpr->addParentNode(unknownLocation);
							sdaSymbolLeaf->replaceWith(unknownLocation);
							linearExpr->addTerm(sdaSymbolLeaf);
							//then build a goar or anything
							handleUnknownLocation(unknownLocation);
						}
					}
					// why a symbol only? Because no cases when (param1->field_1)->field_2 as memVar exists.
				}
			}
			else if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(sdaNode)) {
				auto valueMask = sdaNumberLeaf->getMask();
				sdaNumberLeaf->setDataType(m_dataTypeFactory->calcDataTypeForNumber(sdaNumberLeaf->m_value));
			}
			else if (auto goarNode = dynamic_cast<GoarNode*>(sdaNode)) {
				//...
				return;
			}
			else if (auto unknownLocation = dynamic_cast<UnknownLocation*>(sdaNode)) {
				handleUnknownLocation(unknownLocation);
			}
		}

		virtual void handleUnknownLocation(UnknownLocation* unknownLocation) {
			//if it is a pointer, see to make sure it could'be transformed to an array or a class field
			if (!dynamic_cast<GoarTopNode*>(unknownLocation->getBaseSdaNode())) {
				if (auto goarNode = SdaGoarBuilding(m_dataTypeFactory, unknownLocation).create()) {
					unknownLocation->replaceWith(goarNode);
					delete unknownLocation;
				}
			}
		}

		// casting {sdaNode} to {toDataType}
		void cast(ISdaNode* sdaNode, DataTypePtr toDataType) {
			//exception case (better change number view between HEX and non-HEX than do the cast)
			if (auto sdaNumberLeaf = dynamic_cast<SdaNumberLeaf*>(sdaNode)) {
				if (!toDataType->isPointer()) {
					if (toDataType->getSize() >= sdaNumberLeaf->getDataType()->getSize()) {
						sdaNumberLeaf->setDataType(toDataType);
						return;
					}
				}
			}

			//CASTING
			auto explicitCast = isExplicitCast(sdaNode->getSrcDataType(), toDataType);
			sdaNode->getCast()->setCastDataType(toDataType, explicitCast);

			// for AUTO sda symbols that have to acquire a data type with the biggest priority (e.g. uint64_t -> Player*)
			if (auto sdaSymbolLeaf = dynamic_cast<SdaSymbolLeaf*>(sdaNode)) {
				if (auto autoSdaSymbol = dynamic_cast<CE::Symbol::AutoSdaSymbol*>(sdaSymbolLeaf->getSdaSymbol())) {
					auto symbolDataType = autoSdaSymbol->getDataType();
					if (symbolDataType->getSize() == toDataType->getSize() && symbolDataType->getPriority() < toDataType->getPriority()) {
						sdaSymbolLeaf->setDataType(toDataType);
						m_nextPassRequired = true;
					}
				}
			}
			// *(uint32_t*)(p + 4) -> *(float*)(p + 4)
			else if (auto sdaReadValueNode = dynamic_cast<SdaReadValueNode*>(sdaNode)) {
				if (sdaReadValueNode->getSize() == toDataType->getSize()) {
					auto addrSdaNode = sdaReadValueNode->getAddress();
					auto newAddrDataType = DataType::CloneUnit(toDataType);
					newAddrDataType->addPointerLevelInFront();

					cast(addrSdaNode, newAddrDataType);
					sdaNode->setDataType(toDataType);
				}
			}
		}

		// does it need explicit casting (e.g. (float)0x100024)
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

		// calculate result data type for two operands
		DataTypePtr calcDataTypeForOperands(DataTypePtr opType1, DataTypePtr opType2) {
			auto priority1 = opType1->getConversionPriority();
			auto priority2 = opType2->getConversionPriority();
			if (priority1 == 0 && priority2 == 0)
				return m_dataTypeFactory->getType(SystemType::Int32);
			if (priority2 > priority1)
				return opType2;
			return opType1;
		}
	};
};