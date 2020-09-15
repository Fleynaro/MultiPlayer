#pragma once
#include "ExprTreeSdaNode.h"
#include <Code/Type/FunctionSignature.h>
#include "../../ExprTree/ExprTreeFunctionCall.h"

namespace CE::Decompiler::ExprTree
{
	class SdaFunctionNode : public SdaNode, public INodeAgregator
	{
	public:
		struct TypeContext
		{
			std::vector<DataTypePtr> m_paramTypes;
			DataTypePtr m_returnType;

			TypeContext(std::vector<DataTypePtr> paramTypes, DataTypePtr returnType)
				: m_paramTypes(paramTypes), m_returnType(returnType)
			{}

			void setParamDataTypeWithPriority(int paramIdx, DataTypePtr dataType) {
				if (m_paramTypes[paramIdx - 1]->getPriority() >= dataType->getPriority())
					return;
				m_paramTypes[paramIdx - 1] = dataType;
			}
		};

	private:
		FunctionCall* m_funcCall;
		DataType::Signature* m_signature = nullptr;
		std::shared_ptr<TypeContext> m_typeContext;

	public:
		SdaFunctionNode(FunctionCall* funcCallCtx, std::shared_ptr<TypeContext> typeContext)
			: m_funcCall(funcCallCtx), m_typeContext(typeContext)
		{}

		~SdaFunctionNode() {
			m_funcCall->removeBy(this);
		}

		void replaceNode(INode* node, INode* newNode) override {
			m_funcCall->replaceNode(node, newNode);
		}

		std::list<ExprTree::INode*> getNodesList() override {
			return m_funcCall->getNodesList();
		}

		INode* getDestination() {
			return m_funcCall->getDestination();
		}

		std::vector<ExprTree::INode*>& getParamNodes() {
			return m_funcCall->getParamNodes();
		}

		DataTypePtr getParamDataType(int paramIdx) {
			return m_signature ? m_signature->getParameters()[paramIdx - 1]->getDataType() : m_typeContext->m_paramTypes[paramIdx - 1];
		}

		DataTypePtr getSrcDataType() override {
			return m_signature ? m_signature->getReturnType() : m_typeContext->m_returnType;
		}

		void setDataType(DataTypePtr dataType) override {
			if (m_signature)
				return;
			m_typeContext->m_returnType = dataType;
		}

		BitMask64 getMask() override {
			return m_funcCall->getMask();
		}

		bool isFloatingPoint() override {
			return m_funcCall->isFloatingPoint();
		}

		ObjectHash::Hash getHash() override {
			return m_funcCall->getHash();
		}

		ISdaNode* cloneSdaNode(NodeCloneContext* ctx) override {
			auto clonedFuncCall = dynamic_cast<FunctionCall*>(m_funcCall->clone(ctx));
			auto sdaFunctionNode = new SdaFunctionNode(clonedFuncCall, m_typeContext);
			if (m_signature) {
				sdaFunctionNode->setSignature(m_signature);
			}
			return sdaFunctionNode;
		}

		DataType::Signature* getSignature() {
			return m_signature;
		}

		void setSignature(DataType::Signature* signature) {
			m_signature = signature;
		}

		std::shared_ptr<TypeContext> getTypeContext() {
			return m_typeContext;
		}

		std::string printSdaDebug() override {
			return m_funcCall->printDebug();
		}
	};
};