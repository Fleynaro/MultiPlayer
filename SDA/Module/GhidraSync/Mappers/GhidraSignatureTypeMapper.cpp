#include "GhidraSignatureTypeMapper.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::Ghidra;

SignatureTypeMapper::SignatureTypeMapper(DataTypeMapper* dataTypeMapper)
	: m_dataTypeMapper(dataTypeMapper)
{}

void SignatureTypeMapper::load(packet::SDataFullSyncPacket* dataPacket) {
	for (auto sigDesc : dataPacket->signatures) {
		auto type = m_dataTypeMapper->m_typeManager->getTypeByGhidraId(sigDesc.type.id);
		if (type == nullptr)
			throw std::exception("item not found");
		if (auto sigDef = dynamic_cast<DataType::Signature*>(type)) {
			changeSignatureByDesc(sigDef, sigDesc);
		}
	}
}

void SignatureTypeMapper::upsert(SyncContext* ctx, IObject* obj) {
	auto type = static_cast<DataType::Signature*>(obj);
	ctx->m_dataPacket->signatures.push_back(buildDesc(type));
	m_dataTypeMapper->upsert(ctx, obj);
}

void SignatureTypeMapper::remove(SyncContext* ctx, IObject* obj) {
	m_dataTypeMapper->remove(ctx, obj);
}

datatype::SDataTypeSignature SignatureTypeMapper::buildDesc(DataType::Signature* sig) {
	datatype::SDataTypeSignature sigDesc;
	sigDesc.__set_type(m_dataTypeMapper->buildDesc(sig));
	sigDesc.__set_returnType(m_dataTypeMapper->buildTypeUnitDesc(sig->getReturnType()));

	for (auto arg : sig->getArgList()) {
		datatype::SFunctionArgument argDesc;
		argDesc.__set_name(arg.first);
		argDesc.__set_type(m_dataTypeMapper->buildTypeUnitDesc(arg.second));
		sigDesc.arguments.push_back(argDesc);
	}
	return sigDesc;
}

void SignatureTypeMapper::changeSignatureByDesc(DataType::Signature* sig, const datatype::SDataTypeSignature& sigDesc) {
	m_dataTypeMapper->changeUserTypeByDesc(sig, sigDesc.type);
	sig->setReturnType(m_dataTypeMapper->getTypeByDesc(sigDesc.returnType));
	sig->deleteAllArguments();
	for (auto argDesc : sigDesc.arguments) {
		sig->addArgument(argDesc.name, m_dataTypeMapper->getTypeByDesc(argDesc.type));
	}
}
