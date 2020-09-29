#include "FunctionSignature.h"
#include <Manager/TypeManager.h>
#include <Manager/SymbolManager.h>
#include <Decompiler/PCode/DecPCode.h>

using namespace CE;
using namespace CE::DataType;
using namespace CE::Decompiler;

Signature::Signature(TypeManager* typeManager, const std::string& name, const std::string& comment, CallingConvetion callingConvetion)
	: UserType(typeManager, name, comment), m_callingConvetion(callingConvetion)
{
	setReturnType(DataType::GetUnit(typeManager->getProgramModule()->getTypeManager()->getDefaultReturnType()));
}

Type::Group Signature::getGroup() {
	return Group::Signature;
}

int Signature::getSize() {
	return sizeof(std::uintptr_t);
}

std::string Signature::getSigName() {
	std::string name = getReturnType()->getDisplayName() + " " + getName() + "(";

	auto& argList = getParameters();
	for (int i = 0; i < argList.size(); i++) {
		name += argList[i]->getDataType()->getDisplayName() + " " + argList[i]->getName() + ", ";
	}
	if (argList.size() > 0) {
		name.pop_back();
		name.pop_back();
	}
	return name + ")";
}

void Signature::setReturnType(DataTypePtr returnType) {
	m_returnType = returnType;
	m_hasSignatureUpdated = true;
}

DataTypePtr Signature::getReturnType() {
	return m_returnType;
}

std::vector<Symbol::FuncParameterSymbol*>& Signature::getParameters() {
	return m_parameters;
}

void Signature::addParameter(Symbol::FuncParameterSymbol* symbol) {
	m_parameters.push_back(symbol);
	symbol->setFuncSignature(this);
	m_hasSignatureUpdated = true;
}

void Signature::addParameter(const std::string& name, DataTypePtr dataType, const std::string& comment) {
	auto paramSymbol = dynamic_cast<Symbol::FuncParameterSymbol*>(getTypeManager()->getProgramModule()->getSymbolManager()->createSymbol(Symbol::FUNC_PARAMETER, dataType, name, comment));
	addParameter(paramSymbol);
}

void Signature::removeLastParameter() {
	m_parameters.pop_back();
	m_hasSignatureUpdated = true;
}

void Signature::deleteAllParameters() {
	m_parameters.clear();
	m_hasSignatureUpdated = true;
}

void Signature::updateParameterStorages() {
	for (auto storage : getCustomStorages()) {
		auto paramIdx = storage.getIndex();
		if (paramIdx >= 1 && paramIdx <= getParameters().size()) {
			auto paramSize = getParameters()[paramIdx - 1]->getDataType()->getSize();
			m_paramInfos.push_back(ParameterInfo(paramSize, storage));
		}
		else if (paramIdx == 0) {
			//if it is return
			m_paramInfos.push_back(ParameterInfo(getReturnType()->getSize(), storage));
		}
	}

	//calling conventions
	if (getCallingConvetion() == Signature::FASTCALL) {
		//parameters
		int paramIdx = 1;
		for (auto param : getParameters()) {
			auto paramType = param->getDataType();
			if (paramIdx >= 1 && paramIdx <= 4) {
				static std::map<int, std::pair<PCode::RegisterId, PCode::RegisterId>> paramToReg = {
							std::pair(1, std::pair(ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_ZMM0)),
							std::pair(2, std::pair(ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_ZMM1)),
							std::pair(3, std::pair(ZYDIS_REGISTER_R8, ZYDIS_REGISTER_ZMM2)),
							std::pair(4, std::pair(ZYDIS_REGISTER_R9, ZYDIS_REGISTER_ZMM3))
				};
				auto it = paramToReg.find(paramIdx);
				if (it != paramToReg.end()) {
					auto& reg = it->second;
					bool isFloatingPoint = paramType->isFloatingPoint();
					auto storage = ParameterStorage(paramIdx, ParameterStorage::STORAGE_REGISTER, !isFloatingPoint ? reg.first : reg.second, 0x0);
					m_paramInfos.push_back(ParameterInfo(paramType->getSize(), storage));
				}
			}
			else {
				auto storage = ParameterStorage(paramIdx, ParameterStorage::STORAGE_STACK, ZYDIS_REGISTER_RSP, paramIdx * 0x8);
				m_paramInfos.push_back(ParameterInfo(paramType->getSize(), storage));
			}

			paramIdx++;
		}

		//return
		auto retType = getReturnType();
		if (retType->getSize() != 0x0) {
			bool isFloatingPoint = retType->isFloatingPoint();
			auto storage = ParameterStorage(0, ParameterStorage::STORAGE_REGISTER, !isFloatingPoint ? ZYDIS_REGISTER_RAX : ZYDIS_REGISTER_ZMM0, 0x0);
			m_paramInfos.push_back(ParameterInfo(retType->getSize(), storage));
		}
	}
}