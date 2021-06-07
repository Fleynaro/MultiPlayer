#include "FunctionSignature.h"
#include <Manager/TypeManager.h>
#include <Manager/SymbolManager.h>
#include <Decompiler/PCode/DecPCode.h>

using namespace CE;
using namespace CE::DataType;
using namespace CE::Decompiler;

Signature::Signature(const std::string& name, const std::string& comment, CallingConvetion callingConvetion)
	: UserType(name, comment), m_callingConvetion(callingConvetion)
{
	setReturnType(DataType::GetUnit(new DataType::Byte));
}

Type::Group Signature::getGroup() {
	return Group::Signature;
}

int Signature::getSize() {
	return sizeof(std::uintptr_t);
}

std::string Signature::getDisplayName() {
	return getSigName();
}

Signature::CallingConvetion Signature::getCallingConvetion() {
	return m_callingConvetion;
}

std::list<std::pair<int, Decompiler::Storage>>& Signature::getCustomStorages() {
	return m_customStorages;
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
	auto paramSymbol = new Symbol::FuncParameterSymbol(dataType, name, comment);
	auto manager = getTypeManager()->getProgramModule()->getSymbolManager();
	if(manager)
		manager->bind(paramSymbol);
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

FunctionCallInfo Signature::getCallInfo() {
	if (m_hasSignatureUpdated) {
		m_paramInfos.clear();
		updateParameterStorages();
		m_hasSignatureUpdated = false;
	}
	return FunctionCallInfo(m_paramInfos);
}

void Signature::updateParameterStorages() {
	for (auto pair : getCustomStorages()) {
		auto paramIdx = pair.first;
		auto storage = pair.second;
		if (paramIdx >= 1 && paramIdx <= getParameters().size()) {
			auto paramSize = getParameters()[paramIdx - 1]->getDataType()->getSize();
			m_paramInfos.push_back(ParameterInfo(paramIdx, paramSize, storage));
		}
		else if (paramIdx == 0) {
			//if it is return
			m_paramInfos.push_back(ParameterInfo(0, getReturnType()->getSize(), storage));
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
					auto regId = !paramType->isFloatingPoint() ? reg.first : reg.second;
					auto storage = Storage(Storage::STORAGE_REGISTER, regId, 0x0);
					m_paramInfos.push_back(ParameterInfo(paramIdx, paramType->getSize(), storage));
				}
			}
			else {
				auto storage = Storage(Storage::STORAGE_STACK, ZYDIS_REGISTER_RSP, paramIdx * 0x8);
				m_paramInfos.push_back(ParameterInfo(paramIdx, paramType->getSize(), storage));
			}

			paramIdx++;
		}

		//return
		auto retType = getReturnType();
		if (retType->getSize() != 0x0) {
			auto regId = !retType->isFloatingPoint() ? ZYDIS_REGISTER_RAX : ZYDIS_REGISTER_ZMM0;
			auto storage = Storage(Storage::STORAGE_REGISTER, regId, 0x0);
			m_paramInfos.push_back(ReturnInfo(retType->getSize(), storage));
		}
	}
}