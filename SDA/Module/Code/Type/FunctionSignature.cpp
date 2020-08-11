#include "FunctionSignature.h"
#include <Manager/TypeManager.h>
#include <Manager/SymbolManager.h>

using namespace CE;
using namespace CE::DataType;

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
}

DataTypePtr Signature::getReturnType() {
	return m_returnType;
}

std::vector<Symbol::FuncParameterSymbol*>& Signature::getParameters() {
	return m_parameters;
}

void Signature::addParameter(Symbol::FuncParameterSymbol* symbol) {
	m_parameters.push_back(symbol);
}

void Signature::addParameter(const std::string& name, DataTypePtr dataType, const std::string& comment) {
	auto paramSymbol = dynamic_cast<Symbol::FuncParameterSymbol*>(getTypeManager()->getProgramModule()->getSymbolManager()->createSymbol(Symbol::FUNC_PARAMETER, dataType, name, comment));
	addParameter(paramSymbol);
}

void Signature::removeLastParameter() {
	m_parameters.pop_back();
}

void Signature::deleteAllParameters() {
	m_parameters.clear();
}

