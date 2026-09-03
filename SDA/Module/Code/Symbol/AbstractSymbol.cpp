#include "AbstractSymbol.h"

using namespace CE;
using namespace CE::Symbol;

AbstractSymbol::AbstractSymbol(SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment)
	: m_manager(manager), m_dataType(dataType), Descrtiption(name, comment)
{}

SymbolManager* AbstractSymbol::getManager() {
	return m_manager;
}

DataTypePtr AbstractSymbol::getDataType() {
	return m_dataType;
}

void AbstractSymbol::setDataType(DataTypePtr dataType) {
	m_dataType = dataType;
}
