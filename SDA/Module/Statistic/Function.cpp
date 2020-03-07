#include "Function.h"
#include <Statistic/Function.h>
#include <Trigger/Trigger.h>

using namespace CE::Stat::Function;

void Record::CallInfoWriter::writeHeader(Type type) {
	Header header;
	header.m_type = (BYTE)type;
	header.m_uid = m_hook->getUID();
	header.m_triggerId = m_trigger->getId();
	header.m_funcDefId = getFunctionDef()->getId();
	getStream().write(header);
}
