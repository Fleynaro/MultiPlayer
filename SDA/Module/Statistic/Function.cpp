#include "Function.h"
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

BufferManager::~BufferManager() {
	for (auto it : m_triggerBuffers) {
		saveTriggerBuffer(it.first);
	}
}

void CE::Stat::Function::BufferManager::write(CE::Trigger::Function::Trigger* trigger, StreamRecordWriter* writer) {
	auto id = trigger->getId();
	m_bufferMutex.lock();
	if (m_triggerBuffers.find(id) == m_triggerBuffers.end()) {
		m_triggerBuffers.insert(std::make_pair(id, new TriggerBuffer(this, trigger, m_bufferSizeMb)));
	}
	m_triggerBuffers[id]->write(writer);
	m_bufferMutex.unlock();
}

void BufferManager::saveTriggerBuffer(int triggerId) {
	m_triggerBuffers[triggerId]->saveCurBuffer();

	while (m_triggerBuffers[triggerId]->getWorkedSaverCount() > 0) {
		Sleep(100);
	}

	delete m_triggerBuffers[triggerId];
	m_triggerBuffers.erase(triggerId);
}

std::string TriggerBuffer::generateNewName() {
	auto number = std::to_string(10000 + m_bufferManager->m_savedBufferCount++);
	return "buffer_tr" + std::to_string(m_trigger->getId()) + "_" + number + ".data";
}
