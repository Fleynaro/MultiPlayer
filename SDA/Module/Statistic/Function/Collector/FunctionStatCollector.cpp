#include "FunctionStatCollector.h"
#include <Trigger/FunctionTrigger.h>

using namespace CE;
using namespace Stat::Function;

BufferManager::BufferManager(FS::Directory dir, int bufferSizeMb)
	: m_dir(dir), m_bufferSizeMb(bufferSizeMb)
{
	//MYTODO: max id
	m_savedBufferCount = static_cast<int>(m_dir.getItems().size());
}

BufferManager::~BufferManager() {
	save();
}

void BufferManager::save() {
	for (auto it : m_triggerBuffers) {
		saveTriggerBuffer(it.first);
	}
}

void BufferManager::write(Trigger::Function::Trigger* trigger, StreamRecordWriter* writer) {
	m_bufferMutex.lock();
	if (m_triggerBuffers.find(trigger) == m_triggerBuffers.end()) {
		m_triggerBuffers.insert(std::make_pair(trigger, new TriggerBuffer(this, trigger, m_bufferSizeMb)));
	}
	m_triggerBuffers[trigger]->write(writer);
	m_bufferMutex.unlock();
}

void BufferManager::saveTriggerBuffer(Trigger::Function::Trigger* trigger) {
	m_triggerBuffers[trigger]->saveCurBuffer();

	while (m_triggerBuffers[trigger]->getWorkedSaverCount() > 0) {
		Sleep(100);
	}

	delete m_triggerBuffers[trigger];
	m_triggerBuffers.erase(trigger);
}






TriggerBuffer::TriggerBuffer(BufferManager* bufferManager, Trigger::Function::Trigger* trigger, int bufferSizeMb)
	: m_bufferManager(bufferManager), m_trigger(trigger), m_bufferSizeMb(bufferSizeMb)
{
	createNewBuffer();
}

TriggerBuffer::~TriggerBuffer() {
	for (auto saver : m_savers) {
		delete saver;
	}
}

void TriggerBuffer::write(StreamRecordWriter* writer) {
	StreamRecord record(&m_bufferStream, writer);

	try {
		record.write();
	}
	catch (const BufferOverflowException&) {
		if (getWorkedSaverCount() > 0) {
			m_bufferSizeMb *= 2;
		}
		saveCurBuffer();
		createNewBuffer();
		write(writer);
	}
}

int TriggerBuffer::getWorkedSaverCount() {
	int count = 0;
	for (auto saver : m_savers) {
		if (saver->m_isWorking)
			count++;
	}
	return count;
}

std::string TriggerBuffer::generateNewName() {
	auto number = std::to_string(10000 + m_bufferManager->m_savedBufferCount++);
	return "buffer_tr" + std::to_string(m_trigger->getId()) + "_" + number + ".data";
}

void TriggerBuffer::createNewBuffer() {
	m_currentBuffer = Buffer::Create(m_bufferSizeMb * 1024 * 1024);
	m_bufferStream = Buffer::Stream(m_currentBuffer);
}

void TriggerBuffer::saveCurBuffer() {
	auto saver = new BufferSaver(m_currentBuffer, FS::File(m_bufferManager->m_dir, generateNewName()).getFilename());
	saver->save();
	m_savers.push_back(saver);
	m_currentBuffer = nullptr;
}




Collector::Collector(FS::Directory dir)
	: m_bufferManager(new BufferManager(dir))
{}

Collector::~Collector() {
	delete m_bufferManager;
}

void Collector::addBeforeCallInfo(Trigger::Function::Trigger* trigger, Hook::DynHook* hook)
{
	auto writer = Record::BeforeCallInfo::Writer(trigger, hook);
	m_bufferManager->write(trigger, &writer);
}

void Collector::addAfterCallInfo(Trigger::Function::Trigger* trigger, Hook::DynHook* hook)
{

}

BufferManager* Collector::getBufferManager() {
	return m_bufferManager;
}
