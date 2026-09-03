#include "FunctionStatAnalyser.h"

using namespace CE::Stat::Function;

Analyser::Analyser::Analyser(IAnalysisProvider* analysisProvider, BufferLoader* bufferLoader)
	: m_analysisProvider(analysisProvider), m_bufferLoader(bufferLoader)
{}

void Analyser::Analyser::startAnalysis() {
	if (m_bufferLoader->getBuffersCount() == 0) {
		throw std::exception("buffers count = 0");
	}
	m_bufferAnaylysers.clear();
	m_totalBuffersCount = m_bufferLoader->getBuffersCount();
	m_threadManager = std::thread(&Analyser::manager, this);
	m_threadManager.detach();
}

void Analyser::Analyser::manager() {
	while (auto buffer = m_bufferLoader->getBuffer())
	{
		auto bufferAnalyser = new BufferAnalyser(buffer, m_analysisProvider);
		m_mutex.lock();
		m_bufferAnaylysers.push_back(bufferAnalyser);
		m_mutex.unlock();
		bufferAnalyser->startAnalysis();

		while (getTotalSize() > 1024 * 1024 * 100) {
			Sleep(100);
		}
	}
}

float Analyser::Analyser::getProgress() {
	float totalPorgress = 0.0;
	m_mutex.lock();
	for (auto it : m_bufferAnaylysers) {
		totalPorgress += it->getProgress();
	}
	m_mutex.unlock();
	return totalPorgress / m_totalBuffersCount;
}

int Analyser::Analyser::getTotalSize() {
	int size = 0;
	for (auto it : m_bufferAnaylysers) {
		if (it->isWorking())
			size += it->getSize();
	}
	return size;
}

//BufferAnalyser
Analyser::BufferAnalyser::BufferAnalyser(Buffer* buffer, IAnalysisProvider* analysisProvider)
	: m_buffer(buffer), m_analysisProvider(analysisProvider)
{}

void Analyser::BufferAnalyser::startAnalysis() {
	m_progress = 0.0;
	m_thread = std::thread(&BufferAnalyser::analyse, this);
	m_thread.detach();
}

float Analyser::BufferAnalyser::getProgress() {
	return m_progress;
}

int Analyser::BufferAnalyser::getSize() {
	return m_buffer->getSize();
}

void Analyser::BufferAnalyser::analyse() {
	BufferIterator it(m_buffer);
	while (it.hasNext()) {
		auto stream = it.getStream();
		auto& header = stream.read<Record::Header>();
		m_analysisProvider->handle(header, stream);
		m_progress = min(float(it.getOffset()) / m_buffer->getContentOffset(), 1.0f);
	}
	m_progress = 1.0;
}




//BufferLoader
BufferLoader::BufferLoader(BufferManager* bufferManager)
	: m_bufferManager(bufferManager)
{}

void BufferLoader::loadAllBuffers() {
	m_bufferFiles = m_bufferManager->m_dir.getItems();
}

Buffer* BufferLoader::getBuffer() {
	if (m_bufferFiles.empty())
		return nullptr;
	auto file = *m_bufferFiles.begin();
	m_bufferFiles.pop_front();

	if (file->getName().find("buffer_tr") == std::string::npos) {
		return getBuffer();
	}

	std::ifstream fs(file->getPath(), std::ios::in | std::ios::binary);
	if (fs.is_open()) {
		Buffer::Header header;
		fs.read((char*)&header, sizeof(Buffer::Header));
		fs.seekg(0, std::ios::beg);

		auto buffer = Buffer::Create(header.m_contentSize);
		fs.read((char*)buffer, header.m_contentSize);
		fs.close();
		return buffer;
	}
	return nullptr;
}

int BufferLoader::getBuffersCount() {
	return (int)m_bufferFiles.size();
}
