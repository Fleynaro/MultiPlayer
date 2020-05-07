#include "CollectingBufferSaver.h"

using namespace CE::Stat::Function;

BufferSaver::BufferSaver(Buffer* buffer, const std::string& path)
	: m_buffer(buffer), m_path(path)
{}

void BufferSaver::save() {
	m_isWorking = true;
	m_thread = std::thread(&BufferSaver::handler, this);
	m_thread.detach();
}

void BufferSaver::handler() {
	std::ofstream output_file(m_path, std::ios::binary);
	if (output_file.is_open()) {
		output_file.write((char*)m_buffer->getData(), m_buffer->getSize());
		output_file.close();
	}

	m_isWorking = false;
}
