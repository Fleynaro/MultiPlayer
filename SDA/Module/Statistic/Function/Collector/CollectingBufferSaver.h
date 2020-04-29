#pragma once
#include <Utils/Buffer.h>

namespace CE::Stat::Function
{
	class BufferSaver
	{
	public:
		BufferSaver(Buffer* buffer, const std::string& path)
			: m_buffer(buffer), m_path(path)
		{}

		void save() {
			m_isWorking = true;
			m_thread = std::thread(&BufferSaver::handler, this);
			m_thread.detach();
		}

		void handler() {
			std::ofstream output_file(m_path, std::ios::binary);
			if (output_file.is_open()) {
				output_file.write((char*)m_buffer->getData(), m_buffer->getSize());
				output_file.close();
			}

			m_isWorking = false;
		}

		std::atomic<bool> m_isWorking = false;
	private:
		Buffer* m_buffer;
		std::string m_path;
		std::thread m_thread;
	};
};