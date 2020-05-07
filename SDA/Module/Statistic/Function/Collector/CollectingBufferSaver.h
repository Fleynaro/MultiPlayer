#pragma once
#include <Utils/Buffer.h>

namespace CE::Stat::Function
{
	class BufferSaver
	{
	public:
		BufferSaver(Buffer* buffer, const std::string& path);

		void save();

		void handler();

		std::atomic<bool> m_isWorking = false;
	private:
		Buffer* m_buffer;
		std::string m_path;
		std::thread m_thread;
	};
};