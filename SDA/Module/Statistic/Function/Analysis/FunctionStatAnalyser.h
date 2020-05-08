#pragma once
#include "IAnalysisProvider.h"
#include <Utility/FileWrapper.h>
#include <Utils/ITaskMonitor.h>

using namespace SQLite;

namespace CE::Stat::Function
{
	class BufferLoader
	{
	public:
		BufferLoader(BufferManager* bufferManager);

		void loadAllBuffers();

		Buffer* getBuffer();

		int getBuffersCount();
	private:
		BufferManager* m_bufferManager;
		FS::Directory::itemList m_bufferFiles;
	};

	namespace Analyser
	{
		class BufferAnalyser : public ITaskMonitor {
		public:
			BufferAnalyser(Buffer* buffer, IAnalysisProvider* analysisProvider);

			void startAnalysis();

			float getProgress() override;

			int getSize();
		private:
			Buffer* m_buffer;
			IAnalysisProvider* m_analysisProvider;
			std::thread m_thread;
			std::atomic<float> m_progress = 1.0;

			void analyse();
		};

		class Analyser : public ITaskMonitor {
		public:
			Analyser(IAnalysisProvider* analysisProvider, BufferLoader* bufferLoader);

			void startAnalysis();

			void manager();

			float getProgress() override;

			int getTotalSize();
		private:
			BufferLoader* m_bufferLoader;
			std::thread m_threadManager;
			std::mutex m_mutex;
			std::list<BufferAnalyser*> m_bufferAnaylysers;
			int m_totalBuffersCount = 0;
			IAnalysisProvider* m_analysisProvider;
		};
	};
};