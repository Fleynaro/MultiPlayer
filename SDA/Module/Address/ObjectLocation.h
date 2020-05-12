#pragma once
#include <main.h>

namespace CE
{
	class ProccessModule;

	class ObjectLocation
	{
	public:
		ObjectLocation(ProccessModule* module, int offset);

		void* getAddress();

		ProccessModule* getProccessModule();

		int getOffset();
	private:
		ProccessModule* m_module;
		int m_offset;
	};
};