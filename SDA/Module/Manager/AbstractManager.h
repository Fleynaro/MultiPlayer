#pragma once
#include "SDA.h"

namespace CE
{
	class IManager
	{
	public:
		IManager(SDA* sda)
			: m_sda(sda)
		{}
	protected:
		SDA* getSDA() {
			return m_sda;
		}
	private:
		SDA* m_sda;
	};
};