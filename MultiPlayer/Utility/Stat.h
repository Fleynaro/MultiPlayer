#pragma once

namespace Stat
{
	class Id
	{
	public:
		Id() {
			static int id = 1;
			m_id = id ++;
		}

		int getId() {
			return m_id;
		}
	private:
		int m_id = 0;
	};
};