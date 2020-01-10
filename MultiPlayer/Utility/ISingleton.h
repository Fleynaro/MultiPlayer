#pragma once

template <typename T>
class ISingleton
{
protected:
	inline static T* m_pSingleton;

public:
	ISingleton()
	{
		//assert(!m_pSingleton);
		m_pSingleton = static_cast<T*>(this);
	}

	~ISingleton()
	{
		m_pSingleton = 0;
	}

	static T& GetInstance()
	{
		//assert(m_pSingleton);
		return *m_pSingleton;
	}

	static T* GetInstancePtr()
	{
		return m_pSingleton;
	}
};