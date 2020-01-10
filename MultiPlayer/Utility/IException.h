#pragma once


#include "main.h"



//Game exception interface
class IGameException
{
public:
	IGameException(std::string desc)
	{
		m_desc = desc;
	}

	std::string getDescription() {
		return m_desc;
	}
private:
	std::string m_desc;
};