#pragma once

namespace CE
{
	class IGhidraObject
	{
	public:
		virtual bool isGhidraUnit() = 0;
		virtual void setGhidraUnit(bool toggle) = 0;
	};
};