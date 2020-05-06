#pragma once
#include <main.h>

namespace CE
{
	class IDesc
	{
	public:
		virtual int getId() = 0;
		virtual std::string getName() = 0;
		virtual std::string getDesc() {
			return "Not desc.";
		}
	};

	class Desc : public IDesc
	{
	public:
		Desc(int id, std::string name, std::string desc = "")
			: m_id(id), m_name(name), m_desc(desc)
		{}

		Desc(std::string name, std::string desc = "")
			: m_name(name), m_desc(desc)
		{}

		int getId() override {
			return m_id;
		}

		std::string getName() override {
			return m_name;
		}

		std::string getDesc() override {
			return m_desc;
		}

		void setName(const std::string& name) {
			m_name = name;
		}

		void setDesc(const std::string& desc) {
			m_desc = desc;
		}
	protected:
		int m_id;
		std::string m_name;
		std::string m_desc;
	};

	class IGhidraUnit
	{
	public:
		virtual bool isGhidraUnit() = 0;
		virtual void setGhidraUnit(bool toggle) = 0;
	};
};