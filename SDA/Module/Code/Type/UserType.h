#pragma once
#include "AbstractType.h"

namespace CE
{
	namespace Type
	{
		class UserType : public Type, public IGhidraUnit
		{
		public:
			UserType(int id, std::string name, std::string desc = "")
				: m_id(id), m_name(name), m_desc(desc)
			{}

			bool isUserDefined() override {
				return true;
			}

			int getPointerLvl() override {
				return 0;
			}

			int getArraySize() override {
				return 0;
			}

			int getId() override {
				return m_id;
			}

			std::string getDisplayName() override {
				return getName();
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

			bool isGhidraUnit() override {
				return m_ghidraUnit;
			}

			void setGhidraUnit(bool toggle) override {
				m_ghidraUnit = toggle;
			}
		private:
			int m_id;
			std::string m_name;
			std::string m_desc;
			bool m_ghidraUnit = true;

		};
	};
};