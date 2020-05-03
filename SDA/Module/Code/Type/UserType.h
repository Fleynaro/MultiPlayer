#pragma once
#include "AbstractType.h"


namespace CE
{
	namespace DataType
	{
		class UserType : public Type, public IGhidraUnit
		{
		public:
			UserType(std::string name, std::string desc = "")
				: m_name(name), m_desc(desc)
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

			DB::Id getId() override {
				return m_id;
			}

			void setId(DB::Id id) override {
				m_id = id;
			}

			DB::IMapper* getMapper() override {
				return m_mapper;
			}

			void setMapper(DB::IMapper* mapper) override {
				m_mapper = mapper;
			}
		private:
			std::string m_name;
			std::string m_desc;
			bool m_ghidraUnit = true;
			DB::Id m_id;
			DB::IMapper* m_mapper = nullptr;
		};
	};
};