#pragma once
#include "TypeUnit.h"


namespace CE
{
	namespace DataType
	{
		class UserType : public Type, public IGhidraUnit
		{
		public:
			UserType(TypeManager* typeManager, std::string name, std::string desc = "");

			bool isUserDefined() override;

			std::string getDisplayName() override;

			std::string getName() override;

			std::string getDesc() override;

			void setName(const std::string& name);

			void setDesc(const std::string& desc);

			bool isGhidraUnit() override;

			void setGhidraUnit(bool toggle) override;

			DB::Id getId() override;

			void setId(DB::Id id) override;

			DB::IMapper* getMapper() override;

			void setMapper(DB::IMapper* mapper) override;
		private:
			std::string m_name;
			std::string m_desc;
			bool m_ghidraUnit = true;
			DB::Id m_id;
			DB::IMapper* m_mapper = nullptr;
		};
	};
};