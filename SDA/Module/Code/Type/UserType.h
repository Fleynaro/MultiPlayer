#pragma once
#include "TypeUnit.h"
#include <GhidraSync/IGhidraObject.h>

namespace CE
{
	namespace DataType
	{
		class UserType : public Type, public IGhidraObject
		{
		public:
			UserType(TypeManager* typeManager, const std::string& name, const std::string& comment = "");

			bool isUserDefined() override;

			std::string getDisplayName() override;

			bool isGhidraUnit() override;

			void setGhidraUnit(bool toggle) override;

			DB::Id getId() override;

			void setId(DB::Id id) override;

			DB::IMapper* getMapper() override;

			void setMapper(DB::IMapper* mapper) override;
		private:
			bool m_ghidraUnit = true;
			DB::Id m_id;
			DB::IMapper* m_mapper = nullptr;
		};
	};
};