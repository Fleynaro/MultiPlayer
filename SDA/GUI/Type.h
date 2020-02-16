#pragma once
#include "Shared/GUI/Items/Items.h"
#include <Manager/TypeManager.h>

using namespace CE;

namespace GUI::Units
{
	class Type
		:
		public Elem,
		public Events::OnLeftMouseClick<Type>,
		public Attribute::Font<Type>
	{
	public:
		Type(CE::Type::Type* type, Events::Event* event = nullptr)
			:
			m_type(type),
			Events::OnLeftMouseClick<Type>(this, event)
		{}

		void render() override {
			pushFontParam();

			ImGui::TextColored(
				toImGuiColor(getColor()),
				getName().c_str()
			);

			if (ImGui::IsItemHovered()) {
				sendLeftMouseClickEvent();
				ImGui::SetTooltip(getTooltipDesc(m_type).c_str());
			}

			ImGui::SameLine(0.f, 0.f);

			popFontParam();
		}

		ColorRGBA getColor() {
			return 0xC3F0F2FF;
		}

		std::string getName() {
			return m_type->getDisplayName();
		}

		static std::string getTooltipDesc(CE::Type::Type* type, bool sizeLimit = true) {
			std::string info =
				"Name: " + type->getDisplayName() + " (Id: "+ std::to_string(type->getId()) +")" +
				"\nGroup: " + getGroupName(type->getGroup()) +
				"\nSize: " + std::to_string(type->getSize()) + " bytes"
				"\nDescription:\n" + type->getDesc();

			if (type->isUserDefined())
			{
				info += "\n\n";
				switch (type->getGroup())
				{
				case CE::Type::Type::Typedef:
				{
					auto Typedef = static_cast<CE::Type::Typedef*>(type->getBaseType());
					if (Typedef->getRefType() != nullptr) {
						info += "Source: " + Typedef->getRefType()->getDisplayName() + "\n";
					}
					break;
				}

				case CE::Type::Type::Enum:
				{
					auto Enum = static_cast<CE::Type::Enum*>(type->getBaseType());
					info += "enum " + Enum->getName() + " {\n";
					for (auto& field : Enum->getFieldDict()) {
						info += field.second + " = "+ std::to_string(field.first) +",\n";
					}
					info += "};";
					break;
				}

				case CE::Type::Type::Class:
				{
					auto Class = static_cast<CE::Type::Class*>(type->getBaseType());
					info += "class " + Class->getName() + " ";

					if (Class->getBaseClass() != nullptr) {
						info += ": public " + Class->getBaseClass()->getName() + " ";
					}

					info += "{\n";
					info += "public:\n";

					info += "\t//fields:\n";
					int limitCount = sizeLimit * 30;

					//fields
					for (auto& field : Class->getFieldDict()) {
						info += "\t" + field.second.getType()->getDisplayName() + " " + field.second.getName() + "; //" + std::to_string(field.first);
						if (!field.second.getDesc().empty()) {
							info += "; " + field.second.getDesc();
						}
						info += "\n";

						if (--limitCount == 0) {
							info += "\t{too long list of fields: "+ std::to_string(Class->getFieldDict().size()) +"}\n";
							break;
						}
					}

					if (Class->hasVTable())
					{
						info += "\t//virtual methods:\n";
						limitCount = sizeLimit * 20;

						//virtual methods
						for (auto method : Class->getVtable()->getVMethodList()) {
							info += "\t" + method->getSigName() + "\n";

							if (--limitCount == 0) {
								info += "\t{too long list of virtual methods: " + std::to_string(Class->getMethodList().size()) + "}\n";
								break;
							}
						}
					}


					info += "\t//methods:\n";
					limitCount = sizeLimit * 20;

					//methods
					for (auto method : Class->getMethodList()) {
						info += method->getSigName() + "\n";

						if (--limitCount == 0) {
							info += "\t{too long list of methods: " + std::to_string(Class->getMethodList().size()) + "}\n";
							break;
						}
					}

					info += "};";
					break;
				}
				}
			}

			return info;
		}

		static const std::string& getGroupName(int groupId) {
			static std::vector<std::string> groupName = {
				"Simple",
				"Enum",
				"Class",
				"Typedef",
				"Signature"
			};
			return groupName[groupId];
		}
	private:
		CE::Type::Type* m_type;
	};
};