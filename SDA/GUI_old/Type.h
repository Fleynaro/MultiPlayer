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
		Type(CE::DataType::Type* type, Events::ClickEventType::EventHandlerType* eventHandler = nullptr)
			:
			m_type(type),
			Events::OnLeftMouseClick<Type>(this, this, eventHandler)
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

		static std::string getTooltipDesc(CE::DataType::Type* type, bool sizeLimit = true) {
			std::string info =
				"Name: " + type->getDisplayName() + " (Id: "+ std::to_string(type->getId()) +")" +
				"\nGroup: " + getGroupName(type->getGroup()) +
				"\nSize: " + std::to_string(type->getSize()) + " bytes"
				"\nDescription:\n" + type->getDesc();

			if (type->isUserDefined())
			{
				info += "\n\n";
				
				if (auto Typedef = dynamic_cast<CE::DataType::Typedef*>(type->getBaseType(false))) {
					if (Typedef->getRefType() != nullptr) {
						info += "Source: " + Typedef->getRefType()->getDisplayName() + "\n";
					}
				}
				else if (auto Enum = dynamic_cast<CE::DataType::Enum*>(type->getBaseType())) {
					info += "enum " + Enum->getName() + " {\n";
					for (auto& field : Enum->getFieldDict()) {
						info += "\t" + field.second + " = " + std::to_string(field.first) + ",\n";
					}
					info += "};";
				}
				else if (auto Class = dynamic_cast<CE::DataType::Class*>(type->getBaseType())) {
					info += "class " + Class->getName() + " ";

					if (Class->getBaseClass() != nullptr) {
						info += ": public " + Class->getBaseClass()->getName() + " ";
					}

					info += "{\n";
					info += "public:\n";

					info += "\t//fields:\n";
					int limitCount = sizeLimit * 10;

					//fields
					Class->iterateFieldsWithOffset([&](CE::DataType::Class* class_, int offset, CE::DataType::Class::Field* field) {
						if (class_ != Class)
							return true;

						info += "\t" + field->getType()->getDisplayName() + " " + field->getName() + "; //" + std::to_string(offset);
						if (!field->getDesc().empty()) {
							info += "; " + field->getDesc();
						}
						info += "\n";

						if (--limitCount == 0) {
							info += "\t{too long list of fields: " + std::to_string(Class->getAllFieldCount()) + "}\n";
							return false;
						}
						return true;
						});

					if (Class->hasVTable())
					{
						info += "\t//virtual methods:\n";
						limitCount = sizeLimit * 20;

						//virtual methods
						for (auto method : Class->getVtable()->getVMethodList()) {
							info += "\t" + method->getSigName() + "\n";

							if (--limitCount == 0) {
								info += "\t{too long list of virtual methods: " + std::to_string(Class->getVtable()->getVMethodList().size()) + "}\n";
								break;
							}
						}
					}


					info += "\t//methods:\n";
					limitCount = sizeLimit * 20;

					//methods
					Class->iterateMethods([&](Function::Method* method) {
						if (method->getClass() != Class)
							return true;

						info += method->getSigName() + "\n";

						if (--limitCount == 0) {
							info += "\t{too long list of methods: " + std::to_string(Class->getAllMethodCount()) + "}\n";
							return false;
						}
						return true;
						});

					info += "};";
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
		CE::DataType::Type* m_type;
	};
};