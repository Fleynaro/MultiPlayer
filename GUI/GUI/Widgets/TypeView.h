#pragma once

#include "../Items/IWidget.h"
#include "Core/ScriptLang/ClassBuilder.h"

namespace GUI::Widget::TypeView
{
	class Type {
	public:
		enum Id
		{
			Boolean,
			Integer,
			Double,
			String,
			Class,
			Enum,
			Void
		};
		Type(Id id, std::string name, ColorRGBA color = -1)
			: m_id(id), m_name(name), m_color(color)
		{}

		virtual std::string getName() {
			return m_name;
		}

		ColorRGBA getColor() {
			return m_color;
		}

		Id getId() {
			return m_id;
		}
	private:
		std::string m_name;
		ColorRGBA m_color;
		Id m_id;
	};

	class ClassType : public Type {
	public:
		ClassType(Id id, std::string name, Class::Builder* builder, ColorRGBA color = -1)
			: Type(id, name, color), m_builder(builder)
		{}

		Class::Builder* getBuilder() {
			return m_builder;
		}

		std::string getName() override {
			if (getBuilder() == nullptr)
				return Type::getName();
			return getBuilder()->getName();
		}
	private:
		Class::Builder* m_builder = nullptr;
	};

	class ClassMemberType : public ClassType {
	public:
		ClassMemberType(Id id, std::string name, Class::Builder* builder, ColorRGBA color = -1)
			: ClassType(id, name, builder, color)
		{}
		std::string getName() override {
			if (getBuilder() == nullptr)
				return Type::getName();
			return getBuilder()->getName() + "." + Type::getName();
		}
	};

	static std::unique_ptr<Type> getTypeByRawType(std::string rawType)
	{
		auto tokens = Generic::String::Split(rawType, " ");
		if (tokens[0] == "class") {
			if (tokens[1].find("basic_string") != std::string::npos) {
				return std::unique_ptr<Type>(
					new Type(Type::String, "String", ColorRGBA(0x9AE9EDFF))
					);
			}

			return std::unique_ptr<ClassType>(
				new ClassType(
					Type::Class,
					tokens[1],
					Class::Environment::getClassBuilderByRawName(tokens[1]),
					ColorRGBA(0xEBF38FFF)
				)
				);
		}
		else if (tokens[0] == "enum") {
			auto e = Class::Environment::getEnumByRawTypeName(tokens[1]);
			if (e.first == nullptr) {
				return std::unique_ptr<Type>(
					new Type(Type::Enum, "Enum", ColorRGBA(0x8FF3D0FF))
					);
			}

			return std::unique_ptr<Type>(
				new ClassMemberType(Type::Enum, e.second->getName(), e.first, ColorRGBA(0x8FF3D0FF))
				);
		}
		else if (tokens[0] == "void") {
			return std::unique_ptr<Type>(
				new Type(Type::Void, "Void", ColorRGBA(0xC3F0F2FF))
				);
		}
		else if (tokens[0] == "bool") {
			return std::unique_ptr<Type>(
				new Type(Type::Boolean, "Boolean", ColorRGBA(0x9AD9EDFF))
				);
		}
		else if (tokens[0] == "char") {
			return std::unique_ptr<Type>(
				new Type(Type::String, "String", ColorRGBA(0x9AE9EDFF))
				);
		}
		else if (tokens[0] == "float" || tokens[0] == "double") {
			return std::unique_ptr<Type>(
				new Type(Type::Double, "Double", ColorRGBA(0x9AD9EDFF))
				);
		}
		else {
			return std::unique_ptr<Type>(
				new Type(Type::Integer, "Integer", ColorRGBA(0x9AD9EDFF))
				);
		}
	}

	static std::string getDefaultValue(Type* argType, uint64_t value) {
		if (argType->getId() == Type::Boolean) {
			return (bool&)value ? "true" : "false";
		}
		else if (argType->getId() == Type::Double) {
			return std::to_string((float&)value);
		}
		else if (argType->getId() == Type::Integer || argType->getId() == Type::Enum) {
			return std::to_string((int&)value);
		}
		return "=?";
	}

	class TypeText
		:
		public GUI::Elements::Text::ColoredText,
		private Events::OnLeftMouseClick<TypeText>
	{
	public:
		TypeText(Type* type, Events::Event* event = nullptr)
			:
			m_type(type),
			GUI::Elements::Text::ColoredText(
				type->getName(),
				type->getColor()
			),
			Events::OnLeftMouseClick<TypeText>(event)
		{}
		~TypeText() {
			delete m_type;
		}

		void render() override {
			pushFontParam();

			ImGui::TextColored(
				toImGuiColor(m_color),
				m_text.c_str()
			);

			if (ImGui::IsItemHovered())
			{
				auto typeId = getType()->getId();
				if (typeId == Type::Class || typeId == Type::Enum) {
					sendLeftMouseClickEvent();
					ImGui::SetTooltip((getType()->getName() + "\nClick to get more.").c_str());
				}
				else {
					ImGui::SetTooltip((getType()->getName() + "\nIt is a simple type.").c_str());
				}
			}

			ImGui::SameLine(0.f, 0.f);

			popFontParam();
		}

		Type* getType() {
			return m_type;
		}
	private:
		Type* m_type;
	};


	class TextToCopy
		:
		public GUI::Elements::Text::ColoredText,
		private Events::OnLeftMouseClick<TypeText>
	{
	public:
		TextToCopy(std::string text, ColorRGBA color = -1, Events::Event * event = nullptr)
			:
			GUI::Elements::Text::ColoredText(
				text,
				color
			),
			Events::OnLeftMouseClick<TypeText>(event)
		{}

		void render() override {
			pushFontParam();

			ImGui::TextColored(
				toImGuiColor(m_color),
				getText().c_str()
			);

			if (ImGui::IsItemHovered()) {
				sendLeftMouseClickEvent();
				ImGui::SetTooltip(("\nClick here to copy <" + getText() + ">.").c_str());
			}

			popFontParam();
		}
	};
};