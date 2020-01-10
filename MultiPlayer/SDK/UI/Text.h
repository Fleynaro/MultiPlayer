#pragma once


#include "../NativeCaller.h"
#include "Screen.h"
#include "Item.h"


namespace SDK::UI {
	using Color = uint32_t;
	using ColorRGBA = Color;

	enum class Colors : ColorRGBA
	{
		WHITE = 0xFFFFFFFF,
		RED = 0xFF0000FF,
		GREEN = 0x00FF00FF,
		BLUE = 0x0000FFFF,

		Default = WHITE
	};

	class Text
		: public Item, public Class::IExportable<Text>
	{
	public:
		//for export
		Text* getPersistent() override {
			return Text::constructor(getText());
		}

		static Text* constructor(std::string text) {
			return new Text(text);
		}

		enum class Font
		{
			ChaletLondon = 0,
			HouseScript,
			Monospace,
			ChaletComprimeCologne = 4,
			Pricedown = 7,

			Default = ChaletLondon,
		};

		enum class Alignment
		{
			Center,
			Left ,
			Right
		};

		Text(const std::string& text, float x = 0.f, float y = 0.f)
			: m_text(text), m_x(x), m_y(y)
		{}
		~Text() {}

		Text& setText(std::string text) {
			m_text = text;
			return *this;
		}

		std::string getText() {
			return m_text;
		}

		Text& setColor(ColorRGBA color) {
			m_color = color;
			return *this;
		}

		ColorRGBA getColor() {
			return m_color;
		}

		Text& setFont(Font font) {
			m_font = font;
			return *this;
		}

		Font getFont() {
			return m_font;
		}

		Text& setAlignment(Alignment alignment) {
			m_alignment = alignment;
			return *this;
		}

		Alignment getAlignment() {
			return m_alignment;
		}

		Text& setScale(float scale) {
			m_scale = scale;
			return *this;
		}

		float getScale() {
			return m_scale;
		}

		Text& setPosX(float value) {
			m_x = value;
			return *this;
		}

		float getPosX() {
			return m_x;
		}

		Text& setPosY(float value) {
			m_y = value;
			return *this;
		}

		float getPosY() {
			return m_y;
		}

		Text& setOutline(bool state) {
			m_outline = state;
			return *this;
		}

		bool isOutline() {
			return m_scale;
		}

		Text& setShadow(bool state) {
			m_shadow = state;
			return *this;
		}

		bool isShadow() {
			return m_scale;
		}

		void draw(float screenWidth, float screenHeight) override
		{
			float rel_x = getPosX() / screenWidth;
			float rel_y = getPosY() / screenHeight;

			if (isShadow()) {
				Call(SE::UI::SET_TEXT_DROP_SHADOW);
			}
			if (isOutline()) {
				Call(SE::UI::SET_TEXT_OUTLINE, 1);
			}
			if (getAlignment() == Alignment::Center) {
				Call(SE::UI::SET_TEXT_CENTRE, 1);
			}
			Call(SE::UI::SET_TEXT_FONT, (int)getFont());
			Call(SE::UI::SET_TEXT_SCALE, getScale(), getScale());
			Call(SE::UI::SET_TEXT_COLOUR, m_color >> 24 & 0xFF, m_color >> 16 & 0xFF, m_color >> 8 & 0xFF, m_color & 0xFF);
			Call(SE::UI::SET_TEXT_WRAP, 0.f, 1.f);
			//Call(SE::UI::SET_TEXT_JUSTIFICATION, (int)getAlignment());

			Call(SE::UI::BEGIN_TEXT_COMMAND_DISPLAY_TEXT, "CELL_EMAIL_BCON");
			
			for (std::size_t i = 0; i < m_text.size(); i += 99)
			{
				Call(SE::UI::ADD_TEXT_COMPONENT_SUBSTRING_PLAYER_NAME, m_text.c_str() + i);
			}

			Call(SE::UI::END_TEXT_COMMAND_DISPLAY_TEXT, rel_x, rel_y);
		}

		void draw()
		{
			//auto size = Screen::GetResolution();
			draw(Screen::Width, Screen::Height);
		}
	private:
		float m_x;
		float m_y;

		std::string m_text;
		ColorRGBA m_color = ColorRGBA(Colors::Default);
		Font m_font = Font::Default;
		Alignment m_alignment = Alignment::Left;
		float m_scale = 0.3f;
		bool m_outline = false;
		bool m_shadow = false;
	};
};