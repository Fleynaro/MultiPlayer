#pragma once
#include "../../Items/IWidget.h"

namespace GUI::Widget::Template
{
	class InteractiveInput
		: public Elements::Input::Text,
		public Attribute::Collapse<InteractiveInput>,
		public Events::OnFocused<InteractiveInput>
	{
	public:
		InteractiveInput(const std::string& name = "")
			: Elements::Input::Text(name, nullptr), Attribute::Collapse<InteractiveInput>(false), Events::OnFocused<InteractiveInput>(this)
		{}

		bool m_focused = true;
		void render() override {
			Text::render();
			sendFocusedEvent();
			ImGui::SameLine();

			if (ImGui::IsItemHovered()) {
				if(!toolTip().empty())
					ImGui::SetTooltip(toolTip().c_str());
			}

			m_open |= ImGui::IsItemActive();
			m_open &= m_focused;

			if (isOpen())
			{
				ImGui::SetNextWindowPos({ ImGui::GetItemRectMin().x, ImGui::GetItemRectMax().y });
				ImGui::SetNextWindowSize({ ImGui::GetItemRectSize().x, 0 });
				bool open = m_open;
				if (ImGui::Begin(getUniqueId().c_str(), &open, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize))
				{
					m_focused &= ImGui::IsWindowFocused();
					
					renderComboContent();
					
					ImGui::End();
				}
			}
			else {
				m_focused = true;
			}
		}

		bool isFocused() override {
			return ImGui::IsItemActive();
		}

		void onSpecial() override {
			onInput(getInputValue());
		}

		void refresh() {
			onSpecial();
		}

		virtual std::string toolTip() {
			return "";
		}
		virtual void renderComboContent() = 0;
		virtual void onInput(const std::string& text) = 0;
	};
};