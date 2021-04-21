#pragma once
#include <GUI.h>
#include <Widgets/CodeEditor/CodeEditor.h>

namespace CE {
	class ProgramModule;
};

namespace GUI {
	class DecompilerDemoWindow : public Window
	{
		Widget::CodeEditor* m_asmCodeEditor;
		Widget::CodeEditor* m_decCodeEditor;
		Text::ColoredText m_asmParsingErrorText;
		Input::TextInput m_bytes_input;
		Button::StdButton m_deassembly_btn;
		Button::StdButton m_decompile_btn;

		CE::ProgramModule* m_programModule;
	public:
		DecompilerDemoWindow(HWND hWnd)
			: Window(hWnd, "Decompiler")
		{
			// Window params
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_MenuBar);
			makeFitHostWindowSize(true);

			// Controls
			m_asmCodeEditor = new Widget::CodeEditor("assembler code", ImVec2(200.0f, 300.0f));
			m_asmCodeEditor->getEditor().SetLanguageDefinition(TextEditor::LanguageDefinition::C());
			m_decCodeEditor = new Widget::CodeEditor("decompiled code", ImVec2(200.0f, 400.0f));
			m_decCodeEditor->getEditor().SetLanguageDefinition(TextEditor::LanguageDefinition::C());
			m_decCodeEditor->getEditor().SetReadOnly(true);

			m_asmParsingErrorText.setColor(ColorRGBA(0xFF0000FF));
			m_asmParsingErrorText.setDisplay(false);
			m_bytes_input = Input::TextInput();
			m_deassembly_btn = Button::StdButton("deassembly");
			m_decompile_btn = Button::StdButton("decompile");

			initProgram();
		}

	protected:

		void renderWindow() override {
			m_asmCodeEditor->getSize().x = getSize().x;
			m_decCodeEditor->getSize().x = getSize().x;

			if (ImGui::BeginTabBar("#tabs"))
			{
				ImGuiTabItemFlags_ tabFlag = ImGuiTabItemFlags_None;

				if (ImGui::BeginTabItem("disassembler", nullptr, tabFlag))
				{
					{
						Text::Text("Here write your assembler code:").show();
						m_asmCodeEditor->show();
						m_asmParsingErrorText.show();
						NewLine();
						if (m_deassembly_btn.present()) {
							auto textCode = m_asmCodeEditor->getEditor().GetText();
							if (!textCode.empty()) {
								deassembly(textCode);
							}
						}
					}

					{
						NewLine();
						Separator();
						Text::Text("The machine code is presented as bytes in hexadecimal format:").show();
						m_bytes_input.show();
						NewLine();
						if (m_decompile_btn.present()) {
							if (!m_bytes_input.getInputText().empty()) {
								tabFlag = ImGuiTabItemFlags_SetSelected;
								decompile(m_bytes_input.getInputText());
							}
						}
					}
					ImGui::EndTabItem();
				}

				if (ImGui::BeginTabItem("decompiler", nullptr, tabFlag))
				{
					{
						NewLine();
						Separator();
						Text::Text("Here the decompiled code is presented:").show();
						m_decCodeEditor->show();
					}
					ImGui::EndTabItem();
				}
			}
		}

	private:

		void initProgram();

		void deassembly(const std::string& textCode);

		void decompile(const std::string& hexBytesStr);
	};
};