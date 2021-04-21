#pragma once
#include <GUI.h>
#include <Widgets/CodeEditor/CodeEditor.h>

namespace GUI {
	class DecompilerDemoWindow : public Window
	{
		Widget::CodeEditor* m_asmCodeEditor;
		Widget::CodeEditor* m_decCodeEditor;
		Text::ColoredText m_asmParsingErrorText;
		Input::TextInput m_bytes_input;
		Button::StdButton m_deassembly_btn;
		Button::StdButton m_decompile_btn;
	public:
		DecompilerDemoWindow()
			: Window("Decompiler")
		{
			// Window params
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_MenuBar);
			setPosX(0.0);
			setPosY(0.0);

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
		}

		void renderWindow() override {
			{
				Text::Text("Here write your assembler code:").show();
				m_asmCodeEditor->show();
				m_asmParsingErrorText.show();
				NewLine();
				if (m_deassembly_btn.present()) {
					deassembly();
				}
			}

			{
				NewLine();
				Separator();
				Text::Text("The machine code is presented as bytes in hexadecimal format:").show();
				m_bytes_input.show();
				NewLine();
				if (m_decompile_btn.present()) {

				}
			}

			{
				NewLine();
				Separator();
				Text::Text("Here the decompiled code is presented:").show();
				m_decCodeEditor->show();
			}
		}

		void deassembly();
	};
};