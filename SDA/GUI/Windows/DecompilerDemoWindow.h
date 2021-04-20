#pragma once
#include <GUI.h>
#include <Widgets/CodeEditor/CodeEditor.h>

namespace GUI {
	class DecompilerDemoWindow : public Window
	{
		Widget::CodeEditor* m_asmCodeEditor;
		Widget::CodeEditor* m_decCodeEditor;
		Input::TextInput m_bytes_input;
		Button::StdButton m_deassembly_btn;
		Button::StdButton m_decompile_btn;
	public:
		DecompilerDemoWindow()
			: Window("Decompiler")
		{
			m_asmCodeEditor = new Widget::CodeEditor("assembler code", ImVec2(200.0f, 300.0f));
			m_asmCodeEditor->getEditor().SetLanguageDefinition(TextEditor::LanguageDefinition::C());
			m_decCodeEditor = new Widget::CodeEditor("decompiled code", ImVec2(200.0f, 400.0f));
			m_decCodeEditor->getEditor().SetLanguageDefinition(TextEditor::LanguageDefinition::C());
			m_decCodeEditor->getEditor().SetReadOnly(true);

			m_bytes_input = Input::TextInput();
			m_deassembly_btn = Button::StdButton("deassembly");
			m_decompile_btn = Button::StdButton("decompile");
		}

		void renderWindow() override {
			{
				m_asmCodeEditor->show();
			}

			{
				NewLine();
				Separator();
				if (m_deassembly_btn.present()) {

				}
				m_bytes_input.show();
			}

			{
				NewLine();
				Separator();
				if (m_decompile_btn.present()) {

				}
				m_decCodeEditor->show();
			}
		}
	};
};