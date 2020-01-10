#pragma once

#include "../../Items/IWidget.h"
#include "../PopupContextWindow.h"
#include "TextEditor.h"
#include "Utility/FileWrapper.h"

namespace GUI::Widget
{
	namespace Elements
	{
		class TextEditor
			: public Elem, public Attribute::Name<TextEditor>
		{
		public:
			TextEditor(
				std::string name,
				::TextEditor::LanguageDefinition lang,
				::TextEditor::ErrorMarkers markers
			)
				: Attribute::Name<TextEditor>(name)
			{
				getTextEditor().SetLanguageDefinition(lang);
				getTextEditor().SetErrorMarkers(markers);
			}
			~TextEditor() {}

			::TextEditor& getTextEditor() {
				return m_editor;
			}

			void render() override {
				m_editor.Render(getName().c_str());
			}
		protected:
			::TextEditor m_editor;
		};
	};

	class CodeEditor : public IWidget
	{
	public:
		CodeEditor(
			std::string name,
			TextEditor::LanguageDefinition lang = TextEditor::LanguageDefinition(),
			TextEditor::ErrorMarkers markers = TextEditor::ErrorMarkers()
		)
			: IWidget(name)
		{
			m_editor = new Elements::TextEditor(name, lang, markers);
			getMainContainer()
				.addItem(m_editor);
		}
		~CodeEditor() {}

		Elements::TextEditor* getEditorElemPtr() {
			return m_editor;
		}

		TextEditor& getEditor() {
			return getEditorElemPtr()->getTextEditor();
		}

		void setCode(const std::string& code) {
			getEditor().SetText(code);
		}

		std::string getCode() {
			return getEditor().GetText();
		}
	protected:
		Elements::TextEditor* m_editor;
	};

	class CodeFileEditor : public CodeEditor
	{
	public:
		CodeFileEditor(
			std::string name,
			FS::File file,
			TextEditor::LanguageDefinition lang = TextEditor::LanguageDefinition(),
			TextEditor::ErrorMarkers markers = TextEditor::ErrorMarkers()
		)
			: CodeEditor(name, lang, markers), m_file(file)
		{
			loadCodeFromFile();
		}

		void loadCodeFromFile() {
			if (!getFile().exists()) {
				//throw ex
				return;
			}
			
			setCode(
				FS::ScriptFileDesc(getFile()).getData()
			);
		}

		void saveToFile() {
			if (!getFile().exists()) {
				//throw ex
				return;
			}

			FS::ScriptFileDesc(
				getFile(),
				std::ios::out
			).setData(getCode());
		}

		std::string getStatusInfo() {
			auto cpos = getEditor().GetCursorPosition();
			return Generic::String::format("%6d/%-6d %6d lines  | %s | %s | %s", cpos.mLine + 1, cpos.mColumn + 1, getEditor().GetTotalLines(),
				getEditor().IsOverwrite() ? "Ovr" : "Ins",
				getEditor().CanUndo() ? "*" : " ",
				getEditor().GetLanguageDefinition().mName.c_str()
			);
		}

		FS::File& getFile() {
			return m_file;
		}

		static TextEditor::LanguageDefinition getLangByFile(FS::File file) {
			if (file.getFormat() == "js") {
				return TextEditor::LanguageDefinition::CPlusPlus();
			}
			else if (file.getFormat() == "lua") {
				return TextEditor::LanguageDefinition::Lua();
			}
			return TextEditor::LanguageDefinition();
		}
	protected:
		FS::File m_file;
	};
};