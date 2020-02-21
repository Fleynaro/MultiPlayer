#pragma once
#include "Shared/GUI/Widgets/Template/InteractiveInput.h"
#include <Pointer/Pointer.h>

using namespace CE;

namespace GUI
{
	//MY TODO: ��������� �������� ������������ �����-�� ����(������), �.�. ������� ����������
	//MY TODO: ��������� ���� � ���������� ��� �����, � ����� ���������� �������� �� ����. ��������� ������������� ���������

	class AddressInput
		: public Widget::Template::InteractiveInput
	{
	public:
		class AddressParser
		{
		public:
			//base + ((0x2123 - 0x1567) * 3 + 0xA) - ������ � ������, ��� ������ ������� ������. ����� ��� ������ ������� ������������ �����
			static std::uintptr_t calculate(const std::string& expression)
			{
				return Generic::String::HexToNumber(expression);
			}
		};

		Container* m_comboContent;
		AddressInput()
		{
			m_comboContent = new Container;
			m_comboContent->setParent(this);
		}

		~AddressInput() {
			m_comboContent->destroy();
		}

		void renderComboContent() override {
			m_comboContent->show();
		}

		void onInput(const std::string& text) override {
			m_addr = (void*)AddressParser::calculate(text);

			m_comboContent->clear();
			m_comboContent->text(Pointer(m_addr).canBeRead() ? "valid" : "invalid");
		}

		void* getAddress() {
			return m_addr;
		}
	private:
		void* m_addr;
	};
};