#pragma once
#include "Shared/GUI/Widgets/Template/InteractiveInput.h"
#include <Pointer/Pointer.h>

using namespace CE;

namespace GUI
{
	//MY TODO: поддержка оффсетов относительно какой-то базы(модуля), т.е. алгебра указателей
	//MY TODO: запомнить ввод и предлагать его потом, а также предлагать варианты по дефу. Учитывать относительную адресацию

	class AddressInput
		: public Widget::Template::InteractiveInput
	{
	public:
		class AddressParser
		{
		public:
			//base + ((0x2123 - 0x1567) * 3 + 0xA) - парсим в дерево, где каждая вершина строка. Далее для каждой вершины рассчитываем число
			static std::uintptr_t calculate(const std::string& expression)
			{
				return Generic::String::HexToNumber(expression);
			}
		};

		Container* m_comboContent;
		AddressInput(Events::EventHandler* eventFocused = nullptr)
		{
			m_comboContent = new Container;
			m_comboContent->setParent(this);
		}

		~AddressInput() {
			m_comboContent->destroy();
		}

		void onFocusedIn() override {}
		void onFocusedUpdate() override {}

		void renderComboContent() override {
			m_comboContent->show();
		}

		bool isAddressValid() {
			return Pointer(m_addr).canBeRead();
		}

		void onInput(const std::string& text) override {
			m_addr = (void*)AddressParser::calculate(text);
			if (isAddressValid()) {
				m_lastValidAddr = m_addr;
			}

			m_comboContent->clear();
			m_comboContent->text(isAddressValid() ? "valid" : "invalid");
			//MY TODO: показать модуль, сегмент, права доступа(R/W/E)
		}

		void setAddress(void* addr) {
			setInputValue("0x" + Generic::String::NumberToHex((uint64_t)addr));
			m_lastValidAddr = m_addr = addr;
		}

		void* getAddress() {
			return m_addr;
		}

		void* getLastValidAddress() {
			return m_lastValidAddr;
		}
	private:
		void* m_addr;
		void* m_lastValidAddr;
	};
};