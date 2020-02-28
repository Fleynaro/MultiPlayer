#pragma once
#include "Shared/GUI/Widgets/Template/InteractiveInput.h"
#include <Pointer/Pointer.h>

using namespace CE;

namespace GUI
{
	//MY TODO: поддержка оффсетов относительно какой-то базы(модуля), т.е. алгебра указателей
	//MY TODO: запомнить ввод и предлагать его потом, а также предлагать варианты по дефу. Учитывать относительную адресацию
	//MY TODO: мощный интерпретатор адресной арифметики с возможностью разыменовывания указателей, юзание регистров и т.д

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
			return Address(m_addr).canBeRead();
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


	class AddressValueEditor : public Container
	{
	public:
		AddressValueEditor(CE::Address address, CE::Type::Type* type)
			: m_address(address), m_type(type)
		{
			m_eventUpdate = new Events::EventUI(EVENT_LAMBDA(info) {
				/*if (!isValid())
					return;*/
				update();
			});
			m_eventUpdate->setCanBeRemoved(false);

			(*this)
				.addItem(m_cb_protect_Read = new Elements::Generic::Checkbox("R", true, m_eventUpdate)).sameLine()
				.addItem(m_cb_protect_Write = new Elements::Generic::Checkbox("W", true, m_eventUpdate)).sameLine()
				.addItem(m_cb_protect_Execute = new Elements::Generic::Checkbox("E", true, m_eventUpdate));
		}

		bool isValid() {
			return m_address.canBeRead();
		}

		void update() {
			m_address.setProtect(getProtect());
		}

		CE::Address::ProtectFlags getProtect() {
			int protect =
				CE::Address::Read * m_cb_protect_Read->isSelected() |
				CE::Address::Write * m_cb_protect_Write->isSelected() |
				CE::Address::Execute * m_cb_protect_Execute->isSelected();
			return (CE::Address::ProtectFlags)protect;
		}
	private:
		CE::Address m_address;
		CE::Type::Type* m_type;
		Events::EventHandler* m_eventUpdate;
		Elements::Generic::Checkbox* m_cb_protect_Read = nullptr;
		Elements::Generic::Checkbox* m_cb_protect_Write = nullptr;
		Elements::Generic::Checkbox* m_cb_protect_Execute = nullptr;
	};
};