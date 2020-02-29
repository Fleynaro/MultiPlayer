#pragma once
#include "Shared/GUI/Widgets/Template/InteractiveInput.h"
#include <Pointer/Pointer.h>
#include "Type.h"

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
			: m_addressValidEnteredEvent(this)
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

		AddressInput* setAddress(void* addr) {
			setInputValue("0x" + Generic::String::NumberToHex((uint64_t)addr));
			m_lastValidAddr = m_addr = addr;
			return this;
		}

		void* getAddress() {
			return m_addr;
		}

		void* getLastValidAddress() {
			return m_lastValidAddr;
		}

		uint64_t getInputValue64() override {
			return (uint64_t&)m_lastValidAddr;
		}

		Events::Messager& getAddressValidEnteredEvent() {
			return m_addressValidEnteredEvent;
		}
	private:
		void* m_addr;
		void* m_lastValidAddr;
		Events::Messager m_addressValidEnteredEvent;
	};


	class AddressValueEditor : public Container
	{
	public:
		AddressValueEditor(void* address, CE::Type::Type* type = nullptr, bool changeType = false)
			: m_address(address), m_type(type), m_changeType(changeType)
		{
			m_eventUpdate = new Events::EventUI(EVENT_LAMBDA(info) {
				updateProtect();
			});
			m_eventUpdate->setCanBeRemoved(false);

			build();
		}

		~AddressValueEditor() {
			delete m_eventUpdate;
		}

		void rebuild() {
			m_valueInput = nullptr;
			clear();
			build();
		}

		void build() {
			if (!isValid()) {
				m_ptrLevel = 0;
				m_arrayIndex = 0;
				if (!isValid()) {
					text("Address is not valid.");
					return;
				}
			}

			if (m_changeType) {
				buildTypeSelector();
			}

			(*this)
				.text("Type: ")
				.sameLine()
				.addItem(new Units::Type(m_type))
				.newLine();

			buildProtectSelector();
			buildInputForm();

			updateProtect(false);
		}

		void buildProtectSelector() {
			auto protect = getAddress().getProtect();
			(*this)
				.addItem(m_cb_protect_Read = new Elements::Generic::Checkbox("R", protect & CE::Address::Read, m_eventUpdate)).sameLine()
				.addItem(m_cb_protect_Write = new Elements::Generic::Checkbox("W", protect & CE::Address::Write, m_eventUpdate)).sameLine()
				.addItem(m_cb_protect_Execute = new Elements::Generic::Checkbox("E", protect & CE::Address::Execute, m_eventUpdate))
				.newLine();
		}

		void buildInputForm() {
			if (m_type->getPointerLvl() > 0) {
				Elements::List::Combo* combo;
				(*this)
					.text("Dereference:")
					.addItem(combo = new Elements::List::Combo("", m_ptrLevel));
				combo->addItem("No");
				CE::Address addr = getAddress(m_ptrLevel);

				static const std::vector<const char*> names = {"Level 1 - *", "Level 2 - **", "Level 3 - ***" };
				for (int i = 0; i < min(3, m_type->getPointerLvl()); i++) {
					addr = addr.dereference();
					if (addr.canBeRead()) {
						combo->addItem(names[i]);
					}
				}

				combo->getSpecialEvent() += new Events::EventUI(EVENT_LAMBDA(info) {
					auto sender = static_cast<Elements::List::Combo*>(info->getSender());
					m_ptrLevel = sender->getSelectedItem();
					rebuild();
				});
			}

			if (m_type->getArraySize() > 0) {
				Elements::Input::Int* indexInput;
				(*this)
					.text("Item index: ")
					.sameLine()
					.addItem(indexInput = new Elements::Input::Int);
				indexInput->getSpecialEvent() += new Events::EventUI(EVENT_LAMBDA(info) {
					auto sender = static_cast<Elements::Input::Int*>(info->getSender());
					if (sender->getInputValue() >= 0) {
						m_arrayIndex = sender->getInputValue();
						if (isValid()) {
							rebuild();
						}
					}
				});
				indexInput->setInputValue(m_arrayIndex);
			}

			if (isPointerInput()) {
				auto addrInput = new AddressInput;
				m_valueInput = addrInput;
				addrInput->setAddress(getAddress().get<void*>());
			}
			else if (m_type->getGroup() == Type::Type::Simple || m_type->getGroup() == Type::Type::Typedef) {
				auto basicType = Type::SystemType::GetBasicTypeOf(m_type);

				if (basicType != Type::SystemType::Void)
				{
					if (basicType == Type::SystemType::Bool) {
						m_valueInput = new Elements::Generic::Checkbox("", getAddress().get<bool>());
					}
					else if (basicType == Type::SystemType::Float) {
						m_valueInput = (new Elements::Input::Float)
							->setInputValue(getAddress().get<float>());
					}
					else if (basicType == Type::SystemType::Double) {
						m_valueInput = (new Elements::Input::Double)
							->setInputValue(getAddress().get<double>());
					}
					else {
						if (m_type->getSize() <= 4) {
							uint64_t value = getAddress().get<uint32_t>();
							if (m_type->getSize() == 1)
								value &= 0xFF;
							if (m_type->getSize() == 2)
								value &= 0xFFFF;
							m_valueInput = (new Elements::Input::Int)
								->setInputValue(value);
						}
					}
				}
			}
			else if (m_type->getGroup() == Type::Type::Enum) {
				m_valueInput = (new Elements::Input::Int)
					->setInputValue(getAddress().get<uint32_t>());
			}

			if (m_valueInput != nullptr) {
				(*this)
					.newLine()
					.text("Value:")
					.addItem(m_valueInput)
					.sameLine()
					.addItem(
						new Elements::Button::ButtonStd(
							"ok",
							new Events::EventUI(EVENT_LAMBDA(info) {
								int size = m_type->getBaseType()->getSize();
								if (isPointerInput())
									size = sizeof(std::uintptr_t);
								auto value = m_valueInput->getInputValue64();
								setValue(value, size);
								rebuild();
							})
						)
					);
			}

			if (m_type->getGroup() == Type::Type::Class) {
				text("Link to class editor.");
			}
		}

		void buildTypeSelector();

		bool isPointerInput() {
			return m_ptrLevel < m_type->getPointerLvl();
		}

		bool isValid() {
			return getAddress().canBeRead();
		}

		void updateProtect(bool change = true) {
			auto protect = getSelectedProtect();
			if(change)
				getAddress().setProtect(protect, m_type->getSize());

			if(m_valueInput != nullptr)
				m_valueInput->setReadOnly(!(protect & CE::Address::Write));
		}

		CE::Address::ProtectFlags getSelectedProtect() {
			int protect =
				CE::Address::Read * m_cb_protect_Read->isSelected() |
				CE::Address::Write * m_cb_protect_Write->isSelected() |
				CE::Address::Execute * m_cb_protect_Execute->isSelected();
			return (CE::Address::ProtectFlags)protect;
		}

		CE::Address getAddress(int ptrLevel = 0) {
			if (ptrLevel != m_ptrLevel) {
				return getAddress(ptrLevel + 1).dereference();
			}

			int offset = 0;
			if (m_type->isArray()) {
				offset = m_arrayIndex * static_cast<Type::Array*>(m_type)->getItemSize();
			}
			return (void*)((std::uintptr_t)m_address + offset);
		}

		void setValue(uint64_t value, int size = sizeof(uint64_t)) {
			memcpy_s(getAddress().getAddress(), size, &value, size);
		}
	private:
		void* m_address;
		int m_arrayIndex = 0;
		int m_ptrLevel = 0;
		bool m_changeType;
		CE::Type::Type* m_type;
		Events::EventHandler* m_eventUpdate;
		Elements::Generic::Checkbox* m_cb_protect_Read = nullptr;
		Elements::Generic::Checkbox* m_cb_protect_Write = nullptr;
		Elements::Generic::Checkbox* m_cb_protect_Execute = nullptr;
		Elements::Input::IInput* m_valueInput = nullptr;
	};
};