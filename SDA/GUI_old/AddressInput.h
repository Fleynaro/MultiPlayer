#pragma once
#include "Shared/GUI/Widgets/Template/InteractiveInput.h"
#include <Address/Address.h>
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
		AddressInput()
			: m_addressValidEnteredEvent(this, this)
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
				m_addressValidEnteredEvent.invoke(this);
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

		Events::SpecialEventType& getAddressValidEnteredEvent() {
			return m_addressValidEnteredEvent;
		}
	private:
		void* m_addr;
		void* m_lastValidAddr;
		Events::SpecialEventType m_addressValidEnteredEvent;
	};


	class AddressValueEditor : public Container
	{
	public:
		class Input
			: public Container
		{
		public:
			Input(CE::Address address)
				: m_address(address), m_updateEvent(this, this)
			{}

			virtual void change() = 0;
			virtual void setReadOnly(bool toggle) = 0;

			Events::SpecialEventType m_updateEvent;
		protected:
			CE::Address m_address;
		};

		class TextInput : public Input
		{
		public:
			TextInput(CE::Address address, bool unicode = false)
				: Input(address), m_unicode(unicode)
			{
				addItem(m_valueInput = new Elements::Input::Text);
				m_valueInput->getSpecialEvent() += [&](ISender* sender) {
					m_updateEvent.invoke(sender);
				};
				read();
			}

			void change() override {
				if (m_valueInput->getInputValue().length() > m_sourceLength)
					throw Exception(m_valueInput, "your string is bigger than the source one");

				auto str = m_valueInput->getInputValue();
				for (int i = 0, delta = m_sourceLength - static_cast<int>(str.length()); i < delta; i++)
					str.push_back(' ');

				if(m_unicode) {
					auto wStr = Generic::String::s2ws(str);
					memcpy_s(
						m_address.getAddress(),
						m_sourceLength,
						wStr.data(),
						wStr.length() * 2);
				}
				else {
					memcpy_s(
						m_address.getAddress(),
						m_sourceLength,
						str.data(),
						str.length());
				}
			}

			void setReadOnly(bool toggle) override {
				m_valueInput->setReadOnly(toggle);
			}
		private:
			Elements::Input::Text* m_valueInput;
			bool m_unicode;
			int m_sourceLength;

			template<typename T>
			const T* getRawString() {
				return (const T*)m_address.getAddress();
			}

			void read() {
				std::string str;
				if (m_unicode) {
					str = Generic::String::ws2s(getRawString<wchar_t>());
				}
				else {
					str = getRawString<char>();
				}
				
				m_valueInput->setInputValue(str);
				m_sourceLength = static_cast<int>(str.length());
			}
		};

		class PointerInput : public Input
		{
		public:
			PointerInput(CE::Address address)
				: Input(address)
			{
				addItem(m_valueInput = new AddressInput);
				m_valueInput->getSpecialEvent() += [&](ISender* sender) {
					m_updateEvent.invoke(sender);
				};
				m_valueInput->setAddress(m_address.get<void*>());
			}

			void change() override {
				auto value = m_valueInput->getInputValue64();
				memcpy_s(m_address.getAddress(), sizeof(std::uintptr_t), &value, sizeof(std::uintptr_t));
			}

			void setReadOnly(bool toggle) override {
				m_valueInput->setReadOnly(toggle);
			}
		private:
			AddressInput* m_valueInput;
		};

		class NumericInput : public Input
		{
		public:
			NumericInput(CE::Address address, CE::DataType::Type* type)
				: Input(address), m_type(type)
			{
				auto basicType = m_type->getBaseType()->getId();

				if (basicType != DataType::SystemType::Void)
				{
					if (basicType == DataType::SystemType::Bool) {
						m_valueInput = new Elements::Generic::Checkbox("", m_address.get<bool>());
					}
					else if (basicType == DataType::SystemType::Float) {
						m_valueInput = (new Elements::Input::Float)
							->setInputValue(m_address.get<float>());
					}
					else if (basicType == DataType::SystemType::Double) {
						m_valueInput = (new Elements::Input::Double)
							->setInputValue(m_address.get<double>());
					}
					else {
						if (m_type->getSize() <= 4) {
							uint64_t value = m_address.get<uint32_t>();
							if (m_type->getSize() == 1)
								value &= 0xFF;
							if (m_type->getSize() == 2)
								value &= 0xFFFF;
							m_valueInput = (new Elements::Input::Int)
								->setInputValue(static_cast<int>(value));
						}
					}
				}
				if(m_valueInput == nullptr)
					m_valueInput = (new Elements::Input::Int)
						->setInputValue(m_address.get<uint32_t>());

				m_valueInput->getSpecialEvent() += [&](ISender* sender) {
					m_updateEvent.invoke(sender);
				};

				addItem(m_valueInput);
			}

			void change() override {
				auto value = m_valueInput->getInputValue64();
				memcpy_s(m_address.getAddress(), m_type->getSize(), &value, m_type->getSize());
			}

			void setReadOnly(bool toggle) override {
				m_valueInput->setReadOnly(toggle);
			}
		private:
			CE::DataType::Type* m_type;
			Elements::Input::IInput* m_valueInput;
		};

		class EnumInput : public Input
		{
		public:
			EnumInput(CE::Address address, CE::DataType::Enum* enumeration)
				: Input(address), m_enumeration(enumeration)
			{
				addItem(m_valueInput = new Elements::Input::FilterInt);
				m_valueInput->setInputValue(std::to_string(m_address.get<int>()));
				m_valueInput->setCompare(true);
				for (auto field : m_enumeration->getFieldDict()) {
					m_valueInput->addItem(field.second, field.first);
				}

				m_valueInput->getSpecialEvent() += [&](ISender* sender) {
					m_updateEvent.invoke(sender);
				};
			}

			void change() override {
				if(!m_valueInput->isNumber())
					throw Exception(m_valueInput, "enter a number!");
				auto value = m_valueInput->getInputValue64();
				memcpy_s(m_address.getAddress(), m_enumeration->getSize(), &value, m_enumeration->getSize());
			}

			void setReadOnly(bool toggle) override {
				m_valueInput->setReadOnly(toggle);
			}
		private:
			CE::DataType::Enum* m_enumeration;
			Elements::Input::FilterInt* m_valueInput;
		};

		struct Style {
			bool m_typeSelector = false;
			bool m_protectSelector = true;
			bool m_pointerDereference = true;
			bool m_arrayItemSelector = true;
			bool m_changeValueByButton = true;
			bool m_dereference = false;
		};

		AddressValueEditor(void* address, CE::DataType::Type* type = new CE::DataType::UInt64, Style style = Style())
			: m_address(address), m_type(type), m_style(style)
		{
			m_eventUpdate = Events::Listener(
				std::function([&](Events::ISender* sender) {
					updateProtect();
				})
			);
			m_eventUpdate->setCanBeRemoved(false);

			if (m_style.m_dereference) {
				m_ptrLevel = getMaxPossibleDereferenceLevel();
			}

			m_type->addOwner();
			build();
		}

		~AddressValueEditor() {
			m_type->free();
			delete m_eventUpdate;
		}

		void onVisibleOn() override {
			if (m_protectContainer != nullptr) {
				m_protectContainer->clear();
				buildProtectSelector(m_protectContainer);
			}
		}

		void rebuild() {
			m_valueInput = nullptr;
			m_protectContainer = nullptr;
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

			if (m_style.m_typeSelector) {
				buildTypeSelector();
			}

			(*this)
				.text("Type: ")
				.sameLine()
				.addItem(new Units::Type(m_type));

			if (m_style.m_protectSelector) {
				(*this)
					.newLine()
					.addItem(m_protectContainer = new Container);
				buildProtectSelector(m_protectContainer);
				updateProtect(false);
			}
			if (m_style.m_pointerDereference) {
				buildPointerDereference();
			}
			if (m_style.m_arrayItemSelector) {
				buildArrayItemSelector();
			}
			
			buildInputForm();
		}

		void buildProtectSelector(Container* container) {
			auto protect = getAddress().getProtect();
			(*container)
				.addItem(m_cb_protect_Read = new Elements::Generic::Checkbox("R", protect & CE::Address::Read, m_eventUpdate)).sameLine()
				.addItem(m_cb_protect_Write = new Elements::Generic::Checkbox("W", protect & CE::Address::Write, m_eventUpdate)).sameLine()
				.addItem(m_cb_protect_Execute = new Elements::Generic::Checkbox("E", protect & CE::Address::Execute, m_eventUpdate))
				.newLine();
		}

		void buildInputForm() {
			if (getCurPointerLvl() > 0) {
				m_valueInput = new PointerInput(getAddress());
			}
			else if (m_type->getGroup() == DataType::Type::Simple || m_type->getGroup() == DataType::Type::Typedef) {
				if (m_type->isString()) {
					m_valueInput = new TextInput(getAddress(), m_type->getBaseType()->getId() == DataType::SystemType::WChar);
				}

				if(m_valueInput == nullptr)
					m_valueInput = new NumericInput(getAddress(), m_type->getBaseType());
			}
			else if (auto Enum = dynamic_cast<CE::DataType::Enum*>(m_type->getBaseType())) {
				m_valueInput = new EnumInput(getAddress(), Enum);
			}

			if (m_valueInput != nullptr) {
				(*this)
					.newLine()
					.text("Value:")
					.addItem(m_valueInput)
					.sameLine();

				if (m_style.m_changeValueByButton) {
					(*this)
						.addItem(
							new Elements::Button::ButtonStd(
								"ok",
								Events::Listener(
									std::function([&](Events::ISender* sender) {
										changeValue();
									})
								)
							)
						);
				}
				else {
					m_valueInput->m_updateEvent += [&](Events::ISender* sender) {
						changeValue();
					};
				}
			}

			if (m_type->getGroup() == DataType::Type::Class) {
				newLine()
				.text("Link to class editor.");
			}
		}

		void changeValue() {
			if (m_style.m_protectSelector && !m_cb_protect_Write->isSelected())
				throw Exception(m_cb_protect_Write, "You cannot change value at this address. Need right on writing.");
			m_valueInput->change();
			rebuild();
		}

		int getMaxPossibleDereferenceLevel() {
			bool isVoid = m_type->getId() == DataType::SystemType::Void;
			return max(0, min(3, m_type->getPointerLvl() - isVoid - m_type->isArray() - 1));
		}

		void buildPointerDereference() {
			auto ptrLvl = getMaxPossibleDereferenceLevel();
			if (ptrLvl > 0) {
				Elements::List::Combo* combo;
				(*this)
					.text("Dereference:")
					.addItem(combo = new Elements::List::Combo("", m_ptrLevel));
				combo->addItem("No");
				CE::Address addr = getAddress(m_ptrLevel).dereference();
				
				static const std::vector<const char*> names = { "Level 1 - *", "Level 2 - **", "Level 3 - ***" };
				for (int i = 0; i < ptrLvl; i++) {
					if (!addr.canBeRead())
						break;
					combo->addItem(names[i]);
					addr = addr.dereference();
				}

				combo->getSpecialEvent() += [&](Events::ISender* sender_) {
					auto sender = static_cast<Elements::List::Combo*>(sender_);
					m_ptrLevel = sender->getSelectedItem();
					rebuild();
				};
			}
		}

		void buildArrayItemSelector() {
			if (m_type->getArraySize() > 0) {
				Elements::Input::Int* indexInput;
				(*this)
					.text("Item index: ")
					.addItem(indexInput = new Elements::Input::Int);
				indexInput->getSpecialEvent() += [&](Events::ISender* sender_) {
					auto sender = static_cast<Elements::Input::Int*>(sender_);
					if (sender->getInputValue() >= 0) {
						m_arrayIndex = sender->getInputValue();
						if (isValid()) {
							rebuild();
						}
					}
				};
				indexInput->setInputValue(m_arrayIndex);
			}
		}

		void buildTypeSelector();

		int getCurPointerLvl() {
			return getMaxPossibleDereferenceLevel() - m_ptrLevel;
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
				offset = m_arrayIndex * static_cast<DataType::Array*>(m_type)->getItemSize();
			}
			return (void*)((std::uintptr_t)m_address + offset);
		}

		void setInfo(int arrayIndex, int ptrLevel) {
			m_arrayIndex = arrayIndex;
			m_ptrLevel = ptrLevel;
		}

		void setType(CE::DataType::Type* type) {
			if (m_type != nullptr)
				m_type->free();
			m_type = type;
			m_type->addOwner();
		}

		void setTypeManager(TypeManager* typeManager) {
			m_typeManager = typeManager;
		}
	private:
		void* m_address;
		int m_arrayIndex = 0;
		int m_ptrLevel = 0;
		Style m_style;
		CE::DataType::Type* m_type;
		Events::SpecialEventType::EventHandlerType* m_eventUpdate;
		Container* m_protectContainer = nullptr;
		Elements::Generic::Checkbox* m_cb_protect_Read = nullptr;
		Elements::Generic::Checkbox* m_cb_protect_Write = nullptr;
		Elements::Generic::Checkbox* m_cb_protect_Execute = nullptr;
		Input* m_valueInput = nullptr;
		TypeManager* m_typeManager = nullptr;
	};

	class IntegralValueInput
		: public Container
	{
	public:
		IntegralValueInput(uint64_t value = 0, CE::DataType::Type* type = new CE::DataType::UInt64)
			: m_value(value)
		{
			AddressValueEditor::Style style;
			style.m_typeSelector = true;
			style.m_protectSelector = false;
			style.m_pointerDereference = false;
			style.m_arrayItemSelector = false;
			style.m_changeValueByButton = false;
			addItem(m_addressValueEditor = new AddressValueEditor(&m_value, type, style));
		}

		void changeType(CE::DataType::Type* type) {
			m_addressValueEditor->setType(type);
			m_addressValueEditor->rebuild();
		}

		uint64_t& getValue() {
			return m_value;
		}

		AddressValueEditor* getAddressValueEditor() {
			return m_addressValueEditor;
		}
	private:
		AddressValueEditor* m_addressValueEditor;
		uint64_t m_value;
	};
};