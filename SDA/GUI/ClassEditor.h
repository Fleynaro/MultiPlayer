#pragma once
#include "Windows/ItemLists/DataTypeList.h"
#include "GUI/Signature.h"
#include "AddressInput.h"

using namespace CE;

namespace GUI::Widget
{
	//MY TODO: смена адреса(сделать спец. ввод)
	//MY TODO: vtable
	//MY TODO: stack overflow
	//MY TODO: неиспользуемые €чейки
	//MY TODO: предугадывание типа €чейки(указатель, float)
	//MY TODO: выделение классов, панель справа дл€ выдел. класса, указание в ней названи€, отн. и абс. размера класса
	//MY TODO: множественное выделение €чеек, добавление типа €чеейкам(как в гидре!)
	//MY TODO: несколько классов могут фильтроватьс€ одной панелью
	//MY TODO: getWindow()->showConfirm(), showError(), showWarning(), ....

	class ClassEditor : public Template::ItemList
	{
	public:
		class ClassHierarchy : public GUI::Container
		{
		public:
			class ClassContent : public TreeNode
			{
			public:
				class EmptyField
					: public TreeNode
				{
				public:
					class TypeViewValue : public Elements::Text::ColoredText
					{
					public:
						TypeViewValue(CE::Type::Type* type, void* addr, ColorRGBA color)
							: m_type(type), m_addr(addr), Elements::Text::ColoredText("", color)
						{}

						void render() override {
							std::string addrText = "0x" + Generic::String::NumberToHex((uint64_t)m_addr);
							if (Pointer(m_addr).canBeRead()) {
								setText(addrText + " -> " + m_type->getViewValue(m_addr));
							}
							else {
								setText(addrText + " cannot be read.");
							}
							Elements::Text::ColoredText::render();
						}
					private:
						CE::Type::Type* m_type;
						void* m_addr;
					};

					EmptyField(ClassContent* classContent, int relOffset, CE::Type::Type* type)
						: m_classContent(classContent), m_relOffset(relOffset), m_type(type)
					{
						addFlags(ImGuiTreeNodeFlags_FramePadding);

						m_eventClick = new Events::EventUI(EVENT_LAMBDA(info) {
							m_classContent->m_classHierarchy->m_classEditor->unselectClassField();
							m_classContent->m_classHierarchy->m_classEditor->selectClassField(this);
						});
						m_eventClick->setCanBeRemoved(false);

						getLeftMouseClickEvent() += m_eventClick;
					}

					~EmptyField() {
						if (m_headBaseInfo != nullptr)
							m_headBaseInfo->destroy();
						
						if(isEmpty())
							m_type->free();

						if(m_classContent->m_classHierarchy->m_classEditor->m_classFieldSelected == this)
							m_classContent->m_classHierarchy->m_classEditor->unselectClassField();

						delete m_eventClick;
					}

					void renderHeader() override {
						if (m_headBaseInfo == nullptr) {
							m_headBaseInfo = new Container;
							(*m_headBaseInfo)
								.text("0x" + Generic::String::NumberToHex(getAbsoluteOffset()) + " ", ColorRGBA(0xfaf4b6FF))
								.sameLine()
								.addItem(new Units::Type(m_type))
								.sameText(" " + getFieldName() + " ");
							if (m_classContent->m_baseAddr != nullptr) {
								(*m_headBaseInfo)
									.sameLine()
									.addItem(new TypeViewValue(m_type, m_classContent->getAddressByRelOffset(m_relOffset), ColorRGBA(0x919191FF)));
							}

							m_headBaseInfo->setParent(this);
						}

						ImGui::SameLine();
						m_headBaseInfo->show();
					}

					int getAbsoluteOffset() {
						return m_classContent->m_baseOffset + m_relOffset;
					}

					bool isEmpty() {
						return m_isEmpty;
					}

					virtual std::string getFieldName() {
						return "<empty>";
					}

					ClassContent* m_classContent;
					int m_relOffset;
				protected:
					Container* m_headBaseInfo = nullptr;
					CE::Type::Type* m_type;
					bool m_isEmpty = true;
					Events::EventHandler* m_eventClick;
				};
				friend class EmptyField;

				class Field
					: public EmptyField
				{
				public:
					Field(ClassContent* classContent, int relOffset, Type::Class::Field& field)
						: EmptyField(classContent, relOffset, field.getType()), m_field(field)
					{
						m_isEmpty = false;
					}

					std::string getFieldName() override {
						return m_field.getName();
					}
				private:
					Type::Class::Field& m_field;
				};

				class Method
					: public TreeNode
				{
				public:
					Method(API::Function::Function* method, Events::EventHandler* openFunctionCP = nullptr)
						: m_method(method), m_openFunctionCP(openFunctionCP)
					{
						addFlags(ImGuiTreeNodeFlags_FramePadding | ImGuiTreeNodeFlags_Leaf);
					}

					~Method() {
						if (m_signature != nullptr) {
							m_signature->destroy();
						}
					}

					void renderHeader() override {
						if (m_signature == nullptr) {
							m_signature = new Units::FunctionSignature(m_method,
								nullptr,
								new Events::EventHook(m_openFunctionCP, m_method),
								nullptr
							);
							m_signature->setParent(this);
						}

						ImGui::SameLine();
						m_signature->show();
					}

					CE::Function::Method* getMethod() {
						return m_method->getMethod();
					}
				private:
					API::Function::Function* m_method;
					Units::FunctionSignature* m_signature = nullptr;
					Events::EventHandler* m_openFunctionCP;
				};

				ClassContent(ClassHierarchy* classHierarchy, API::Type::Class* Class, bool calculateValues = false)
					: ClassContent(classHierarchy, Class, calculateValues, Class->getClass()->getBaseOffset())
				{}

				ClassContent(ClassHierarchy* classHierarchy, API::Type::Class* Class, bool calculateValues, int baseOffset)
					: m_classHierarchy(classHierarchy), m_class(Class), m_calculateValues(calculateValues), m_baseOffset(baseOffset)
				{
					addFlags(ImGuiTreeNodeFlags_FramePadding | ImGuiTreeNodeFlags_Bullet);
				}

				~ClassContent() {
					if (m_className != nullptr)
						m_className->destroy();

					if (m_classHierarchy->m_classEditor->m_classContentSelected == this)
						m_classHierarchy->m_classEditor->unselectClassContent();
				}

				Elements::Text::ClickedText* m_className = nullptr;
				void renderHeader() override {
					if (m_className == nullptr) {
						m_className = new Elements::Text::ClickedText(m_class->getClass()->getName(), ColorRGBA(0xeddf91FF));
						m_className->getLeftMouseClickEvent() += new Events::EventUI(EVENT_LAMBDA(info) {
							m_classHierarchy->m_classEditor->unselectClassContent();
							m_classHierarchy->m_classEditor->selectClassContent(this);
						});
						m_className->setParent(this);
					}

					m_className->show();
				}

				//MY TODO: float, double, string
				CE::Type::Type* predictTypeAtAddress(void* addr) {
					auto alignment = (char)addr % 8;
					switch (alignment)
					{
						case 0: {
							void* ptr = (void*)* (std::uintptr_t*)addr;
							if (Pointer(ptr).canBeRead()) {
								return new CE::Type::Pointer(predictTypeAtAddress(ptr));
							}
							break;
						}
					}

					if (alignment == 0 && m_classHierarchy->m_classEditor->isEmptyFields_GroupingEnabled()) {
						return new CE::Type::Array(new CE::Type::Byte, 8);
					}
					else {
						return new CE::Type::Byte;
					}
				}

				void buildFields(Container* container, const std::string& name) {
					getClass()->iterateFields([&](int& relOffset, Type::Class::Field* classField)
					{
						void* fieldAddr = getAddressByRelOffset(relOffset);

						EmptyField* field;
						if (getClass()->isDefaultField(classField)) {
							auto type = predictTypeAtAddress(fieldAddr);
							container->addItem(field = new EmptyField(this, relOffset, type));
							relOffset += type->getSize() - 1;
						}
						else {
							container->addItem(field = new Field(this, relOffset, *classField));
						}
						field->addFlags(ImGuiTreeNodeFlags_Leaf, true);

						bool canBeFilteredToRemove = true;
						if (m_baseAddr != nullptr) {
							auto fieldType = classField->getType();
							auto baseType = fieldType->getBaseType();
							if (baseType->getGroup() == Type::Type::Group::Class) {
								auto apiBaseClassType = static_cast<API::Type::Class*>(m_class->getTypeManager()->getTypeById(baseType->getId()));
								if (apiBaseClassType != nullptr) {
									if (fieldType->isArray()) {
										//поле ввода дл€ целых чисел со стрелками + добавить новые
									}
									else {
										if (fieldType->isPointer()) {
											for (int i = 0; i < fieldType->getPointerLvl(); i++) {
												if (!Pointer(fieldAddr).canBeRead())
													break;
												fieldAddr = (void*)*(std::uintptr_t*)fieldAddr;
											}
										}

										if (Pointer(fieldAddr).canBeRead()) {
											ClassHierarchy* classHierarchy;
											field->addItem(classHierarchy = new ClassHierarchy(m_classHierarchy->m_classEditor, apiBaseClassType, fieldAddr, true));
											classHierarchy->onSearch(name);
										}
										else {
											field->text("Address not valid.");
										}
									}

									field->addFlags(ImGuiTreeNodeFlags_Leaf, false);
									canBeFilteredToRemove = false;

									if (m_classHierarchy->m_classEditor->isAlwaysOpen()) {
										field->setOpen(true);
									}
								}
							}
						}

						if (canBeFilteredToRemove) {
							if (m_classHierarchy->m_classEditor->isFilterEnabled() && !m_classHierarchy->m_classEditor->checkOnInputValue(*classField, name)) {
								container->removeLastItem();
							}
						}

						return true;
					}, m_classHierarchy->m_classEditor->isEmptyFieldsEnabled());
				}

				void buildMethods(Container* container, const std::string& methodName) {
					for (auto method : getClass()->getMethodList()) {
						auto method_ = m_class->getTypeManager()->getProgramModule()->getFunctionManager()->getFunctionById(method->getId());
						if (!m_classHierarchy->m_classEditor->isFilterEnabled() || m_classHierarchy->m_classEditor->checkOnInputValue(method_, methodName)) {
							container->addItem(new Method(method_));
						}
					}
				}

				void onSearch(const std::string& name)
				{
					clear();

					buildFields(this, name);

					ColContainer* methodContainer;
					addItem(methodContainer = new ColContainer("Methods"));
					buildMethods(methodContainer, name);
				}

				void* getAddressByRelOffset(int relOffset) {
					return (void*)((std::uintptr_t)m_baseAddr + m_baseOffset + relOffset);
				}

				void setBaseAddress(void* addr) {
					m_baseAddr = addr;
				}

				Type::Class* getClass() {
					return m_class->getClass();
				}

				API::Type::Class* m_class;
			private:
				ClassHierarchy* m_classHierarchy;
				void* m_baseAddr = nullptr;
				int m_baseOffset;
				bool m_calculateValues;
			};
			friend class ClassContent;

			ClassHierarchy(ClassEditor* classEditor, API::Type::Class* targetClass, void* baseAddr = nullptr, bool isChild = false)
				: m_classEditor(classEditor), m_targetClass(targetClass)
			{
				if (!isChild) {
					m_addressInput = new AddressInput;
					m_addressInput->setParent(this);
					m_addressInput->setAddress(baseAddr);
					m_addressInput->getFocusedEvent() += new Events::EventUI(EVENT_LAMBDA(info) {
						m_classEditor->update();
					});
				}
				else {
					m_baseAddr = baseAddr;
				}

				m_targetClass->getClass()->iterateClasses([&](Type::Class* class_) {
					auto apiClassType = static_cast<API::Type::Class*>(m_targetClass->getTypeManager()->getTypeById(class_->getId()));
					if (apiClassType != nullptr) {
						ClassContent* classContent = new ClassContent(this, apiClassType, baseAddr != nullptr);
						addItem(classContent);
						m_classContents.push_back(classContent);

						if (m_classEditor->isAlwaysOpen())
							classContent->setOpen(true);

						if (m_targetClass->getClass()->getId() == class_->getId()) {
							if(m_classEditor->m_classContentSelected == nullptr)
								m_classEditor->selectClassContent(classContent);
						}
					}
					return true;
				});

				if(m_classEditor->m_classHierarchySelected == nullptr)
					m_classEditor->selectClassHierarchy(this);
			}

			~ClassHierarchy() {
				if(m_addressInput != nullptr)
					m_addressInput->destroy();
			}

			void onSearch(const std::string& name)
			{
				for (auto it : m_classContents) {
					it->setBaseAddress(getBaseAddress());
					it->onSearch(name);
				}
			}

			void* getBaseAddress() {
				return m_addressInput != nullptr ? m_addressInput->getLastValidAddress() : m_baseAddr;
			}

			AddressInput* m_addressInput = nullptr;
		private:
			API::Type::Class* m_targetClass;
			ClassEditor* m_classEditor;
			std::list<ClassContent*> m_classContents;
			void* m_baseAddr = nullptr;
		};

		class ClassView : public IView
		{
		public:
			//ClassView(ClassEditor* classEditor, API::Type::Class* Class, void* baseAddr = nullptr)
			//	: ClassView(new ClassHierarchy(classEditor, Class, baseAddr))
			//{}

			ClassView(ClassHierarchy* classHierarchy)
				: m_classHierarchy(classHierarchy)
			{}

			void onSetView() override {
				getOutContainer()
					->addItem(m_classHierarchy);
			}

			void onSearch(const std::string& name) override
			{
				m_classHierarchy->onSearch(name);
			}
		private:
			ClassHierarchy* m_classHierarchy;
		};
		
		class ClassFilter : public FilterManager::Filter
		{
		public:
			ClassFilter(const std::string& name, ClassEditor* classEditor)
				: Filter(classEditor->getFilterManager(), name), m_classEditor(classEditor)
			{}

			virtual bool isFieldFilter() {
				return false;
			}

			/*virtual bool isMethodFilter() {
				return false;
			}*/
		protected:
			ClassEditor* m_classEditor;
		};


		class FieldFilter : public ClassFilter
		{
		public:
			FieldFilter(const std::string& name, ClassEditor* classEditor)
				: ClassFilter(name, classEditor)
			{}

			bool isFieldFilter() {
				return true;
			}

			virtual bool checkFilter(API::Type::Class* Class, Type::Class::Field& field) = 0;
		};


		class ClassFilterCreator : public FilterManager::FilterCreator
		{
		public:
			ClassFilterCreator(ClassEditor* classEditor)
				: m_classEditor(classEditor), FilterCreator(classEditor->getFilterManager())
			{
				
			}

			FilterManager::Filter* createFilter(int idx) override
			{
				switch (idx)
				{
				//case 0: return new CategoryFilter(m_funcList);
				}
				return nullptr;
			}

		private:
			ClassEditor* m_classEditor;
		};

		struct StyleSettings : ItemList::StyleSettings
		{
			StyleSettings()
			{
				m_leftWidth = 250;
			}
		};

		Container* m_classHierarchyEditorContainer;
		ColContainer* m_classEditorContainer;
		ColContainer* m_classFieldContainer;

		ClassEditor(StyleSettings style = StyleSettings())
			: ItemList(new ClassFilterCreator(this), style)
		{
			//getFilterManager()->addFilter(new CategoryFilter(this));

			m_eventUpdateCB = new Events::EventUI(EVENT_LAMBDA(info) {
				update();
			});
			m_eventUpdateCB->setCanBeRemoved(false);

			(*m_underFilterCP)
				.beginReverseInserting()
					.beginContainer()
						.newLine()
						.separator()
						.beginContainer()
							.addItem(m_cb_isFilterEnabled = new Elements::Generic::Checkbox("Use filters and search", true, m_eventUpdateCB))
							.addItem(m_cb_isEmptyFieldsEnabled = new Elements::Generic::Checkbox("Empty fields", true, m_eventUpdateCB))
							.beginIf(_condition( m_cb_isEmptyFieldsEnabled->isSelected() ))
								.addItem(m_cb_isEmptyFields_GroupingEnabled = new Elements::Generic::Checkbox("Group by 8 bytes", true, m_eventUpdateCB))
							.end()
							.addItem(m_cb_isAlwaysOpen = new Elements::Generic::Checkbox("Open all", false, m_eventUpdateCB))
						.end()
						
						.newLine()
						.separator()
						.text("Base address")
						.addItem(m_classHierarchyEditorContainer = new Container)
						.newLine()
						.addItem(m_classEditorContainer = new ColContainer("Class editor panel"))
						.addItem(m_classFieldContainer = new ColContainer("Class field panel"))
					.end()
				.endReverseInserting();

			m_classEditorContainer->setDisplay(false);
			m_classFieldContainer->setDisplay(false);
		}

		~ClassEditor() {
			delete m_eventUpdateCB;
		}

		class ClassEditorPanel : public Container
		{
		public:
			ClassEditorPanel(ClassEditor* classEditor, API::Type::Class* Class)
				: m_classEditor(classEditor), m_class(Class)
			{
				(*this)
					.text("Selected class: " + Class->getClass()->getName());
			}
		private:
			API::Type::Class* m_class;
			ClassEditor* m_classEditor;
		};


		class ClassFieldPanel : public Container
		{
		public:
			ClassFieldPanel(ClassEditor* classEditor, API::Type::Class* Class, int relOffset)
				: m_classEditor(classEditor), m_class(Class), m_relOffset(relOffset)
			{
				m_field = getClass()->getField(m_relOffset).second;

				(*this)
					.addItem(m_nameInput = new Elements::Input::Text("Name: "))
					.text("Type: " + m_field->getType()->getDisplayName())
					.text("Relative offset: 0x" + Generic::String::NumberToHex(relOffset));

				m_nameInput->setInputValue(m_field->getName());
				(*this)
					.newLine()
					.addItem(
						new Elements::Button::ButtonStd("Change data type", new Events::EventUI(
							EVENT_LAMBDA(info) {
								if (m_dataTypeSelector == nullptr) {
									getWindow()->addWindow(
										m_dataTypeSelector = new Window::DataTypeSelector(m_class->getTypeManager())
									);
									m_dataTypeSelector->setType(m_field->getType());
									m_dataTypeSelector->getCloseEvent() +=
										new Events::EventUI(
											EVENT_LAMBDA(info) {
												m_typeInput = m_dataTypeSelector->getType();
												m_typeInput->setCanBeRemoved(false);
												m_dataTypeSelector = nullptr;
											}
										);
								}
							}
					)));

				(*this)
					.newLine()
					.newLine()
					.addItem(
						new Elements::Button::ButtonStd(isEmptyField() ? "Add" : "Change", new Events::EventUI(
							EVENT_LAMBDA(info) {
								change();
							}
						))
					);

				(*this)
					.sameLine()
					.addItem(
						new Elements::Button::ButtonStd("Remove", new Events::EventUI(
							EVENT_LAMBDA(info) {
								remove();
							}
						))
					);
			}

			void change() {
				if (m_nameInput->getInputValue().empty()) {
					throw Exception(m_nameInput, "Type a correct field name");
				}

				if (isEmptyField())
				{
					if (m_typeInput == nullptr) {
						throw Exception("Select a type!");
					}

					if (!getClass()->isEmptyField(m_relOffset, m_typeInput->getSize())) {
						throw Exception("Cannot insert the selected type to the class");
					}

					getClass()->addField(m_relOffset, m_nameInput->getInputValue(), m_typeInput);
				}
				else
				{
					if (m_typeInput != nullptr)
						m_field->setType(m_typeInput);
					m_field->setName(m_nameInput->getInputValue());
				}

				update();
			}

			void remove() {
				if (isEmptyField())
				{
					getClass()->removeField(m_relOffset);
				}
				update();
			}

			void update() {
				m_classEditor->update();
			}

			bool isEmptyField() {
				return getClass()->isDefaultField(m_field);
			}

			Type::Class* getClass() {
				return m_class->getClass();
			}
		private:
			API::Type::Class* m_class;
			int m_relOffset;
			ClassEditor* m_classEditor;
			Type::Class::Field* m_field;

			Elements::Input::Text* m_nameInput;
			Type::Type* m_typeInput = nullptr;
			Window::DataTypeSelector* m_dataTypeSelector = nullptr;
		};

		ClassHierarchy* m_classHierarchySelected = nullptr;
		void selectClassHierarchy(ClassHierarchy* classHierarchy) {
			m_classHierarchyEditorContainer->clear();
			m_classHierarchyEditorContainer->addItem(classHierarchy->m_addressInput);
			m_classHierarchySelected = classHierarchy;
		}

		ClassHierarchy::ClassContent* m_classContentSelected = nullptr;
		void selectClassContent(ClassHierarchy::ClassContent* classContent) {
			if (m_classContentSelected == classContent)
				return;

			m_classEditorContainer->setDisplay(true);
			m_classEditorContainer->setOpen(true);
			m_classEditorContainer->clear();
			m_classEditorContainer->addItem(new ClassEditorPanel(this, classContent->m_class));

			classContent->addFlags(ImGuiTreeNodeFlags_Selected, true);
			m_classContentSelected = classContent;
		}

		void unselectClassContent() {
			if (m_classContentSelected != nullptr) {
				m_classEditorContainer->setDisplay(false);
				m_classContentSelected->addFlags(ImGuiTreeNodeFlags_Selected, false);
				m_classContentSelected = nullptr;
			}
		}

		ClassHierarchy::ClassContent::EmptyField* m_classFieldSelected = nullptr;
		void selectClassField(ClassHierarchy::ClassContent::EmptyField* classField) {
			if (m_classFieldSelected == classField)
				return;
			
			if (m_classContentSelected != classField->m_classContent) {
				selectClassContent(classField->m_classContent);
			}

			m_classFieldContainer->setDisplay(true);
			m_classFieldContainer->setOpen(true);
			m_classFieldContainer->clear();
			m_classFieldContainer->addItem(new ClassFieldPanel(this, classField->m_classContent->m_class, classField->m_relOffset));

			classField->addFlags(ImGuiTreeNodeFlags_Selected, true);
			m_classFieldSelected = classField;
		}

		void unselectClassField() {
			if (m_classFieldSelected != nullptr) {
				m_classFieldContainer->setDisplay(false);
				m_classFieldSelected->addFlags(ImGuiTreeNodeFlags_Selected, false);
				m_classFieldSelected = nullptr;
			}
		}

		bool isFilterEnabled() {
			return m_cb_isFilterEnabled->isSelected();
		}

		bool isEmptyFieldsEnabled() {
			return m_cb_isEmptyFieldsEnabled->isSelected();
		}

		bool isEmptyFields_GroupingEnabled() {
			return m_cb_isEmptyFields_GroupingEnabled->isSelected();
		}

		bool isAlwaysOpen() {
			return m_cb_isAlwaysOpen->isSelected();
		}

		bool checkOnInputValue(Type::Class::Field& field, const std::string& value) {
			return Generic::String::ToLower(field.getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkOnInputValue(API::Function::Function* function, const std::string& value) {
			return Generic::String::ToLower(function->getMethod()->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		/*bool checkAllFilters(Type::Class::Field& field) {
			return getFilterManager()->check([&field](FilterManager::Filter* filter) {
				return static_cast<ClassFilter*>(filter)->checkFilter(function);
				});
		}*/
	private:
		Elements::Generic::Checkbox* m_cb_isFilterEnabled = nullptr;
		Elements::Generic::Checkbox* m_cb_isEmptyFieldsEnabled = nullptr;
		Elements::Generic::Checkbox* m_cb_isEmptyFields_GroupingEnabled = nullptr;
		Elements::Generic::Checkbox* m_cb_isAlwaysOpen = nullptr;
		Events::EventHandler* m_eventUpdateCB = nullptr;
	};
};



namespace GUI::Window
{
	class ClassEditor : public IWindow
	{
	public:
		ClassEditor(Widget::ClassEditor* classEditor, const std::string& name = "Class editor")
			: IWindow(name)
		{
			setWidth(400);
			setHeight(300);
			setMainContainer(classEditor);
		}

		~ClassEditor() {
		}
	};
};