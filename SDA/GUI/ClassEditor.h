#pragma once
#include "Windows/ItemLists/DataTypeList.h"
#include "GUI/Signature.h"
#include "AddressInput.h"

using namespace CE;

namespace GUI::Widget
{
	//MY TODO: ���� �� ����� ����������� ���� � �����
	//MY TODO: ����� ������(������� ����. ����)
	//MY TODO: vtable
	//MY TODO: stack overflow
	//MY TODO: �������������� ������
	//MY TODO: �������������� ���� ������(���������, float)
	//MY TODO: ��������� �������, ������ ������ ��� �����. ������, �������� � ��� ��������, ���. � ���. ������� ������
	//MY TODO: ������������� ��������� �����, ���������� ���� ��������(��� � �����!)
	//MY TODO: ��������� ������� ����� ������������� ����� �������
	//MY TODO: getWindow()->showConfirm(), showError(), showWarning(), ....
	//MY TODO: ���� ������ ������� �� �������, �� ������� ������������ ��������
	//MY TODO: emptyFields ��� ��������� �������
	//MY TODO: fast ������ � ������ ��� �������� ���������� �����
	//MY TODO: ����� - ��� ����������� ����, ��� ������������ ��������� ���� �� ������: + �������� �� ������ ��������, ��������� ���� � �.�
	
	//MY TODO: ���� ��������� � ����������� �������: ������� - show known functions(+ ���-�� � ���� ������)
	//MY TODO: ������� ������ ������ ����������� ��������������� � ������ => �������������� ������� ��������� ������ ����� �������

	class ClassEditor : public Template::ItemList
	{
	public:
		class ClassHierarchy : public GUI::Container
		{
		public:
			class ClassContent : public TreeNode
			{
			public:
				class Byte : public CE::Type::Byte
				{
				public:
					Byte(int maxBytesCount)
						: m_maxBytesCount(maxBytesCount)
					{}

					std::string getViewValue(void* addr) override {
						return
							/*Generic::String::NumberToHex(*(uint64_t*)addr) + " | " +*/
							std::to_string(*(int*)addr) + "i | " +
							std::to_string(*(float*)addr) + "f | " +
							std::to_string(*(double*)addr).substr(0, 15) + "d";
					}
				protected:
					int m_maxBytesCount;
				};

				class ByteGroup : public CE::Type::Array
				{
				public:
					ByteGroup(int bytesCount)
						: CE::Type::Array(new Byte(bytesCount), bytesCount)
					{}

					std::string getViewValue(void* addr) override {
						return getType()->getViewValue(addr);
					}
				};

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

				class EmptyField
					: public TreeNode
				{
				public:
					EmptyField(ClassContent* classContent, int relOffset, CE::Type::Type* type)
						: m_classContent(classContent), m_relOffset(relOffset), m_type(type)
					{
						addFlags(ImGuiTreeNodeFlags_FramePadding);

						m_eventClick = new Events::EventUI(EVENT_LAMBDA(info) {
							m_classContent->m_classHierarchy->m_classEditor->selectClassFields(this, Keys::IsShiftPressed(), Keys::IsCtrlPressed());
						});
						m_eventClick->setCanBeRemoved(false);

						getLeftMouseClickEvent() += m_eventClick;
						m_type->addOwner();
					}

					~EmptyField() {
						if (m_headBaseInfo != nullptr)
							m_headBaseInfo->destroy();
						
						m_type->free();

						if(m_classContent->m_classHierarchy->m_classEditor->m_classFieldSelected == this)
							m_classContent->m_classHierarchy->m_classEditor->unselectClassField(this);

						delete m_eventClick;
					}

					void renderHeader() override {
						if (m_headBaseInfo == nullptr) {
							std::string offsetText;
							if (m_classContent->m_classHierarchy->m_classEditor->isHexDisplayEnabled())
								offsetText = "0x" + Generic::String::NumberToHex(getAbsoluteOffset());
							else offsetText = std::to_string(getAbsoluteOffset());

							m_headBaseInfo = new Container;
							(*m_headBaseInfo)
								.text(offsetText + " ", ColorRGBA(0xfaf4b6FF))
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

					virtual std::string getFieldName() {
						return "<empty>";
					}

					ClassContent* m_classContent;
					int m_relOffset;
					CE::Type::Type* m_type;
				protected:
					Container* m_headBaseInfo = nullptr;
					Events::EventHandler* m_eventClick;
				};
				friend class EmptyField;

				class Field
					: public EmptyField
				{
				public:
					Field(ClassContent* classContent, int relOffset, Type::Class::Field* field)
						: EmptyField(classContent, relOffset, field->getType()), m_field(field)
					{}

					std::string getFieldName() override {
						return m_field->getName();
					}
				private:
					Type::Class::Field* m_field;
				};

				class ArrayItem
					: public TreeNode
				{
				public:
					ArrayItem(Field* field, int index)
						: m_arrayField(field), m_index(index)
					{
						addFlags(ImGuiTreeNodeFlags_FramePadding);
					}

					~ArrayItem() {
						if (m_headBaseInfo != nullptr)
							m_headBaseInfo->destroy();
					}

					void renderHeader() override {
						if (m_headBaseInfo == nullptr) {
							std::string offsetText;
							if (m_arrayField->m_classContent->m_classHierarchy->m_classEditor->isHexDisplayEnabled())
								offsetText = "0x" + Generic::String::NumberToHex(getAbsoluteOffset());
							else offsetText = std::to_string(getAbsoluteOffset());

							m_headBaseInfo = new Container;
							(*m_headBaseInfo)
								.text(offsetText + " ", ColorRGBA(0xfaf4b6FF))
								.sameLine()
								.sameText(" [" + std::to_string(m_index) + "] ");
							if (m_arrayField->m_classContent->m_baseAddr != nullptr) {
								(*m_headBaseInfo)
									.sameLine()
									.addItem(new TypeViewValue(m_arrayField->m_type, m_arrayField->m_classContent->getAddressByRelOffset(getRelOffset()), ColorRGBA(0x919191FF)));
							}

							m_headBaseInfo->setParent(this);
						}

						ImGui::SameLine();
						m_headBaseInfo->show();
					}

					int getOffset() {
						return m_index * m_arrayField->m_type->getSize();
					}

					int getRelOffset() {
						return m_arrayField->m_relOffset + getOffset();
					}

					int getAbsoluteOffset() {
						return m_arrayField->getAbsoluteOffset() + getOffset();
					}
				private:
					Container* m_headBaseInfo = nullptr;
					Field* m_arrayField;
					int m_index;
				};

				class ArrayClassViewer
					: public Container
				{
				public:
					ArrayClassViewer(API::Type::Class* Class, void* baseAddr)
						: m_baseAddr(baseAddr), m_class(Class)
					{
						(*this)
							.text("Item index: ").sameLine().addItem(m_indexInput = new Elements::Input::Int);

						
					}

					~ArrayClassViewer() {
						
					}

					ClassHierarchy* createClassHierarchy() {
						return new ClassHierarchy(
							m_arrayField->m_classContent->m_classHierarchy->m_classEditor,
							m_class,
							m_arrayField->m_classContent->getAddressByRelOffset(getRelOffset()),
							true);
					}

					int getIndex() {
						return m_indexInput->getInputValue();
					}

					void* getAddress() {
						return (void*)((std::uintptr_t)m_baseAddr + getIndex() * m_class->getType()->getSize());
					}
				private:
					void* m_baseAddr;
					ClassHierarchy* m_classHierarchy;
					Elements::Input::Int* m_indexInput;
					API::Type::Class* m_class;
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
				CE::Type::Type* predictTypeAtAddress(void* addr, int maxSize = 8, int level = 1) {
					auto alignment = (char)addr % 8;

					if (alignment != 0 && alignment <= maxSize || maxSize >= 8) {
						switch (alignment)
						{
							case 0: {
								if (level <= 3) {
									void* ptr = (void*)*(std::uintptr_t*)addr;
									if (Pointer(ptr).canBeRead()) {
										return new CE::Type::Pointer(predictTypeAtAddress(ptr, 8, level + 1));
									}
									break;
								}
							}
						}
					}

					if (level == 1 && alignment == 0 && maxSize >= 8) {
						if (m_classHierarchy->m_classEditor->isEmptyFields_GroupingEnabled()) {
							return new ByteGroup(8);
						}
					}

					return new Byte(maxSize);
				}

				void buildFields(Container* container, const std::string& name) {
					getClass()->iterateFields([&](int& relOffset, Type::Class::Field* classField)
					{
						void* fieldAddr = getAddressByRelOffset(relOffset);

						EmptyField* field;
						if (getClass()->isDefaultField(classField)) {
							auto type = predictTypeAtAddress(fieldAddr, getClass()->getNextEmptyBytesCount(relOffset));
							container->addItem(field = new EmptyField(this, relOffset, type));
							relOffset += type->getSize() - 1;
						}
						else {
							container->addItem(field = new Field(this, relOffset, classField));
						}
						field->addFlags(ImGuiTreeNodeFlags_Leaf, true);
						m_fields.push_back(field);

						bool canBeFilteredToRemove = true;
						if (m_baseAddr != nullptr) {
							auto fieldType = classField->getType();
							auto baseType = fieldType->getBaseType();

							if (baseType->getGroup() == Type::Type::Group::Class)
							{
								auto apiBaseClassType = static_cast<API::Type::Class*>(m_class->getTypeManager()->getTypeById(baseType->getId()));
								if (apiBaseClassType != nullptr && !m_classHierarchy->hasClass(apiBaseClassType)) {
									if (fieldType->isArray()) {
										//���� ����� ��� ����� ����� �� ��������� + �������� �����
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
											classHierarchy->setParentClassHierarchy(m_classHierarchy);
											classHierarchy->onSearch(name);
											m_classHierarchies.insert(classHierarchy);
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
							} else if (fieldType->isArray()) {
								buildArrayItems(static_cast<Field*>(field));
								field->addFlags(ImGuiTreeNodeFlags_Leaf, false);
							}
						}

						if (canBeFilteredToRemove) {
							if (m_classHierarchy->m_classEditor->isFilterEnabled() && !m_classHierarchy->m_classEditor->checkOnInputValue(*classField, name)) {
								container->removeLastItem();
								m_fields.pop_back();
							}
						}

						return true;
					}, m_classHierarchy->m_classEditor->isEmptyFieldsEnabled());
				}

				void buildArrayItems(Field* field, int maxItems = 20)
				{
					auto arrayType = static_cast<CE::Type::Array*>(field->m_type);
					int arrItemsCount = arrayType->getArraySize();
					for (int i = 0; i < min(maxItems, arrItemsCount); i++) {
						field->addItem(new ArrayItem(field, i));
					}
					if (arrItemsCount > 20) {
						field->addItem(
							new Elements::Button::ButtonStd(
								"Load all items",
								new Events::EventHook(new Events::EventUI(EVENT_LAMBDA(info) {
									auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
									buildArrayItems((Field*)message->getUserDataPtr(), 200);
								}), field)
							)
						);
					}
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
					m_fields.clear();
					
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
				std::list<EmptyField*> m_fields;
				std::set<ClassHierarchy*> m_classHierarchies;
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

			ClassContent::EmptyField* getFieldLocationBy(CE::Type::Class* Class, int relOffset) {
				for (auto it : m_classContents) {
					if (it->getClass() == Class) {
						for (auto field : it->m_fields) {
							if (field->m_relOffset == relOffset) {
								return field;
							}
						}
					}

					for (auto hierarchy : it->m_classHierarchies) {
						auto result = hierarchy->getFieldLocationBy(Class, relOffset);
						if (result != nullptr) {
							return result;
						}
					}
				}
				return nullptr;
			}

			void setParentClassHierarchy(ClassHierarchy* classHierarchy) {
				m_parentClassHierarchy = classHierarchy;
			}

			bool hasClass(API::Type::Class* Class) {
				if (m_targetClass == Class)
					return true;
				if(m_parentClassHierarchy != nullptr)
					return m_parentClassHierarchy->hasClass(Class);
				return false;
			}

			AddressInput* m_addressInput = nullptr;
		private:
			API::Type::Class* m_targetClass;
			ClassEditor* m_classEditor;
			std::list<ClassContent*> m_classContents;
			void* m_baseAddr = nullptr;
			ClassHierarchy* m_parentClassHierarchy = nullptr;
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
							.addItem(m_cb_isHexDisplayEnabled = new Elements::Generic::Checkbox("Hex display", true, m_eventUpdateCB))
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
					.text("Name: ").sameLine().addItem(m_nameInput = new Elements::Input::Text)
					.text("Size: ").sameLine().addItem(m_relSizeInput = new Elements::Input::Int)
					.newLine()
					.addItem(
						new Elements::Button::ButtonStd("Change", new Events::EventUI(
							EVENT_LAMBDA(info) {
								change();
								update();
							}
						))
					);

				m_nameInput->setInputValue(getClass()->getName());
				m_relSizeInput->setInputValue(getClass()->getRelSize());
			}

			void change() {
				if (m_nameInput->getInputValue().empty()) {
					throw Exception(m_nameInput, "Type a correct class name");
				}

				if (m_relSizeInput->getInputValue() <= 0) {
					throw Exception(m_relSizeInput, "Type a correct relation size of the class");
				}

				if (m_relSizeInput->getInputValue() < getClass()->getSizeByLastField()) {
					throw Exception(m_relSizeInput, "Some fields go out of the size. Remove/relocate them.");
				}

				getClass()->setName(m_nameInput->getInputValue());
				getClass()->resize(m_relSizeInput->getInputValue());

			}

			void update() {
				m_classEditor->update();
			}

			Type::Class* getClass() {
				return m_class->getClass();
			}
		private:
			API::Type::Class* m_class;
			ClassEditor* m_classEditor;
			Elements::Input::Text* m_nameInput;
			Elements::Input::Int* m_relSizeInput;
		};


		class ClassFieldPanel : public Container
		{
		public:
			ClassFieldPanel(ClassEditor* classEditor, API::Type::Class* Class, int relOffset)
				: m_classEditor(classEditor), m_class(Class), m_relOffset(relOffset)
			{
				m_field = getClass()->getField(m_relOffset).second;
				m_typeInput = m_field->getType();

				(*this)
					.text("Name: ").sameLine().addItem(m_nameInput = new Elements::Input::Text)
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
									m_dataTypeSelector->setType(m_typeInput);
									m_dataTypeSelector->getCloseEvent() +=
										new Events::EventUI(
											EVENT_LAMBDA(info) {
												if(m_dataTypeSelector->getType() != nullptr) {
													m_typeInput = m_dataTypeSelector->getType();
													m_typeInput->addOwner();
												}
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
								update();
							}
						))
					);

				if (!isEmptyField())
				{
					(*this)
						.sameLine()
						.addItem(
							new Elements::Button::ButtonStd("Remove", new Events::EventUI(
								EVENT_LAMBDA(info) {
									remove();
									update();
								}
							))
						)
						.sameLine()
						.addItem(
							new Elements::Button::ButtonArrow(ImGuiDir_Down, new Events::EventUI(
								EVENT_LAMBDA(info) {
									if(move(1))
										update();
								}
							))
						)
						.sameLine()
						.addItem(
							new Elements::Button::ButtonArrow(ImGuiDir_Up, new Events::EventUI(
								EVENT_LAMBDA(info) {
									if (move(-1))
										update();
								}
							))
						)
						.sameLine()
						.addItem(m_cb_isMoveFieldOnlyEnabled = new Elements::Generic::Checkbox("Move field only", true));
						m_cb_isMoveFieldOnlyEnabled->setToolTip(true);
				}
			}

			void change() {
				if (m_nameInput->getInputValue().empty()) {
					throw Exception(m_nameInput, "Type a correct field name");
				}

				if (isEmptyField())
				{
					if (!getClass()->areEmptyFields(m_relOffset, m_typeInput->getSize())) {
						throw Exception("Cannot insert the selected type to the class");
					}

					getClass()->addField(m_relOffset, m_nameInput->getInputValue(), m_typeInput);
				}
				else
				{
					remove();
					change();
				}
			}

			void remove() {
				getClass()->removeField(m_relOffset);
				m_field = getClass()->getDefaultField();
			}

			bool move(int direction) {
				auto bytesCount = m_typeInput->getSize() * direction;
				bool result;

				if (m_cb_isMoveFieldOnlyEnabled->isSelected()) {
					result = getClass()->moveField(m_relOffset, bytesCount);
				}
				else {
					result = getClass()->moveFields(m_relOffset, bytesCount);
				}

				if(result)
					m_relOffset += bytesCount;
				return result;
			}

			void update() {
				m_classEditor->update();
				auto fieldLocation = m_classEditor->m_classHierarchySelected->getFieldLocationBy(getClass(), m_relOffset);
				if (fieldLocation != nullptr) {
					m_classEditor->selectClassFields(fieldLocation);
				}
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
			Elements::Generic::Checkbox* m_cb_isMoveFieldOnlyEnabled = nullptr;
			Type::Type* m_typeInput;
			Window::DataTypeSelector* m_dataTypeSelector = nullptr;
		};

		class ClassFieldsPanel : public Container
		{
		public:
			ClassFieldsPanel(ClassEditor* classEditor, std::list<std::pair<API::Type::Class*, int>> fields)
				: m_classEditor(classEditor), m_fields(fields)
			{
				(*this)
					.text("Selected "+ std::to_string(m_fields.size()) +" fields.")
					.newLine()
					.addItem(
						new Elements::Button::ButtonStd("Clear", new Events::EventUI(
							EVENT_LAMBDA(info) {
								clearFields();
							}
						))
					);
			}

			void clearFields() {
				for (auto it : m_fields) {
					auto Class = it.first->getClass();
					auto field = Class->getField(it.second);
					if (!Class->isDefaultField(field.second)) {
						Class->removeField(field.first);
					}
				}
				update();
			}

			void update() {
				m_classEditor->update();
			}
		private:
			ClassEditor* m_classEditor;
			std::list<std::pair<API::Type::Class*, int>> m_fields;
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
		std::set<ClassHierarchy::ClassContent::EmptyField*> m_classFieldsSelected;

		void selectClassFields(ClassHierarchy::ClassContent::EmptyField* classField, bool shiftPressed = false, bool ctrlPressed = false) {
			if (m_classFieldSelected == nullptr || (!shiftPressed && !ctrlPressed)) {
				unselectClassFields();
				selectClassField(classField);

				if (m_classContentSelected != classField->m_classContent) {
					selectClassContent(classField->m_classContent);
				}

				m_classFieldContainer->setDisplay(true);
				m_classFieldContainer->setOpen(true);
				m_classFieldContainer->clear();
				m_classFieldContainer->addItem(new ClassFieldPanel(this, classField->m_classContent->m_class, classField->m_relOffset));
			}
			else {
				if (shiftPressed) {
					auto classContent = classField->m_classContent;
					if (m_classFieldSelected->m_classContent == classField->m_classContent)
					{
						auto firstField = m_classFieldSelected;
						auto lastField = classField;
						if (classField->m_relOffset < m_classFieldSelected->m_relOffset)
							std::swap(firstField, lastField);

						bool select = false;
						for (auto it = classContent->m_fields.begin(); it != classContent->m_fields.end(); it ++) {
							if (*it == firstField)
								select = true;

							if (select) {
								if (isClassFieldSelected(*it) && *it != firstField && *it != lastField)
									unselectClassField(*it);
								else selectClassField(*it);
							}

							if (*it == lastField)
								select = false;
						}
					}
				}
				else if (ctrlPressed) {
					if (isClassFieldSelected(classField))
						unselectClassField(classField);
					else selectClassField(classField);
				}

				if (m_classFieldsSelected.size() == 1) {
					selectClassFields(*m_classFieldsSelected.begin(), false, false);
					return;
				}

				m_classFieldContainer->clear();
				std::list<std::pair<API::Type::Class*, int>> fields;
				for (auto it : m_classFieldsSelected) {
					fields.push_back(std::make_pair(it->m_classContent->m_class, it->m_relOffset));
				}
				m_classFieldContainer->addItem(new ClassFieldsPanel(this, fields));
			}

			m_classFieldSelected = classField;
		}

		bool isClassFieldSelected(ClassHierarchy::ClassContent::EmptyField* classField) {
			return m_classFieldsSelected.find(classField) != m_classFieldsSelected.end();
		}

		void selectClassField(ClassHierarchy::ClassContent::EmptyField* classField) {
			m_classFieldsSelected.insert(classField);
			classField->addFlags(ImGuiTreeNodeFlags_Selected, true);
		}

		void unselectClassField(ClassHierarchy::ClassContent::EmptyField* classField) {
			m_classFieldsSelected.erase(classField);
			classField->addFlags(ImGuiTreeNodeFlags_Selected, false);
			if (m_classFieldsSelected.size() == 0) {
				unselectClassFields();
			}
		}

		void unselectClassFields() {
			m_classFieldContainer->setDisplay(false);
			for (auto field : m_classFieldsSelected) {
				field->addFlags(ImGuiTreeNodeFlags_Selected, false);
			}
			m_classFieldsSelected.clear();
			m_classFieldSelected = nullptr;
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

		bool isHexDisplayEnabled() {
			return m_cb_isHexDisplayEnabled->isSelected();
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
		Elements::Generic::Checkbox* m_cb_isHexDisplayEnabled = nullptr;
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
			setWidth(700);
			setHeight(700);
			setMainContainer(classEditor);
		}

		~ClassEditor() {
		}
	};
};