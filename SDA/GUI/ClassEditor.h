#pragma once
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>
#include <FunctionTag/FunctionTag.h>
#include "Windows/ItemControlPanels/FunctionCP.h"
#include "Windows/ProjectWindow.h"
#include <Pointer/Pointer.h>

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
			class ClassContent : public ColContainer
			{
			public:
				class Field
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

					Field(ClassContent* classContent, int relOffset, Type::Class::Field& field)
						: m_classContent(classContent), m_relOffset(relOffset), m_field(field)
					{
						addFlags(ImGuiTreeNodeFlags_FramePadding);
					}

					~Field() {
						if (m_headBaseInfo != nullptr)
							m_headBaseInfo->destroy();
					}

					void renderHeader() override {
						if (m_headBaseInfo == nullptr) {
							m_headBaseInfo = new Container;
							(*m_headBaseInfo)
								.text("0x" + Generic::String::NumberToHex(getAbsoluteOffset()) + " ", ColorRGBA(0xfaf4b6FF))
								.sameLine()
								.addItem(new Units::Type(m_field.getType()))
								.sameText(" " + m_field.getName() + " ")
								.sameLine();
							if (m_classContent->m_baseAddr != nullptr) {
								m_headBaseInfo
									->addItem(new TypeViewValue(m_field.getType(), m_classContent->getAddressByRelOffset(m_relOffset), ColorRGBA(0x919191FF)))
									.sameLine();
							}

							m_headBaseInfo->setParent(this);
						}

						ImGui::SameLine();
						m_headBaseInfo->show();
					}

					int getAbsoluteOffset() {
						return m_classContent->m_baseOffset + m_relOffset;
					}
				private:
					ClassContent* m_classContent;
					int m_relOffset;
					Type::Class::Field& m_field;
					Container* m_headBaseInfo = nullptr;
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

				ClassContent(ClassHierarchy* classHierarchy, API::Type::Class* Class, bool calculateValues = false, void* baseAddr = nullptr)
					: ClassContent(classHierarchy, Class, calculateValues, baseAddr, Class->getClass()->getBaseOffset())
				{}

				ClassContent(ClassHierarchy* classHierarchy, API::Type::Class* Class, bool calculateValues, void* baseAddr, int baseOffset)
					: m_classHierarchy(classHierarchy), m_class(Class), m_baseAddr(baseAddr), m_calculateValues(calculateValues), m_baseOffset(baseOffset)
				{}

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
							m_classHierarchy->m_classEditor->selectClassContent(this);
						});
						m_className->setParent(this);
					}

					m_className->show();
				}

				void buildFields(Container* container, const std::string& name) {
					for (auto& fieldPair : getClass()->getFieldDict()) {
						auto relOffset = fieldPair.first;
						auto& classField = fieldPair.second;

						Field* field;
						container->addItem(field = new Field(this, relOffset, classField));
						field->addFlags(ImGuiTreeNodeFlags_Leaf, true);

						bool canBeFilteredToRemove = true;
						if (m_baseAddr != nullptr) {
							auto fieldType = classField.getType();
							auto baseType = fieldType->getBaseType();
							if (baseType->getGroup() == Type::Type::Group::Class) {
								auto apiBaseClassType = static_cast<API::Type::Class*>(m_class->getTypeManager()->getTypeById(baseType->getId()));
								if (apiBaseClassType != nullptr) {
									void* addr = getAddressByRelOffset(relOffset);

									if (fieldType->isArray()) {
										//поле ввода дл€ целых чисел со стрелками + добавить новые
									}
									else {
										if (fieldType->isPointer()) {
											for (int i = 0; i < fieldType->getPointerLvl(); i++) {
												if (!Pointer(addr).canBeRead())
													break;
												addr = (void*)*(std::uintptr_t*)addr;
											}
										}

										if (Pointer(addr).canBeRead()) {
											ClassHierarchy* classHierarchy;
											field->addItem(classHierarchy = new ClassHierarchy(m_classHierarchy->m_classEditor, apiBaseClassType, addr));
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
							if (m_classHierarchy->m_classEditor->isFilterEnabled() && !m_classHierarchy->m_classEditor->checkOnInputValue(classField, name)) {
								container->removeLastItem();
							}
						}
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

					buildFields(this, name);

					ColContainer* methodContainer;
					addItem(methodContainer = new ColContainer("Methods"));
					buildMethods(methodContainer, name);
				}

				void* getAddressByRelOffset(int relOffset) {
					return (void*)((std::uintptr_t)m_baseAddr + m_baseOffset + relOffset);
				}

				Type::Class* getClass() {
					return m_class->getClass();
				}

				API::Type::Class* m_class;
			private:
				ClassHierarchy* m_classHierarchy;
				void* m_baseAddr;
				int m_baseOffset;
				bool m_calculateValues;
			};
			friend class ClassContent;

			ClassHierarchy(ClassEditor* classEditor, API::Type::Class* targetClass, void* baseAddr = nullptr)
				: m_classEditor(classEditor), m_targetClass(targetClass), m_baseAddr(baseAddr)
			{
				m_targetClass->getClass()->iterateClasses([&](Type::Class* class_) {
					auto apiClassType = static_cast<API::Type::Class*>(m_targetClass->getTypeManager()->getTypeById(class_->getId()));
					if (apiClassType != nullptr) {
						ClassContent* classContent = new ClassContent(this, apiClassType, m_baseAddr != nullptr, m_baseAddr);
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
			}

			void onSearch(const std::string& name)
			{
				for (auto it : m_classContents) {
					it->onSearch(name);
				}
			}
		private:
			void* m_baseAddr;
			API::Type::Class* m_targetClass;
			ClassEditor* m_classEditor;
			std::list<ClassContent*> m_classContents;
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

		Container* m_classEditorContainer;

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
							.addItem(m_cb_isAlwaysOpen = new Elements::Generic::Checkbox("Open all", false, m_eventUpdateCB))
						.end()
						
						.newLine()
						.separator()
						.addItem(new AddressInput)
						.addItem(m_classEditorContainer = new ColContainer("Class editor panel"))
					.end()
				.endReverseInserting();
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

		ClassHierarchy::ClassContent* m_classContentSelected = nullptr;
		void selectClassContent(ClassHierarchy::ClassContent* classContent) {
			unselectClassContent();

			m_classEditorContainer->clear();
			m_classEditorContainer->addItem(new ClassEditorPanel(this, classContent->m_class));

			classContent->addFlags(ImGuiTreeNodeFlags_Selected, true);
			m_classContentSelected = classContent;
		}

		void unselectClassContent() {
			if (m_classContentSelected != nullptr) {
				m_classContentSelected->addFlags(ImGuiTreeNodeFlags_Selected, false);
				m_classContentSelected = nullptr;
			}
		}

		bool isFilterEnabled() {
			return m_cb_isFilterEnabled->isSelected();
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
			//MY TODO*: error
			m_openFunctionCP = new Events::EventUI(EVENT_LAMBDA(info) {
				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
				auto function = (API::Function::Function*)message->getUserDataPtr();

				getParent()->getMainContainer().clear();
				getParent()->getMainContainer().addItem(new Widget::FunctionCP(function));
			});
			m_openFunctionCP->setCanBeRemoved(false);

			//classEditor->setOpenFunctionEventHandler(m_openFunctionCP);
			setMainContainer(classEditor);
		}

		~ClassEditor() {
			delete m_openFunctionCP;
		}
	private:
		Events::EventHandler* m_openFunctionCP;
	};
};