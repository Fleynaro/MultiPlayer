#pragma once
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>
#include <FunctionTag/FunctionTag.h>
#include "Windows/ItemControlPanels/FunctionCP.h"
#include "Windows/ProjectWindow.h"

using namespace CE;

namespace GUI::Widget
{
	class ClassEditor : public Template::ItemList
	{
	public:
		class ClassView : public IView
		{
		public:
			class ClassContent : public ColContainer, public IView
			{
			public:
				class Field
					: public TreeNode
				{
				public:
					Field(ClassContent* classContent, int relOffset, Type::Class::Field& field)
						: m_classContent(classContent), m_relOffset(relOffset), m_field(field)
					{
						addFlags(ImGuiTreeNodeFlags_FramePadding | ImGuiTreeNodeFlags_Leaf);
						setName(field.getType()->getDisplayName() + " " + field.getName());
					}


				private:
					ClassContent* m_classContent;
					int m_relOffset;
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

				ClassContent(ClassView* classView, API::Type::Class* Class, void* baseAddr = nullptr)
					: ClassContent(classView, Class, baseAddr, Class->getClass()->getBaseOffset())
				{}

				ClassContent(ClassView* classView, API::Type::Class* Class, void* baseAddr, int baseOffset)
					: m_classView(classView), m_class(Class), m_baseAddr(baseAddr), m_baseOffset(baseOffset), ColContainer(Class->getClass()->getName())
				{
					setOutputContainer(this);
				}

				void buildFields(Container* container, const std::string& name) {
					for (auto& fieldPair : getClass()->getFieldDict()) {
						auto relOffset = fieldPair.first;
						auto& classField = fieldPair.second;
						
						Field* field;
						container->addItem(field = new Field(this, relOffset, classField));
						
						if (m_baseAddr != nullptr) {
							auto fieldType = classField.getType();
							auto baseType = fieldType->getBaseType();
							if (baseType->getGroup() == Type::Type::Group::Class) {
								auto apiBaseType = static_cast<API::Type::Class*>(m_class->getTypeManager()->getTypeById(baseType->getId()));
								if (apiBaseType != nullptr) {
									void* addr = getAddressByRelOffset(relOffset);

									if (fieldType->isArray()) {
										//поле ввода для целых чисел со стрелками + добавить новые
									}
									else {
										if (fieldType->isPointer()) {
											for (int i = 0; i < fieldType->getPointerLvl(); i++) {
												addr = (void*)*(std::uintptr_t*)addr;
											}
										}
										ClassContent* classContent;
										field->addItem(classContent = new ClassContent(m_classView, apiBaseType, addr));
										classContent->onSearch(name);
									}

									field->addFlags(ImGuiTreeNodeFlags_Leaf, false);
								}
							}
						}
					}
				}

				void buildMethods(Container* container, const std::string& methodName) {
					for (auto method : getClass()->getMethodList()) {
						auto method_ = m_class->getTypeManager()->getProgramModule()->getFunctionManager()->getFunctionById(method->getId());
						if (!m_classView->isFilterEnabled() || m_classView->m_classEditor->checkOnInputValue(method_, methodName)) {
							container->addItem(new Method(method_));
						}
					}
				}

				void onSearch(const std::string& name) override
				{
					getOutContainer()->clear();

					buildFields(getOutContainer(), name);

					ColContainer* methodContainer;
					getOutContainer()->addItem(
						methodContainer = new ColContainer("Methods"));
					buildMethods(methodContainer, name);
				}

				void* getAddressByRelOffset(int relOffset) {
					return (void*)((std::uintptr_t)m_baseAddr + m_baseOffset + relOffset);
				}

				Type::Class* getClass() {
					return m_class->getClass();
				}
			private:
				ClassView* m_classView;
				void* m_baseAddr;
				int m_baseOffset;
				API::Type::Class* m_class;
			};
			friend class ClassContent;


			ClassView(ClassEditor* classEditor, API::Type::Class* Class, void* baseAddr = nullptr)
				: m_classEditor(classEditor), m_class(Class), m_baseAddr(baseAddr)
			{}

			~ClassView() {
				delete m_eventUpdateCB;
			}

			//MY TODO*: несколько классов могут фильтроваться одной панелью
			void onSetView() override {
				m_class->getClass()->iterateClasses([&](Type::Class* class_) {
					auto baseClass = static_cast<API::Type::Class*>(m_class->getTypeManager()->getTypeById(class_->getId()));
					if (baseClass != nullptr) {
						ClassContent* classContent = new ClassContent(this, baseClass, m_baseAddr);
						getOutContainer()->addItem(classContent);
						m_classContents.push_back(classContent);
					}
					return true;
				});

				m_eventUpdateCB = new Events::EventUI(EVENT_LAMBDA(info) {
					m_classEditor->update();
				});
				m_eventUpdateCB->setCanBeRemoved(false);

				(*m_classEditor->m_underFilterCP)
					.beginReverseInserting()
						.beginContainer()
						.newLine()
						.separator()
							.addItem(m_cb_isFilterEnabled = new Elements::Generic::Checkbox("Use filters and search", false, m_eventUpdateCB))
						.end()
					.endReverseInserting();
			}

			void onSearch(const std::string& name) override
			{
				for (auto it : m_classContents) {
					it->onSearch(name);
				}
			}
		private:
			bool isFilterEnabled() {
				return m_cb_isFilterEnabled->isSelected();
			}
		private:
			void* m_baseAddr;
			API::Type::Class* m_class;
			ClassEditor* m_classEditor;
			std::list<ClassContent*> m_classContents;

			Elements::Generic::Checkbox* m_cb_isFilterEnabled = nullptr;
			Events::EventHandler* m_eventUpdateCB = nullptr;
		};
		friend class ClassView;


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

		ClassEditor()
			: ItemList(new ClassFilterCreator(this))
		{
			//getFilterManager()->addFilter(new CategoryFilter(this));
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

		void setOpenFunctionEventHandler(Events::Event* eventHandler) {
			m_openFunction = eventHandler;
		}
	public:
		Events::Event* m_openFunction;
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