#pragma once
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>
#include <FunctionTag/FunctionTag.h>
#include "../ItemControlPanels/FunctionCP.h"
#include "../ProjectWindow.h"

using namespace CE;

namespace GUI::Widget
{
	class FunctionTagCreator
		: public Container
	{
	public:

		FunctionTagCreator()
		{}
	};

	class FunctionTagShortCut
		: public Container
	{
	public:

		FunctionTagShortCut()
		{}
	};

	class FunctionTagList : public Template::ItemList
	{
	public:
		class TreeView : public IView
		{
		public:
			class FunctionTag : public TreeNode
			{
			public:
				FunctionTag(API::Function::Function* function, int depth, Events::EventHandler* openFunctionCP)
					: m_function(function), m_openFunctionCP(openFunctionCP)
				{}

				~FunctionTag() {
					if (m_signature != nullptr) {
						delete m_signature;
					}
				}

				void onVisibleUpdate() override {}
				
				void renderHeader() override {
					if (m_signature == nullptr) {
						m_signature = new Units::FunctionSignature(m_function,
							new Events::EventUI(EVENT_LAMBDA(info) {}),
							new Events::EventHook(m_openFunctionCP, m_function)
						);
					}

					ImGui::SameLine();
					m_signature->show();
				}

				CallGraph::Unit::FunctionBody* getBody() {
					return m_function->getBody();
				}

				bool m_isContentLoaded = false;
			private:
				API::Function::Function* m_function;
				Units::FunctionSignature* m_signature = nullptr;
				Events::EventHandler* m_openFunctionCP;
			};
			
			TreeView(FunctionList* funcList, API::Function::Function* function)
				: m_funcList(funcList), m_function(function)
			{
				m_eventUpdateCB = new Events::EventUI(EVENT_LAMBDA(info) {
					m_funcList->update();
				});
				m_eventUpdateCB->setCanBeRemoved(false);

				m_eventVisibleFuncBody = new Events::EventUI(EVENT_LAMBDA(info) {
					auto message = std::dynamic_pointer_cast<Events::EventMessage>(info);
					if (message->getValue<Events::VisibleType>() != Events::VisibleOn)
						return;
					auto sender = static_cast<FunctionBody*>(message->getSender());
					if (!sender->m_isContentLoaded) {
						bool isRemove;
						load(sender, sender->m_depth, isRemove, "");
					}
				});
				m_eventVisibleFuncBody->setCanBeRemoved(false);

				(*m_funcList->m_underFilterCP)
					.beginReverseInserting()
						.beginContainer()
							.newLine()
							.separator()
							.addItem(m_cb_isFilterEnabled = new Elements::Generic::Checkbox("Use filters and search", false, m_eventUpdateCB))
							.addItem(m_cb_isAlwaysOpen = new Elements::Generic::Checkbox("Open all", true, m_eventUpdateCB))
							.addItem(m_cb_isGlobalVarNode = new Elements::Generic::Checkbox("Global variables", true, m_eventUpdateCB))
							.addItem(m_cb_isVMethodNode = new Elements::Generic::Checkbox("Virtual methods", true, m_eventUpdateCB))
							.addItem(m_cb_isNotCalculatedFunc = new Elements::Generic::Checkbox("Not calculated functions", true, m_eventUpdateCB))
							.addItem(m_cb_isCalculatedFunc = new Elements::Generic::Checkbox("Calculated functions", true, m_eventUpdateCB))
						.end()
					.endReverseInserting();
			}

			~TreeView() {
				delete m_eventUpdateCB;
				delete m_eventVisibleFuncBody;
			}

			//MY TODO*: stack overflow; add check
			void load(FunctionBody* funcBody, int depth, bool& remove, const std::string& funcName) {
				if (isAlwaysOpen() || depth == 1)
					funcBody->setOpen(true);

				int nextDepth = depth + 1;
				remove = true;

				for (auto node : funcBody->getBody()->getNodeList()) {
					if (node->isFunction()) {
						auto funcNode = static_cast<CallGraph::Unit::FunctionNode*>(node);
						if (!funcNode->isNotCalculated()) {
							if (isCalculatedFunc()) {
								FunctionBody* body;
								funcBody->addItem(body = new FunctionBody(funcNode->getFunction(), nextDepth, m_funcList->m_openFunction));
								if (isAlwaysOpen() || depth == 1) {
									bool isRemove;
									load(body, nextDepth, isRemove, funcName);

									if (isFilterEnabled()) {
										if (body->empty()) {
											if (m_funcList->checkOnInputValue(funcNode->getFunction(), funcName)
												&& m_funcList->checkAllFilters(funcNode->getFunction())) {
												remove = false;
												isRemove = false;
											}
										}

										if (isRemove) {
											funcBody->removeLastItem();
										}
									}
								}
								else {
									funcBody->setVisibleEvent(m_eventVisibleFuncBody);
								}
							}
						}
						else if (isNotCalculatedFunc()) {
							funcBody->addItem(new FunctionNode(funcNode, nextDepth));
						}
					}
					else if (node->isVMethod() && isVMethodNode()) {
						auto vMethod = static_cast<CallGraph::Unit::VMethodNode*>(node);
						funcBody->addItem(new VMethodNode(vMethod, nextDepth));
					}
					else if (node->isGlobalVar() && isGlobalVarNode()) {
						auto gVar = static_cast<CallGraph::Unit::GlobalVarNode*>(node);
						funcBody->addItem(new GlobalVarNode(gVar, nextDepth));
					}
				}

				funcBody->m_isContentLoaded = true;
			}

			void onSearch(const std::string& funcName) override
			{
				m_funcList->getItemsContainer().clear();
				
				FunctionBody* body;
				m_funcList->getItemsContainer().addItem(body = new FunctionBody(m_function, 1, nullptr));

				bool isRemove;
				load(body, 1, isRemove, funcName);
			}
		private:
			bool isAlwaysOpen() {
				return m_cb_isAlwaysOpen->isSelected() || isFilterEnabled();
			}

			bool isGlobalVarNode() {
				return m_cb_isGlobalVarNode->isSelected() && !isFilterEnabled();
			}

			bool isVMethodNode() {
				return m_cb_isVMethodNode->isSelected() && !isFilterEnabled();
			}

			bool isNotCalculatedFunc() {
				return m_cb_isNotCalculatedFunc->isSelected() && !isFilterEnabled();
			}

			bool isCalculatedFunc() {
				return m_cb_isCalculatedFunc->isSelected() || isFilterEnabled();
			}

			bool isFilterEnabled() {
				return m_cb_isFilterEnabled->isSelected();
			}
		private:
			API::Function::Function* m_function;
			FunctionList* m_funcList;

			Elements::Generic::Checkbox* m_cb_isFilterEnabled;
			Elements::Generic::Checkbox* m_cb_isAlwaysOpen;
			Elements::Generic::Checkbox* m_cb_isGlobalVarNode;
			Elements::Generic::Checkbox* m_cb_isVMethodNode;
			Elements::Generic::Checkbox* m_cb_isNotCalculatedFunc;
			Elements::Generic::Checkbox* m_cb_isCalculatedFunc;
			Events::EventHandler* m_eventUpdateCB;
			Events::EventHandler* m_eventVisibleFuncBody;
		};
		friend class CallStackView;

		FunctionTagList()
			: ItemList(new FunctionFilterCreator(this))
		{
			getFilterManager()->addFilter(new CategoryFilter(this));
			getFilterManager()->addFilter(new ClassFilter(this));
			getFilterManager()->addFilter(new FuncTagFilter(this));
		}

		bool checkOnInputValue(API::Function::Function* function, const std::string& value) {
			return Generic::String::ToLower(function->getFunction()->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(API::Function::Function* function) {
			return getFilterManager()->check([&function](FilterManager::Filter* filter) {
				return static_cast<FunctionFilter*>(filter)->checkFilter(function);
			});
		}

		void setOpenFunctionEventHandler(Events::Event* eventHandler) {
			m_openFunction = eventHandler;
		}
	private:
		Events::Event* m_openFunction;
	};
};

namespace GUI::Window
{
	class FunctionTagList : public IWindow
	{
	public:
		FunctionTagList(Widget::FunctionTagList* funcList = new Widget::FunctionTagList)
			: IWindow("Function tag list")
		{
			//MY TODO*: error
			m_openFunctionCP = new Events::EventUI(EVENT_LAMBDA(info) {
				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
				auto function = (API::Function::Function*)message->getUserDataPtr();

				getParent()->getMainContainer().clear();
				getParent()->getMainContainer().addItem(new Widget::FunctionCP(function));
			});
			m_openFunctionCP->setCanBeRemoved(false);

			funcList->setOpenFunctionEventHandler(m_openFunctionCP);
			setMainContainer(funcList);
		}

		~FunctionTagList() {
			delete m_openFunctionCP;
		}

		Widget::FunctionList* getList() {
			return static_cast<Widget::FunctionList*>(getMainContainerPtr());
		}
	private:
		Events::EventHandler* m_openFunctionCP;
	};
};