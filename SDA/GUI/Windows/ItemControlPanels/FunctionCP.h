#pragma once
#include "Shared/GUI/Widgets/Template/ControlPanel.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>
#include <FunctionTag/FunctionTag.h>

using namespace CE;

namespace GUI::Widget
{
	class FunctionCallStackViewer : public Container
	{
	public:
		class Node
		{
		public:
			Node(int depth)
				: m_depth(depth)
			{}
		protected:
			int m_depth;
		};

		class GlobalVarNode : public Item, public Node
		{
		public:
			GlobalVarNode(CallGraph::Unit::GlobalVarNode* gVarNode, int depth)
				: m_gVarNode(gVarNode), Node(depth)
			{}

			void render() override {
				std::string str = "Global var node ";
				if (m_gVarNode->getUse() == CallGraph::Unit::GlobalVarNode::Read) {
					str += "(Read)";
				}
				else {
					str += "(Write)";
				}

				if (ImGui::Selectable(str.c_str()))
				{
				}
			}
		private:
			CallGraph::Unit::GlobalVarNode* m_gVarNode;
		};

		class FunctionNode : public Item, public Node
		{
		public:
			FunctionNode(CallGraph::Unit::FunctionNode* funcNode, int depth)
				: m_funcNode(funcNode), Node(depth)
			{}

			void render() override {
				if (ImGui::Selectable("Not calculated function/method"))
				{
				}
			}
		private:
			CallGraph::Unit::FunctionNode* m_funcNode;
		};

		class VMethodNode : public Item, public Node
		{
		public:
			VMethodNode(CallGraph::Unit::VMethodNode* vMethodNode, int depth)
				: m_vMethodNode(vMethodNode), Node(depth)
			{}

			void render() override {
				if (m_vMethodNode->isNotCalculated()) {
					if (ImGui::Selectable("Not calculated virtual method"))
					{}
					return;
				}
				if (ImGui::Selectable(m_vMethodNode->getDeclaration()->getSigName().c_str()))
				{}
			}
		private:
			CallGraph::Unit::VMethodNode* m_vMethodNode;
		};

		class FunctionBody : public TreeNode, public Node
		{
		public:
			class ShortCut
				: public PopupContainer
			{
			public:
				ShortCut(API::Function::Function* function)
					: m_function(function), PopupContainer(false, 200)
				{}

				void onVisibleOn() override {
					text("All tags of the function:");
					newLine();

					auto tagManager = m_function->getFunctionManager()->getFunctionTagManager();
					auto collection = tagManager->getTagCollectionByDecl(m_function);

					if (!collection.empty()) {
						for (auto tag : collection.getTagList()) {
							text(tag->getName() + " ");
							sameLine();
						}
					}
					else {
						text("no tags");
					}
				}

				void onVisibleOff() override {
					clear();
				}

			private:
				API::Function::Function* m_function;
			};

			FunctionBody(API::Function::Function* function, int depth)
				: m_function(function), Node(depth)
			{}

			~FunctionBody() {
				if (m_signature != nullptr) {
					delete m_signature;
				}
			}

			void onVisibleOn() override {
				clear();
				load();
			}

			void load() {
				if (m_depth == 1)
					setOpen(true);

				int nextDepth = m_depth + 1;

				for (auto node : getBody()->getNodeList()) {
					if (node->isFunction()) {
						auto funcNode = static_cast<CallGraph::Unit::FunctionNode*>(node);
						if (!funcNode->isNotCalculated()) {
							FunctionBody* body;
							addItem(body = new FunctionBody(funcNode->getFunction(), nextDepth));
						} else
							addItem(new FunctionNode(funcNode, nextDepth));
					}
					else if (node->isVMethod()) {
						auto vMethod = static_cast<CallGraph::Unit::VMethodNode*>(node);
						addItem(new VMethodNode(vMethod, nextDepth));
					}
					else if (node->isGlobalVar()) {
						auto gVar = static_cast<CallGraph::Unit::GlobalVarNode*>(node);
						addItem(new GlobalVarNode(gVar, nextDepth));
					}
				}
			}

			void renderHeader() override {
				if (m_signature == nullptr) {
					m_signature = new Units::Signature(m_function);
					(*m_signature)
						.beginReverseInserting()
							.addItem(m_shortCut = new ShortCut(m_function))
						.endReverseInserting();
				}

				if (ImGui::ArrowButton("##r", ImGuiDir_Down))
				{}
				if (ImGui::IsItemHovered()) {
					m_shortCut->setVisible();
				}

				ImGui::SameLine();
				m_signature->show();
			}

			CallGraph::Unit::FunctionBody* getBody() {
				return m_function->getBody();
			}
		private:
			API::Function::Function* m_function;
			Units::Signature* m_signature = nullptr;
			ShortCut* m_shortCut = nullptr;
		};



		FunctionCallStackViewer(API::Function::Function* function)
			: m_function(function)
		{}

		void onVisibleOn() override {
			load();
		}

		void load() {
			FunctionBody* body;
			addItem(body = new FunctionBody(m_function, 1));
		}
	private:
		API::Function::Function* m_function;
	};

	class FunctionCP : public Template::ControlPanel
	{
	public:
		Container* m_generic;
		Container* m_callFunction;
		FunctionCallStackViewer* m_funcCallStackViewer;

		FunctionCP(API::Function::Function* function)
			: m_function(function), ControlPanel()
		{
			getSideBar()->addMenuItem("Generic", m_generic = new Container);
			getSideBar()->addMenuItem("Call", m_callFunction = new Container);
			getSideBar()->addMenuItem("Call stack", m_funcCallStackViewer = new FunctionCallStackViewer(function));
			getSideBar()->setSelectedContainer(m_generic);

			buildGeneric();
			buildCallFunction();
		}

		~FunctionCP() {
			delete m_signature;
		}

		void buildSiganture()
		{
			m_signature = new Units::Signature(m_function,
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto type = static_cast<Units::Signature::Type*>(info->getSender());
					auto name = type->getName();
					int id = type->getId();
					int a = 5;
				}),
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto funcName = static_cast<Units::Signature::Name*>(info->getSender());
					auto name = funcName->getText();
					int a = 5;
				}),
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto argName = static_cast<Units::Signature::ArgName*>(info->getSender());
					auto name = argName->getText();
					int a = 6;
				})
			);
			m_signature->setCanBeRemoved(false);
		}

		void buildGeneric()
		{
			buildSiganture();
			(*m_generic)
				.addItem(m_signature);
		}

		void buildCallFunction()
		{
			(*m_callFunction)
				.text("callFunction");
		}
	private:
		API::Function::Function* m_function;
		Units::Signature* m_signature;
	};
};