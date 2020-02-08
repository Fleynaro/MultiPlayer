#pragma once
#include "Type.h"
#include <Manager/FunctionManager.h>
#include <Utils/MultipleAction.h>
#include <CallGraph/CallGraph.h>

using namespace CE;

namespace GUI::Units
{
	//MY TODO: for func def and decl
	class Signature
		: public Container
	{
	public:
		class Name
			: public Elements::Text::Text,
			public Events::ISender,
			public Events::OnLeftMouseClick<Name>
		{
		public:
			Name(const std::string& name, Events::Event* clickEvent)
				: Elements::Text::Text(name), Events::OnLeftMouseClick<Name>(this, clickEvent)
			{}

			void render() override {
				Elements::Text::Text::render();
				sendLeftMouseClickEvent();
			}
		};

		class FuncName : public Name
		{
		public:
			FuncName(API::Function::Function* function, const std::string& name, Events::Event* clickEvent)
				: m_function(function), Name(name, clickEvent)
			{}

			void render() override {
				Name::render();
				if (ImGui::IsItemHovered()) {
					ImGui::SetTooltip(getTooltipDesc(m_function->getFunction(), m_function->getBody()).c_str());
				}
			}
		private:
			API::Function::Function* m_function;
		};

		class ArgName : public Name
		{
		public:
			ArgName(int id, const std::string& name, Events::Event* clickEvent)
				: m_id(id), Name(name, clickEvent)
			{}

			int getArgumentId() {
				return m_id;
			}
		private:
			int m_id;
		};

		class Type : public Units::Type
		{
		public:
			Type(int id, CE::Type::Type* type, Events::Event* eventHandler)
				: m_id(id), Units::Type(type, eventHandler)
			{}

			int getId() {
				return m_id;
			}
		private:
			int m_id;
		};


		Signature(
			API::Function::Function* function,
			Events::Event* leftMouseClickOnType = nullptr,
			Events::Event* leftMouseClickOnFuncName = nullptr,
			Events::Event* leftMouseClickOnArgName = nullptr
		)
			:
			m_function(function),
			m_leftMouseClickOnType(leftMouseClickOnType),
			m_leftMouseClickOnFuncName(leftMouseClickOnFuncName),
			m_leftMouseClickOnArgName(leftMouseClickOnArgName)
		{
			buildReturnValueType();
			buildName();
			buildArgumentList();

			Utils::actionForList<Events::Event>(
			{
				m_leftMouseClickOnType,
				m_leftMouseClickOnFuncName,
				m_leftMouseClickOnArgName
			}, [](Events::Event* handler) {
				handler->setCanBeRemoved(false);
			});
		}

		~Signature() {
			Utils::actionForList<Events::Event>(
			{
				m_leftMouseClickOnType,
				m_leftMouseClickOnFuncName,
				m_leftMouseClickOnArgName
			}, [](Events::Event* handler) {
				if (handler->canBeRemovedBy(nullptr)) {
					delete handler;
				}
			});
		}

		int m_argumentSelectedIdx = 0;
	protected:
		void buildReturnValueType()
		{
			(*this)
				.addItem(new Type(0, getFunction()->getSignature().getReturnType(), m_leftMouseClickOnType));
		}

		void buildName()
		{
			std::string funcName = " " + getFunction()->getDeclaration().Desc::getName();
			(*this)
				.addItem(new FuncName(m_function, funcName, m_leftMouseClickOnFuncName))
				.sameLine(0.f);
		}

		void buildArgumentList()
		{
			(*this)
				.sameLine(0.f)
				.text("(")
				.sameLine(0.f);

			int idx = 1;
			for (auto& type : getFunction()->getSignature().getArgList()) {
				buildArgument(idx, getFunction()->getArgNameList()[idx - 1], type,
					getFunction()->getSignature().getArgList().size() == idx);
				idx++;
			}

			(*this)
				.sameLine(0.f)
				.text(")")
				.sameLine(0.f);
		}

		void buildArgument(int idx, const std::string& name, CE::Type::Type* type, bool isFinal = false)
		{
			std::string argName = " " + name + (!isFinal ? ", " : "");
			(*this)
				.sameLine(0.f)
				.addItem(new Type(idx, type, m_leftMouseClickOnType))
				.addItem(new ArgName(idx, argName, m_leftMouseClickOnArgName))
				.sameLine(0.f);
		}

		ColorRGBA getColor() {
			return -1;
		}

		static std::string getTooltipDesc(CE::Function::Function* function, CE::CallGraph::Unit::FunctionBody* body = nullptr) {
			using namespace Generic::String;
			
			std::string info =
				"Name: " + function->getName() + " (DeclId: " + std::to_string(function->getDeclaration().getId()) +
				", DefId: " + (function->hasDefinition() ? std::to_string(function->getDefinition().getId()) : "not definition") + ")" +
				"\nRole: " + getRoleName((int)function->getDeclaration().getRole());

			if (function->hasDefinition())
			{
				info +=
					"\nBase address: 0x" + NumberToHex((std::uintptr_t)function->getAddress());

				auto& ranges = function->getDefinition().getRangeList();
				if (ranges.size() > 1)
				{
					info +=
						"\nAddress ranges:";
					for (auto range : ranges) {
						info +=
							"\n\t- Begin: 0x" + NumberToHex((std::uintptr_t)range.getMinAddress()) + " | Size: 0x" + NumberToHex(range.getSize());
					}
				}
				else if (ranges.size() == 1) {
					info +=
						" | Size: 0x" + NumberToHex(ranges[0].getSize());
				}

				if (body != nullptr) {
					info +=
						"\nReferences to: " + std::to_string(body->getFunctionsReferTo().size());
				}
			}

			info +=
				"\nDescription:\n\n" + function->getDesc();

			return info;
		}

		static const std::string& getRoleName(int roleId) {
			static std::vector<std::string> roleName = {
				"Function",
				"Method",
				"Static method",
				"Virtual method",
				"Constructor",
				"Destructor",
				"Virtual destructor"
			};
			return roleName[roleId];
		}

		API::Function::Function* m_function;
	private:
		Events::Event* m_leftMouseClickOnType;
		Events::Event* m_leftMouseClickOnFuncName;
		Events::Event* m_leftMouseClickOnArgName;

		Function::Function* getFunction() {
			return m_function->getFunction();
		}

		/*API::Function::FunctionDecl* getFunctionDecl() {
			return m_functionDecl;
		}*/
	};
};