#pragma once
#include "Type.h"
#include <Manager/FunctionManager.h>
#include <Utils/MultipleAction.h>
#include <CallGraph/CallGraph.h>
#include <FunctionTag/FunctionTag.h>
#include "Shared/GUI/Items/IWindow.h"

using namespace CE;

namespace GUI::Widget {
	class FunctionTagShortCut;

	using FunctionEventType = Events::Event<Events::ISender*, API::Function::Function*>;
};

namespace GUI::Units
{
	class TableInfo
	{
	public:
		TableInfo()
		{}

		void addRow(const std::string& name, Elements::Text::Text* value) {
			m_rows.push_back(std::make_pair(name, value));
		}

		void addRow(const std::string& name, const std::string& value) {
			addRow(name, new Elements::Text::Text(value));
		}

		Container* buildText() {
			Container* container = new Container;

			std::string info = "";
			for (auto& row : m_rows) {
				(*container)
					.text(row.first + ": ", ColorRGBA(0xbdbdbdFF))
					.sameLine(0.0f)
					.addItem(row.second);
			}

			return container;
		}

		Table::Table* buildTable() {
			Table::Table* table = new Table::Table;

			auto& header = (*table)
				.beginHeader()
					.beginTD().endTD()
					.beginTD().endTD();
			header.setDisplay(false);

			auto& body = table->beginBody();

			for (auto& row : m_rows) {
				body
				.beginTR()
					.beginTD()
						.text(row.first)
					.endTD()
					.beginTD()
						.addItem(row.second)
					.endTD()
				.endTR();
			}

			return table;
		}
	private:
		std::list<std::pair<std::string, Elements::Text::Text*>> m_rows;
	};

	class DeclInfo : public Container
	{
	public:
		DeclInfo(API::Function::FunctionDecl* functionDecl, bool viewAsTable = false)
			: m_functionDecl(functionDecl), m_viewAsTable(viewAsTable)
		{}

		void onVisibleOn() override {
			TableInfo tableInfo;
			buildBasicInfo(tableInfo);

			if (m_viewAsTable) {
				addItem(tableInfo.buildTable());
			} else {
				addItem(tableInfo.buildText());
			}

			buildDescription();
		}

		void onVisibleOff() override {
			clear();
		}

		virtual void buildBasicInfo(TableInfo& tableInfo) {
			tableInfo.addRow("Name", getFunctionDecl()->getName() + buildIdInfo() + ")");
			tableInfo.addRow("Role", getRoleName((int)getFunctionDecl()->getRole()));
		}

		virtual std::string buildIdInfo() {
			return " (DeclId: " + std::to_string(getFunctionDecl()->getId());
		}

		virtual void buildDescription() {
			text("Description:");
			if (getFunctionDecl()->getDesc().empty()) {
				sameText(" not.");
			}
			else {
				newLine();
				text(getFunctionDecl()->getDesc());
			}
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
	private:
		bool m_viewAsTable = false;
		API::Function::FunctionDecl* m_functionDecl;

		CE::Function::FunctionDecl* getFunctionDecl() {
			return m_functionDecl->getFunctionDecl();
		}
	};

	class FuncInfo : public DeclInfo
	{
	public:
		FuncInfo(API::Function::Function* function, bool viewAsTable = false)
			: m_function(function), DeclInfo(function->getDeclaration(), viewAsTable)
		{}

		std::string buildIdInfo() override {
			return DeclInfo::buildIdInfo() + ", DefId: " + std::to_string(getFunction()->getDefinition().getId());
		}

		void buildBasicInfo(TableInfo& tableInfo) override {
			using namespace Generic::String;

			DeclInfo::buildBasicInfo(tableInfo);

			std::string baseAddr = "0x" + NumberToHex((std::uintptr_t)getFunction()->getAddress());

			auto& ranges = getFunction()->getDefinition().getRangeList();
			if (ranges.size() > 1)
			{
				std::string rangesText = "";
				for (auto range : ranges) {
					rangesText += "\n\t- Begin: 0x" + NumberToHex((std::uintptr_t)range.getMinAddress()) + " | Size: 0x" + NumberToHex(range.getSize());
				}

				tableInfo.addRow("Base address", baseAddr);
				tableInfo.addRow("Address ranges", rangesText);
			}
			else if (ranges.size() == 1) {
				tableInfo.addRow("Base address", baseAddr + " | Size: 0x" + NumberToHex(ranges[0].getSize()));
			}

			if(m_function->hasBody()) {
				auto body = m_function->getBody();

				auto& basicInfo = body->getBasicInfo();
				std::string callStackInfo = "";
				callStackInfo += "Max depth: "+ std::to_string(basicInfo.m_stackMaxDepth) +"\n";
				callStackInfo += "Global vars: all - " + std::to_string(basicInfo.m_gVarCount) + ", write - " + std::to_string(basicInfo.m_gVarWriteCount) + "\n";
				callStackInfo += "Functions: all - " + std::to_string(basicInfo.getAllFunctionsCount()) + ", calc. - " + std::to_string(basicInfo.m_calculatedFuncCount) + ", virt. - " + std::to_string(basicInfo.m_vMethodCount) + "\n";

				tableInfo.addRow("Call stack:", callStackInfo);
				tableInfo.addRow("References to", std::to_string(body->getFunctionsReferTo().size()));
			}
		}

		void buildDescription() override {
			addItem(m_tagShortCut = new GUI::Widget::FunctionTagShortCut(m_function));
			DeclInfo::buildDescription();
		}
	private:
		API::Function::Function* m_function;
		GUI::Widget::FunctionTagShortCut* m_tagShortCut = nullptr;

		CE::Function::Function* getFunction() {
			return m_function->getFunction();
		}
	};

	//MY TODO: for func def and decl
	class DeclSignature
		: public Container
	{
	public:
		class Name
			: public Elements::Text::Text,
			public Events::OnLeftMouseClick<Name>
		{
		public:
			Name(const std::string& name, Events::ClickEventType::EventHandlerType* clickEvent)
				: Elements::Text::Text(name), Events::OnLeftMouseClick<Name>(this, this, clickEvent)
			{}

			void render() override {
				Elements::Text::Text::render();
				sendLeftMouseClickEvent();
			}
		};

		class FuncName : public Name
		{
		public:
			FuncName(const std::string& name, Events::ClickEventType::EventHandlerType* clickEvent)
				: Name(name, clickEvent)
			{}

			FuncName(API::Function::FunctionDecl* functionDecl, const std::string& name, Events::ClickEventType::EventHandlerType* clickEvent)
				: FuncName(name, clickEvent)
			{
				m_declInfo = new ShortCutInfo(new DeclInfo(functionDecl));
				m_declInfo->setParent(this);
			}

			~FuncName() {
				m_declInfo->destroy();
			}

			void render() override {
				Name::render();
				m_declInfo->showWhenAboveItemHovered();
			}
		protected:
			ShortCutInfo* m_declInfo;
		};

		class ArgName : public Name
		{
		public:
			ArgName(int id, const std::string& name, Events::ClickEventType::EventHandlerType* clickEvent)
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
			Type(int id, CE::DataType::Type* type, Events::ClickEventType::EventHandlerType* eventHandler)
				: m_id(id), Units::Type(type, eventHandler)
			{}

			int getId() {
				return m_id;
			}
		private:
			int m_id;
		};


		DeclSignature(
			API::Function::FunctionDecl* functionDecl,
			Events::ClickEventType::EventHandlerType* leftMouseClickOnType = nullptr,
			Events::ClickEventType::EventHandlerType* leftMouseClickOnFuncName = nullptr,
			Events::ClickEventType::EventHandlerType* leftMouseClickOnArgName = nullptr
		)
			:
			m_functionDecl(functionDecl),
			m_leftMouseClickOnType(leftMouseClickOnType),
			m_leftMouseClickOnFuncName(leftMouseClickOnFuncName),
			m_leftMouseClickOnArgName(leftMouseClickOnArgName)
		{
			Utils::actionForList<Events::ClickEventType::EventHandlerType>(
			{
				m_leftMouseClickOnType,
				m_leftMouseClickOnFuncName,
				m_leftMouseClickOnArgName
			}, [](Events::ClickEventType::EventHandlerType* handler) {
				handler->setCanBeRemoved(false);
			});
		}

		~DeclSignature() {
			Utils::actionForList<Events::ClickEventType::EventHandlerType>(
			{
				m_leftMouseClickOnType,
				m_leftMouseClickOnFuncName,
				m_leftMouseClickOnArgName
			}, [](Events::ClickEventType::EventHandlerType* handler) {
				if (handler->canBeRemovedBy(nullptr)) {
					delete handler;
				}
			});
		}

		void onVisibleOn() override {
			buildReturnValueType();
			buildName();
			buildArgumentList();
		}

		int m_argumentSelectedIdx = 0;
	protected:
		void buildReturnValueType()
		{
			(*this)
				.addItem(new Type(0, getFunctionDecl()->getSignature().getReturnType(), m_leftMouseClickOnType));
		}

		void buildName()
		{
			std::string funcName = " " + getFunctionDecl()->Desc::getName();
			(*this)
				.addItem(createFuncName(funcName))
				.sameLine(0.f);
		}

		virtual Name* createFuncName(const std::string& name) {
			return new FuncName(m_functionDecl, name, m_leftMouseClickOnFuncName);
		}

		void buildArgumentList()
		{
			(*this)
				.sameLine(0.f)
				.text("(")
				.sameLine(0.f);

			int idx = 1;
			for (auto& type : getFunctionDecl()->getSignature().getArgList()) {
				buildArgument(idx, getFunctionDecl()->getArgNameList()[idx - 1], type,
					getFunctionDecl()->getSignature().getArgList().size() == idx);
				idx++;
			}

			(*this)
				.sameLine(0.f)
				.text(")")
				.sameLine(0.f);
		}

		void buildArgument(int idx, const std::string& name, CE::DataType::Type* type, bool isFinal = false)
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

		API::Function::FunctionDecl* m_functionDecl;
	protected:
		Events::ClickEventType::EventHandlerType* m_leftMouseClickOnType;
		Events::ClickEventType::EventHandlerType* m_leftMouseClickOnFuncName;
		Events::ClickEventType::EventHandlerType* m_leftMouseClickOnArgName;

		CE::Function::FunctionDecl* getFunctionDecl() {
			return m_functionDecl->getFunctionDecl();
		}
	};


	class FunctionSignature : public DeclSignature
	{
	public:
		class FuncName : public DeclSignature::FuncName
		{
		public:
			FuncName(API::Function::Function* function, const std::string& name, Events::ClickEventType::EventHandlerType* clickEvent)
				: DeclSignature::FuncName(name, clickEvent)
			{
				m_declInfo = new ShortCutInfo(new FuncInfo(function, false));
				m_declInfo->setParent(this);
			}
		};

		FunctionSignature(API::Function::Function* function,
			Events::ClickEventType::EventHandlerType* leftMouseClickOnType = nullptr,
			Events::ClickEventType::EventHandlerType* leftMouseClickOnFuncName = nullptr,
			Events::ClickEventType::EventHandlerType* leftMouseClickOnArgName = nullptr)
			:
			m_function(function),
			DeclSignature(function->getDeclaration(),
				leftMouseClickOnType,
				leftMouseClickOnFuncName,
				leftMouseClickOnArgName
			)
		{}


		Name* createFuncName(const std::string& name) override {
			return new FuncName(m_function, name, m_leftMouseClickOnFuncName);
		}
	private:
		API::Function::Function* m_function;
	};
};