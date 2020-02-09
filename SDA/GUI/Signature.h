#pragma once
#include "Type.h"
#include <Manager/FunctionManager.h>
#include <Utils/MultipleAction.h>
#include <CallGraph/CallGraph.h>

using namespace CE;

namespace GUI::Units
{
	class TableInfo
	{
	public:
		TableInfo()
		{}

		void addRow(const std::string& name, const std::string& value) {
			m_rows.push_back(std::make_pair(name, value));
		}

		std::string buildText() {
			std::string info = "";
			for (auto& row : m_rows) {
				info += row.first + ": " + row.second + "\n";
			}
			return info;
		}
	private:
		std::list<std::pair<std::string, std::string>> m_rows;
	};


	class ShortInfo
		: public Container
	{

	};

	class DeclInfo : public ShortInfo
	{
	public:
		DeclInfo(API::Function::FunctionDecl* functionDecl)
			: m_functionDecl(functionDecl)
		{}

		void onVisibleOn() override {
			auto& table = beginTable();
			auto& tableBody = table.beginBody();
			buildBasicInfo(tableBody);
			buildDescription();

			auto& header = table
			.beginHeader()
				.beginTD().endTD()
				.beginTD().endTD();
			header.setDisplay(false);
		}

		void onVisibleOff() override {
			clear();
		}

		virtual void buildBasicInfo(Table::Body& body) {
			auto& td = body
			.beginTR()
				.beginTD()
					.text("Name")
				.endTD()
				.beginTD();
					td.text(getFunctionDecl()->getName());
					buildIdInfo(td);
					td.sameText(")")
				.endTD()
			.endTR()
			.beginTR()
				.beginTD()
					.text("Role")
				.endTD()
				.beginTD()
					.text(getRoleName((int)getFunctionDecl()->getRole()))
				.endTD()
			.endTR();
		}

		virtual void buildIdInfo(Table::TD& td) {
			td.sameText(" (DeclId: " + std::to_string(getFunctionDecl()->getId()));
		}

		virtual void buildDescription() {
			text("Description:");
			newLine();
			text(getFunctionDecl()->getDesc());
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
		API::Function::FunctionDecl* m_functionDecl;

		CE::Function::FunctionDecl* getFunctionDecl() {
			return m_functionDecl->getFunctionDecl();
		}
	};

	class FuncInfo : public DeclInfo
	{
	public:
		FuncInfo(API::Function::Function* function)
			: m_function(function), DeclInfo(function->getDeclaration())
		{}

		void buildIdInfo(Table::TD& td) override {
			DeclInfo::buildIdInfo(td);
			td.sameText(", DefId: " + std::to_string(getFunction()->getDefinition().getId()));
		}

		void buildBasicInfo(Table::Body& body) override {
			using namespace Generic::String;

			DeclInfo::buildBasicInfo(body);

			body
			.beginTR()
				.beginTD()
					.text("Base address")
				.endTD()
				.beginTD()
					.text("0x" + NumberToHex((std::uintptr_t)getFunction()->getAddress()))
				.endTD()
			.endTR();

			auto& ranges = getFunction()->getDefinition().getRangeList();
			if (ranges.size() > 1)
			{
				auto& td = body
				.beginTR()
					.beginTD()
						.text("Address ranges")
					.endTD()
					.beginTD();
						for (auto range : ranges) {
							td.text("\t- Begin: 0x" + NumberToHex((std::uintptr_t)range.getMinAddress()) + " | Size: 0x" + NumberToHex(range.getSize()));
						}
			}
			else if (ranges.size() == 1) {
				sameText(" | Size: 0x" + NumberToHex(ranges[0].getSize()));
			}

			if(m_function->hasBody()) {
				body
				.beginTR()
					.beginTD()
						.text("References to")
					.endTD()
					.beginTD()
						.text(std::to_string(m_function->getBody()->getFunctionsReferTo().size()))
					.endTD()
				.endTR();
			}
		}
	private:
		API::Function::Function* m_function;

		CE::Function::Function* getFunction() {
			return m_function->getFunction();
		}
	};

	class ShortCutInfo
		: public PopupContainer
	{
	public:
		ShortCutInfo(ShortInfo* shortInfo) {
			addItem(shortInfo);
		}

		void showWhenAboveItemHovered() {
			if (ImGui::IsItemHovered()) {
				setVisible();
			}
			PopupContainer::show();
		}
	};

	//MY TODO: for func def and decl
	class DeclSignature
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
			FuncName(const std::string& name, Events::Event* clickEvent)
				: Name(name, clickEvent)
			{}

			FuncName(API::Function::FunctionDecl* functionDecl, const std::string& name, Events::Event* clickEvent)
				: FuncName(name, clickEvent)
			{
				m_declInfo = new ShortCutInfo(new DeclInfo(functionDecl));
				m_declInfo->setWidth(200.0f);
			}

			~FuncName() {
				delete m_declInfo;
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


		DeclSignature(
			API::Function::FunctionDecl* functionDecl,
			Events::Event* leftMouseClickOnType = nullptr,
			Events::Event* leftMouseClickOnFuncName = nullptr,
			Events::Event* leftMouseClickOnArgName = nullptr
		)
			:
			m_functionDecl(functionDecl),
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

		~DeclSignature() {
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

		API::Function::FunctionDecl* m_functionDecl;
	protected:
		Events::Event* m_leftMouseClickOnType;
		Events::Event* m_leftMouseClickOnFuncName;
		Events::Event* m_leftMouseClickOnArgName;

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
			FuncName(API::Function::Function* function, const std::string& name, Events::Event* clickEvent)
				: DeclSignature::FuncName(name, clickEvent)
			{
				m_declInfo = new ShortCutInfo(new FuncInfo(function));
				m_declInfo->setWidth(200.0f);
			}
		};

		FunctionSignature(API::Function::Function* function,
			Events::Event* leftMouseClickOnType = nullptr,
			Events::Event* leftMouseClickOnFuncName = nullptr,
			Events::Event* leftMouseClickOnArgName = nullptr)
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