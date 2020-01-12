#pragma once

#include "Game/GameAppInfo.h"
#include "Game/ScriptEngine/GameScriptEngine.h"
#include "Template/CategoryListSearch.h"
#include "TypeView.h"
#include "ILoadContent.h"

namespace GUI::Widget
{
	class GameNativeListSearch
		: public Template::CategoryListSearch, public ILoadContentThreaded
	{
		LoadedContent<json>* m_nativeDesc;
		bool m_nativeDescReleased = false;
	public:
		GameNativeListSearch()
		{
			m_clickTextToCopy = new Events::EventUI(
				EVENT_METHOD_PASS(clickTextToCopy)
			);
			m_clickTextToCopy->setCanBeRemoved(false);

			getMainContainer().text("Loading...");

			m_nativeDesc = new LoadedContent<json>;
			m_nativeDesc->load(&loadNativeDesc);
		}

		~GameNativeListSearch() {
			if(!m_nativeDescReleased)
				m_nativeDesc->markAsNoLongerNeeded();
		}

		static void loadNativeDesc(LoadedContent<json>* desc) {
			auto file = FS::File(
				GameAppInfo::GetInstancePtr()->getDllDirectory(),
				"nativesInfo.json"
			);
			if (!file.exists()) {
				desc->markAsLoaded();
				desc->markAsNoLongerNeeded();
				return;
			}

			FS::JsonFileDesc nativesInfo(file, std::ios::in);
			if (nativesInfo.isOpen()) {
				desc->setData(
					nativesInfo.getData()
				);
			}
			desc->markAsLoaded();
		}

		void loadingCheckUpdate() override {
			if (m_nativeDescReleased || !m_nativeDesc->isLoadedAndNeeded())
				return;

			getMainContainer().removeLastItem();
			for (auto const& group : GameScriptEngine::getNativeGroups())
			{
				auto& category = beginCategory(group.first);
				buildCategory(category, group.first, group.second);
				category.m_externalPtr = (void*)group.first.c_str();
			}
			getMainContainer()
				.newLine()
				.addItem(
					new GUI::Elements::Button::ButtonStd(
						"Export natives to .cvs",
						new Events::EventUI(
							EVENT_LAMBDA(info) {
								exportToFile();
							}
						)
					)
				);

			showAll();

			m_nativeDesc->markAsNoLongerNeeded();
			m_nativeDescReleased = true;
		}

		void buildCategory(Category& cat, const std::string& groupName, const std::list<IGameNative*>& natives)
		{
			for (auto native : natives) {
				cat.addItem(
					buildNative(groupName, native)
				);
			}
		}

		Events::EventUI* m_clickTextToCopy = nullptr;
		EVENT_METHOD(clickTextToCopy, info)
		{
			auto sender = (TypeView::TextToCopy*)info->getSender();
			ImGui::SetClipboardText(sender->getText().c_str());
		}

		std::vector<std::string> m_CvsNativeExport;
		void exportToFile(std::string filename = "natives.cvs") {
			auto file = FS::File(
				GameAppInfo::GetInstancePtr()->getDllDirectory(),
				filename
			);
			if (file.exists()) {
				file.remove();
			}

			FS::TextFileDesc natives(file, std::ios::out);
			if (natives.isOpen()) {
				std::string output;
				for (auto line : m_CvsNativeExport)
					output += line + "\n";
				natives.setData(output);
			}
		}

		json& getNativeDesc(std::string groupName, IGameNative* native) {
			auto& group = m_nativeDesc->getData()[groupName];
			return group[native->getHashStr()];
		}
		
		Item* buildNative(std::string groupName, IGameNative* native)
		{
			auto body = new Container;
			//body->setBorder(true);
			//body->setFlags(ImGuiWindowFlags_AlwaysAutoResize);
			//body->setColor(ImGuiCol_ChildBg, ColorRGBA(0x000000CC));
			body->setColor(ImGuiCol_Text, ColorRGBA(0xECECECBB));

			auto item = new Item(new TreeNode("", false));
			item->getContainer<TreeNode>()->addItem(body);
			std::string name;
			std::string cvsExport;

			auto signature = Class::Member::parseSignature(native->getSignature());
			auto& desc = getNativeDesc(groupName, native);

			if (desc.is_null()
				|| desc["params"].is_null() && signature.second.size() > 0
				|| desc["params"].is_array() && desc["params"].get_ptr<json::array_t*>()->size() < signature.second.size()) {
				//not defined
				item->getContainer<TreeNode>()->setName("? " + native->getName() + "(???)");
				return item;
			}
			if (!desc["result"].is_string())
				desc["result"] = "?";

			auto nativeAddr = "0x" + String::NumberToHex(native->getHandler().getHandle().as<std::uintptr_t>());
			(*body)
				.separator()
				.text("Address: ").sameLine(0.f)
				.addItem(
					new TypeView::TextToCopy(
						nativeAddr,
						ColorRGBA(0xCFFDFDAA),
						m_clickTextToCopy
					)
				)
				.text("Static hash: ").sameLine(0.f)
				.addItem(
					new TypeView::TextToCopy(
						native->getHashStr(),
						ColorRGBA(0xFFE9B2AA),
						m_clickTextToCopy
					)
				);

			cvsExport = nativeAddr + "," + native->getHashStr();

			auto adapter = GameHashAdapter::getList()->getHash(native->getHash());
			if (adapter != nullptr) {
				auto newHash = "0x" + String::NumberToHex(adapter->getNewHash());
				(*body)
					.text("Current hash: ").sameLine(0.f)
					.addItem(
						new TypeView::TextToCopy(
							newHash,
							ColorRGBA(0xCFFDE4AA),
							m_clickTextToCopy
						)
					);

				cvsExport += "," + newHash;
			} else cvsExport += ",0x0";
			cvsExport += "," + groupName + "," + native->getName() + ",";

			(*body)
				.newLine();

			{
				//returned value
				auto retType
					= TypeView::getTypeByRawType(signature.first).release();
				auto retOrigType
					= desc["result"].get<std::string>();
				(*body)
					.addItem(
						(new TypeView::TypeText(
							retType
						))
						->setText(retOrigType)
					)
					.text(" ").sameLine(0.f)
					.addItem(
						new TypeView::TextToCopy(
							native->getName(),
							ColorRGBA(-1),
							m_clickTextToCopy
						)
					)
					.sameLine(0.f).text("(");

				//-- title name --
				name += desc["result"].get<std::string>() + " " + native->getName() + "(";
				cvsExport += signature.first;
				cvsExport.pop_back();
			}

			//argument list
			int idx = 0;
			for (auto &arg : signature.second)
			{
				auto argType
					= TypeView::getTypeByRawType(arg).release();
				auto argName
					= desc["params"][idx][1].get<std::string>();
				auto argOrigType
					= desc["params"][idx][0].get<std::string>();

				(*body)
					.sameLine(0.f)
					.addItem(
						(new TypeView::TypeText(
							argType
						))
						->setText(argOrigType)
					)
					.text(" " + argName, ColorRGBA(0xCBCBCBFF)).sameLine(0.f);

				//-- title name --
				name += argOrigType + " " + argName;

				(*body)
					.text(", ");

				//-- title name --
				name += ", ";
				idx++;

				cvsExport += "," + arg + "," + argName;
			}
			if(idx) body->getItems().pop_back();
			(*body)
				.sameLine(0.f)
				.text(")");

			std::list<std::string> keywords = {
				String::ToLower(native->getName()),
				String::ToLower(native->getHashStr())
			};

			//show description if it exists
			if (!desc["desc"].is_null())
			{
				std::vector<json::string_t*> description;
				if (desc["desc"].is_string()) {
					description.push_back(desc["desc"].get_ptr<json::string_t*>());
				}
				else if (desc["desc"].is_array()) {
					for (auto& line : desc["desc"]) {
						description.push_back(line.get_ptr<json::string_t*>());
					}
				}

				(*body)
					.separator();
				for (auto line : description) {
					(*body)
						.addItem(
							new GUI::Elements::Text::BulletText(*line)
						);
					keywords.push_back(String::ToLower(*line));
				}
			}

			//title name
			{
				if (idx) {
					name.pop_back();
					name.pop_back();
				}
				item->getContainer<TreeNode>()->setName(name + ")");
			}

			m_CvsNativeExport.push_back(cvsExport);
			item->setKeywordList(keywords);
			return item;
		}
	};
};