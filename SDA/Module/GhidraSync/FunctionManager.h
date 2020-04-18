#pragma once
#include "AbstractManager.h"
#include <Manager/FunctionManager.h>
#include "DataTypeManager.h"

namespace CE
{
	namespace Ghidra
	{
		class FunctionManager : public AbstractManager
		{
		public:
			using HashMap = std::map<function::Id, function::Hash>;

			FunctionManager(CE::FunctionManager* functionManager, Client* client)
				:
				m_functionManager(functionManager),
				AbstractManager(client),
				m_client(std::shared_ptr<TMultiplexedProtocol>(new TMultiplexedProtocol(getClient()->m_protocol, "FunctionManager")))
			{}

			function::Id getId(Function::Function* function) {
				/*ObjectHash objHash;
				objHash.addValue(m_functionManager->getFunctionOffset(function));
				return objHash.getHash();*/
				return m_functionManager->getFunctionOffset(function);
			}

			API::Function::Function* findFunctionById(function::Id id, bool returnDefType = true) {
				for (auto& it : m_functionManager->getFunctions()) {
					if (getId(it.second->getFunction()) == id) {
						return it.second;
					}
				}
				return returnDefType ? m_functionManager->getDefaultFunction() : nullptr;
			}

			function::SFunction buildDescToRemove(Function::Function* function) {
				function::SFunction funcDesc;
				funcDesc.__set_id(getId(function));
				funcDesc.__set_name("{remove}");
				return funcDesc;
			}

			function::SFunction buildDesc(Function::Function* function) {
				function::SFunction funcDesc;
				funcDesc.__set_id(getId(function));

				auto spliter = function->getName().find("::");
				if (spliter != std::string::npos) {
					std::string funcName = function->getName();
					funcName[spliter] = '_';
					funcName[spliter + 1] = '_';
					funcDesc.__set_name(funcName);
				}
				else {
					funcDesc.__set_name(function->getName());
				}

				funcDesc.__set_comment(function->getDesc());

				auto& signature = function->getSignature();
				funcDesc.signature.__set_returnType(
					getClient()->m_dataTypeManager->getTypeUnit(signature.getReturnType())
				);
				for (int i = 0; i < signature.getArgList().size(); i++) {
					auto argType = signature.getArgList()[i];
					auto argName = function->getArgNameList()[i];
					funcDesc.signature.arguments.push_back(getClient()->m_dataTypeManager->getTypeUnit(argType));
					funcDesc.argumentNames.push_back(argName);
				}

				for (auto& range : function->getDefinition().getRangeList()) {
					function::SFunctionRange rangeDesc;
					rangeDesc.__set_minOffset(getClient()->getProgramModule()->toRelAddr(range.getMinAddress()));
					rangeDesc.__set_maxOffset(getClient()->getProgramModule()->toRelAddr(range.getMaxAddress()));
					funcDesc.ranges.push_back(rangeDesc);
				}

				return funcDesc;
			}

			void push(const std::vector<function::SFunction>& functionDescBuffer) {
				Transport tr(getClient()->m_transport);
				m_client.push(functionDescBuffer);
			}

			std::vector<function::SFunction> pull(const HashMap& hashmap) {
				Transport tr(getClient()->m_transport);
				std::vector<function::SFunction> result;
				m_client.pull(result, hashmap);
				return result;
			}

			Function::AddressRangeList getFunctionRanges(const std::vector<function::SFunctionRange>& rangeDescs) {
				Function::AddressRangeList ranges;
				for (auto& range : rangeDescs) {
					ranges.push_back(Function::AddressRange(
						getClient()->getProgramModule()->toAbsAddr(range.minOffset),
						getClient()->getProgramModule()->toAbsAddr(range.maxOffset)
					));
				}
				return ranges;
			}

			void change(Function::Function* function, const function::SFunction& funcDesc) {
				function->getDeclaration().setName(funcDesc.name);
				function->getDeclaration().setDesc(funcDesc.comment);

				auto& signature = function->getSignature();
				signature.setReturnType(
					getClient()->m_dataTypeManager->getType(funcDesc.signature.returnType)
				);

				function->getDeclaration().deleteAllArguments();
				auto& args = funcDesc.signature.arguments;
				for (int i = 0; i < args.size(); i++) {
					function->getDeclaration().addArgument(getClient()->m_dataTypeManager->getType(args[i]), funcDesc.argumentNames[i]);
				}

				function->getDefinition().getRangeList().clear();
				function->getDefinition().getRangeList() = getFunctionRanges(funcDesc.ranges);
			}

			API::Function::Function* changeOrCreate(const function::SFunction& funcDesc) {
				API::Function::Function* function = findFunctionById(funcDesc.id, false);
				if (function == nullptr) {
					function = m_functionManager->createFunction(getClient()->getProgramModule()->toAbsAddr(funcDesc.ranges[0].minOffset), {}, m_functionManager->createFunctionDecl("", ""));
				}

				function->change([&]{
					change(function->getFunction(), funcDesc);
				});
				return function;
			}

			void update(HashMap hashmap) {
				auto functions = pull(hashmap);
				int max = 1000;
				for (auto function : functions) {
					if (function.name.find("FUN_") != std::string::npos || function.name.find("tempFunc") != std::string::npos)
						continue;

					if (function.name.find("UI_") == std::string::npos && function.name.find("String") == std::string::npos && function.name.find("Thread") == std::string::npos)
						if (--max <= 0) continue;
					changeOrCreate(function);
				}
			}

			ObjectHash getHash(const function::SFunction& funcDesc) {
				ObjectHash hash;
				hash.addValue(funcDesc.name);
				hash.addValue(funcDesc.comment);

				auto& args = funcDesc.signature.arguments;
				for (int i = 0; i < args.size(); i++) {
					ObjectHash argHash;
					argHash.addValue(funcDesc.argumentNames[i]);
					argHash.addValue(args[i].typeId);
					argHash.addValue(args[i].pointerLvl);
					argHash.addValue(args[i].arraySize);
					hash.join(argHash);
				}

				for (auto& range : funcDesc.ranges) {
					ObjectHash rangeHash;
					rangeHash.addValue(range.minOffset);
					rangeHash.addValue(range.maxOffset);
					hash.add(rangeHash);
				}
				return hash;
			}

			function::Hash getHash(Function::Function* function) {
				return getHash(buildDesc(function)).getHash();
			}

			HashMap generateHashMap() { //MY TODO: исправить хеширование функций
				HashMap hashmap;
				for (auto& it : m_functionManager->getFunctions()) {
					auto function = it.second->getFunction();
					if (function->isGhidraUnit()) {
						hashmap.insert(std::make_pair(getId(function), getHash(function)));
					}
				}

				return hashmap;
			}
		private:
			CE::FunctionManager* m_functionManager;
			function::FunctionManagerServiceClient m_client;
		};
	};
};