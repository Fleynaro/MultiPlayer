#pragma once
#include "../DecPCode.h"
#include "../DecStorage.h"
#include <Code/Type/FunctionSignature.h>

namespace CE::Decompiler
{
	std::list<ParameterInfo> GetParameterStorages(DataType::Signature* signature) {
		using namespace DataType;
		std::list<ParameterInfo> result;
		for (auto storage : signature->getCustomStorages()) {
			auto paramIdx = storage.getIndex();
			if (paramIdx >= 1 && paramIdx <= signature->getParameters().size()) {
				auto paramSize = signature->getParameters()[paramIdx - 1]->getDataType()->getSize();
				result.push_back(ParameterInfo(paramSize, storage));
			}
			else if (paramIdx == 0) {
				//if it is return
				result.push_back(ParameterInfo(signature->getReturnType()->getSize(), storage));
			}
		}
		//calling conventions
		if (signature->getCallingConvetion() == Signature::FASTCALL) {
			//parameters
			int paramIdx = 1;
			for (auto param : signature->getParameters()) {
				auto paramType = param->getDataType();
				if (paramIdx >= 1 && paramIdx <= 4) {
					static std::map<int, std::pair<PCode::RegisterId, PCode::RegisterId>> paramToReg = {
								std::pair(1, std::pair(ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_ZMM0)),
								std::pair(2, std::pair(ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_ZMM1)),
								std::pair(3, std::pair(ZYDIS_REGISTER_R8, ZYDIS_REGISTER_ZMM2)),
								std::pair(4, std::pair(ZYDIS_REGISTER_R9, ZYDIS_REGISTER_ZMM3))
					};
					auto it = paramToReg.find(paramIdx);
					if (it != paramToReg.end()) {
						auto& reg = it->second;
						bool isFloatingPoint = paramType->isFloatingPoint();
						auto storage = ParameterStorage(paramIdx, ParameterStorage::STORAGE_REGISTER, !isFloatingPoint ? reg.first : reg.second, 0x0);
						result.push_back(ParameterInfo(paramType->getSize(), storage));
					}
				}
				else {
					auto storage = ParameterStorage(paramIdx, ParameterStorage::STORAGE_STACK, ZYDIS_REGISTER_RSP, (paramIdx - 4) * 0x8);
					result.push_back(ParameterInfo(paramType->getSize(), storage));
				}

				paramIdx++;
			}

			//return
			auto retType = signature->getReturnType();
			if (retType->getSize() != 0x0) {
				bool isFloatingPoint = retType->isFloatingPoint();
				auto storage = ParameterStorage(0, ParameterStorage::STORAGE_REGISTER, !isFloatingPoint ? ZYDIS_REGISTER_RAX : ZYDIS_REGISTER_ZMM0, 0x0);
				result.push_back(ParameterInfo(retType->getSize(), storage));
			}
		}
		return result;
	}

	FunctionCallInfo GetFunctionCallInfo(DataType::Signature* signature) {
		return FunctionCallInfo(GetParameterStorages(signature));
	}
};