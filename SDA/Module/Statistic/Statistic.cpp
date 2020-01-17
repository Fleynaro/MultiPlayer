#include "Statistic.h"
#include <Trigger/Trigger.h>

void CE::Stat::Function::Args::Collector::add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
{
	m_bufferMutex.lock();
	m_buffers.push(Buffer(hook, trigger));
	m_bufferMutex.unlock();
}

void CE::Stat::Function::Ret::Collector::add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
{
	m_bufferMutex.lock();
	m_buffers.push(Buffer(hook, trigger));
	m_bufferMutex.unlock();
}

void CE::Stat::Function::Args::Collector::send(Buffer& buffer)
{
	try {
		SQLite::Database& db = getDB();
		//SQLite::Transaction transaction(db);

		{
			SQLite::Statement query(db, "INSERT INTO sda_call_before (id, function_id, trigger_id) VALUES(?1, ?2, ?3)");
			query.bind(1, (long long)buffer.m_uid);
			query.bind(2, buffer.getFunction()->getId());
			query.bind(3, buffer.m_trigger->getId());
			query.exec();
		}

		{
			for (int i = 0; i < buffer.m_hook->getArgCount(); i++) {
				SQLite::Statement query(db, "INSERT INTO sda_call_args (call_id, id, value) VALUES(?1, ?2, ?3)");
				query.bind(1, (long long)buffer.m_uid);
				query.bind(2, i + 1);
				query.bind(3, (long long)buffer.m_args[i]);
				query.exec();
			}

			if (buffer.m_hook->isXmmSaved())
			{
				for (int i = 0; i < min(4, buffer.m_hook->getArgCount()); i++) {
					SQLite::Statement query(db, "INSERT INTO sda_call_args (call_id, id, value) VALUES(?1, ?2, ?3)");
					query.bind(1, (long long)buffer.m_uid);
					query.bind(2, -(i + 1));
					query.bind(3, (long long)buffer.m_xmm_args[i]);
					query.exec();
				}
			}
		}

		//transaction.commit();
	}
	catch (std::exception& e) {
		std::cout << "exception: " << e.what() << std::endl;
		Sleep(5000);
	}
}

void CE::Stat::Function::Ret::Collector::send(Buffer& buffer)
{
	try {
		SQLite::Database& db = getDB();
		{
			SQLite::Statement query(db, "INSERT INTO sda_call_after (id, ret_value, ret_xmm_value, elapsed_time) VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, (long long)buffer.m_uid);
			query.bind(2, (long long)buffer.m_ret);
			query.bind(3, (long long)buffer.m_xmm_ret);
			query.bind(4, 1);
			query.exec();
		}
	}
	catch (std::exception& e) {
		std::cout << "exception: " << e.what() << std::endl;
		Sleep(5000);
	}
}

void CE::Stat::Function::Account::iterateCalls(std::function<void(CallInfo& info)> handler, CE::Trigger::Function::Trigger* trigger, int page, int pageSize)
{
	using namespace SQLite;

	SQLite::Database& db = getDB();
	SQLite::Statement query(db, "SELECT ca.id,ca.ret_value,ca.ret_xmm_value,ca.elapsed_time FROM sda_call_before AS cb JOIN sda_call_after AS ca ON cb.id=ca.id WHERE cb.function_id=?1 AND cb.trigger_id=?2 LIMIT ?3,?4");
	query.bind(1, m_function->getId());
	query.bind(2, trigger->getId());
	query.bind(3, (page - 1) * pageSize);
	query.bind(4, pageSize);

	while (query.executeStep())
	{
		CallInfo info;
		info.m_uid = (long long)query.getColumn("id");
		info.m_ret = (long long)query.getColumn("ret_value");
		info.m_xmm_ret = (long long)query.getColumn("ret_xmm_value");

		SQLite::Statement query_args(db, "SELECT ca.id,ca.value FROM sda_call_before AS cb JOIN sda_call_args AS ca ON cb.id=ca.call_id WHERE ca.call_id=?1");
		query_args.bind(1, (long long)info.m_uid);
		while (query_args.executeStep())
		{
			int id = query_args.getColumn("id");
			if (id > 0) {
				info.m_args[id - 1] = (long long)query_args.getColumn("value");
			}
			else
				info.m_xmm_args[-id - 1] = (long long)query_args.getColumn("value");
		}

		handler(info);
	}
}

CE::Stat::Function::StatInfo* CE::Stat::Function::Account::createStatInfo(CE::Trigger::Function::Trigger* trigger)
{
	using namespace SQLite;
	using namespace CE::Type;

	auto& signature = m_function->getSignature();
	StatInfo* statInfo = new StatInfo;
	SQLite::Database& db = getDB();

	{
		SQLite::Statement query(db, "SELECT ca.ret_value,ca.ret_xmm_value,ca.elapsed_time FROM sda_call_before AS cb JOIN sda_call_after AS ca ON cb.id=ca.id WHERE cb.function_id=?1 AND cb.trigger_id=?2");
		query.bind(1, m_function->getId());
		query.bind(2, trigger->getId());

		Analyser ret;
		Analyser xmm_ret;
		while (query.executeStep())
		{
			ret.addValue((long long)query.getColumn("ret_value"));
			xmm_ret.addValue((long long)query.getColumn("ret_xmm_value"));
		}

		ret.doAnalyse();
		xmm_ret.doAnalyse();

		if (ret.getSet() == SystemType::Integer) {
			ret.setTypeId(SystemType::GetBasicTypeOf(signature.getReturnType()));
		}

		statInfo->setReturnValue(getValueByAnalysers(ret, xmm_ret, signature.getReturnType()));
	}

	{
		auto& argList = signature.getArgList();

		SQLite::Statement query(db, "SELECT ca.id,ca.value FROM sda_call_before AS cb JOIN sda_call_args AS ca ON cb.id=ca.call_id WHERE cb.function_id=?1 AND cb.trigger_id=?2");
		query.bind(1, m_function->getId());
		query.bind(2, trigger->getId());

		Analyser args[12];
		Analyser xmm_args[4];

		while (query.executeStep())
		{
			int arg_id = query.getColumn("id");

			if (arg_id > 0) {
				args[arg_id - 1].addValue((long long)query.getColumn("value"));
			}
			else
				xmm_args[-arg_id - 1].addValue((long long)query.getColumn("value"));
		}

		for (int i = 0; i < min(4, argList.size()); i++)
			xmm_args[i].doAnalyse();
		for (int i = 0; i < argList.size(); i++) {
			args[i].doAnalyse();
			if (args[i].getSet() == SystemType::Integer) {
				args[i].setTypeId(SystemType::GetBasicTypeOf(argList[i]));
			}
		}

		for (int i = 0; i < min(4, argList.size()); i++)
			statInfo->addArgument(getValueByAnalysers(args[i], xmm_args[i], argList[i]));
		for (int i = 4; i < argList.size(); i++)
			statInfo->addArgument(StatInfo::Value(args[i].getSet(), args[i].getTypeId(), args[i].createHistogram()));
	}

	return statInfo;
}