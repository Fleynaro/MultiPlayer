#pragma once
#include <Code/Type/Type.h>

namespace CE
{
	namespace Stat
	{
		class Analyser
		{
		public:
			Analyser()
			{}

			class Histogram
			{
			public:
				struct Interval
				{
					double m_left;
					double m_right;
					Interval(double a, double b)
						: m_left(a), m_right(b)
					{}

					double getMiddle() {
						return (m_right + m_left) / 2.0;
					}

					bool isPoint() {
						return m_left == m_right;
					}
				};

				struct Column
				{
					Interval m_interval;
					int m_frequency;
					Column(Interval interval, int frequency)
						: m_interval(interval), m_frequency(frequency)
					{}
				};

				Column& getColumn(int index) {
					return m_columns[index];
				}

				void addColumn(Column column) {
					m_columns.push_back(column);
				}

				int getColumnCount() {
					return static_cast<int>(m_columns.size());
				}

				int getTotalCount() {
					int result = 0;
					for (const auto& column : m_columns) {
						result += column.m_frequency;
					}
					return result;
				}

				double getBeginingMoment(int degree) {
					double result = 0.0;
					for (auto& column : m_columns) {
						result += ((double)column.m_frequency / getTotalCount()) * pow(column.m_interval.getMiddle(), degree);
					}
					return result;
				}

				double getMiddle() {
					return getBeginingMoment(1);
				}

				double getVariance2() {
					return getBeginingMoment(2) - pow(getBeginingMoment(1), 2);
				}

				double getVariance() {
					return sqrt(getVariance2());
				}

				double getMin() {
					return m_columns.begin()->m_interval.m_left;
				}

				double getMax() {
					return m_columns.rbegin()->m_interval.m_right;
				}

				void debugShow()
				{
					printf(" Histogram{E=%.1f,V=%.2f,min=%.1f,max=%.1f; ", (float)getMiddle(), (float)getVariance(), (float)getMin(), (float)getMax());
					for (auto& column : m_columns) {
						printf("[%.1f,%.1f=>%i] ", (float)column.m_interval.m_left, (float)column.m_interval.m_right, column.m_frequency);
					}
				}
			private:
				std::vector<Column> m_columns;
			};

			bool hasValue(uint64_t value) {
				return m_rawValues.find(value) != m_rawValues.end();
			}

			template<typename T = uint64_t>
			void addValue(T value) {
				uint64_t rawValue = (uint64_t&)value;
				if (hasValue(rawValue)) {
					m_rawValues[rawValue] ++;
				}
				else {
					m_rawValues[rawValue] = 1;
				}
			}

			void doAnalyse()
			{
				using namespace CE::DataType;

				if (m_rawValues.size() == 0)
					return;

				if (isRealInRange<float>({
					std::make_pair(0.0001, 10000.0),
					std::make_pair(-10000.0, -0.0001),
					std::make_pair(0.0, 0.0)
					})) {
					m_set = SystemType::Real;
					m_typeId = SystemType::Float;
				}
				else if (isRealInRange<double>({
				 std::make_pair(0.00001, 100000.0),
				 std::make_pair(-100000.0, -0.00001),
				 std::make_pair(0.0, 0.0)
					})) {
					m_set = SystemType::Real;
					m_typeId = SystemType::Double;
				}

				if (m_rawValues.size() == 1) {
					if (getMin<BYTE>() == 0 && getMin<BYTE>() == 1) {
						m_set = SystemType::Boolean;
					}
					else {
						if (m_set != SystemType::Real) {
							m_set = SystemType::Integer;
						}
					}
				}
				else if (m_rawValues.size() == 2) {
					if (getMin<BYTE>() == 0 && getMax<BYTE>() == 1) {
						m_set = SystemType::Boolean;
					}
				}
				else {
					if (m_set == SystemType::Undefined) {
						m_set = SystemType::Integer;
					}
				}
			}

			Histogram* createHistogram()
			{
				using namespace CE::DataType;

				Histogram* histogram = new Histogram;
				switch (getSet())
				{
				case SystemType::Boolean:
				{
					for (uint64_t value = 0; value <= 1; value++) {
						histogram->addColumn(Histogram::Column(
							Histogram::Interval((float)value, (float)value),
							hasValue(value) ? m_rawValues[value] : 0
						));
					}
					break;
				}

				case SystemType::Integer:
				{
					switch (getTypeId())
					{
					case SystemType::Int8:
						fillHistogramWithColumns<int8_t>(*histogram);
						break;
					case SystemType::Int16:
						fillHistogramWithColumns<int16_t>(*histogram);
						break;
					case SystemType::Int32:
						fillHistogramWithColumns<int32_t>(*histogram);
						break;
					case SystemType::Int64:
						fillHistogramWithColumns<int64_t>(*histogram);
						break;
					default:
						fillHistogramWithColumns<uint64_t>(*histogram);
					}
					break;
				}

				case SystemType::Real:
				{
					switch (getTypeId())
					{
					case SystemType::Float:
						fillHistogramWithColumns<float>(*histogram);
						break;
					case SystemType::Double:
						fillHistogramWithColumns<double>(*histogram);
						break;
					}
					break;
				}
				}
				return histogram;
			}

			bool isUndefined() {
				return getSet() == DataType::SystemType::Undefined;
			}

			DataType::SystemType::Set getSet() {
				return m_set;
			}

			DataType::SystemType::Types getTypeId() {
				return m_typeId;
			}

			void setTypeId(DataType::SystemType::Types typeId) {
				m_typeId = typeId;
			}
		private:
			template<typename T = uint64_t>
			T getMin() {
				T result = (T)0x0;
				bool isFirst = true;
				for (auto& it : m_rawValues) {
					if (isFirst || (T&)it.first < result) {
						result = (T&)it.first;
						isFirst = false;
					}
				}
				return result;
			}


			template<typename T = uint64_t>
			T getMax() {
				T result = (T)0x0;
				bool isFirst = true;
				for (auto& it : m_rawValues) {
					if (isFirst || (T&)it.first > result) {
						result = (T&)it.first;
						isFirst = false;
					}
				}
				return result;
			}

			template<typename T>
			bool isRealInRange(std::vector<std::pair<T, T>> ranges) {
				for (auto& it : m_rawValues) {
					bool result = false;
					for (auto& range : ranges) {
						if ((T&)it.first >= range.first && (T&)it.first <= range.second) {
							result = true;
						}
					}
					if (!result) {
						return false;
					}
				}
				return true;
			}

			template<typename T>
			void fillHistogramWithColumns(Histogram& histogram)
			{
				double min = static_cast<double>(getMin<T>());
				double max = static_cast<double>(getMax<T>());
				double step = (max - min) / getColumnCount();
				for (int i = 0; i < getColumnCount(); i++) {
					auto interval = Histogram::Interval(min + step * i, min + step * (i + 1));
					histogram.addColumn(Histogram::Column(
						interval,
						getValueCountInInterval<T>(interval, i == 0)
					));
				}
			}

			template<typename T>
			int getValueCountInInterval(const Histogram::Interval& interval, bool leftBoundaryInclude = false) {
				int count = 0;
				for (auto& it : m_rawValues) {
					if ((double)(T&)it.first > interval.m_left - leftBoundaryInclude * 0.01 && (double)(T&)it.first <= interval.m_right) {
						count += it.second;
					}
				}
				return count;
			}

			int getColumnCount() {
				return static_cast<int>(floor(log2(m_rawValues.size()))) + 1;
			}
		private:
			DataType::SystemType::Set m_set = DataType::SystemType::Undefined;
			DataType::SystemType::Types m_typeId = DataType::SystemType::Void;
			std::map<uint64_t, int> m_rawValues;
		};
	};
};