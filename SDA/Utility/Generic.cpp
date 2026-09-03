#include "Generic.h"

using namespace Generic;

std::vector<std::string> String::Split(const std::string& input, const std::string& regex) {
	std::regex re(regex);
	std::sregex_token_iterator
		first{ input.begin(), input.end(), re, -1 },
		last;
	return { first, last };
}

//replace all
void String::Replace(std::string& source, const std::string& from, const std::string& to)
{
	std::string newString;
	newString.reserve(source.length());  // avoids a few memory allocations

	std::string::size_type lastPos = 0;
	std::string::size_type findPos;

	while (std::string::npos != (findPos = source.find(from, lastPos)))
	{
		newString.append(source, lastPos, findPos - lastPos);
		newString += to;
		lastPos = findPos + from.length();
	}

	// Care for the rest after last occurrence
	newString += source.substr(lastPos);

	source.swap(newString);
}

std::string String::ToLower(std::string source)
{
	std::transform(source.begin(), source.end(), source.begin(),
	[](unsigned char c) {
		return tolower(c);
	});
	return source;
}

std::string String::ToUpper(std::string source)
{
	std::transform(source.begin(), source.end(), source.begin(),
		[](unsigned char c) {
			return toupper(c);
		});
	return source;
}

bool String::Contains(const std::string& str, const std::string& keyword)
{
	return Generic::String::ToLower(str)
		.find(Generic::String::ToLower(keyword)) != std::string::npos;
}

uint64_t String::HexToNumber(std::string source)
{
	std::istringstream converter(source);
	uint64_t value;
	converter >> std::hex >> value;
	return value;
}

std::string String::NumberToHex(uint64_t number)
{
	std::stringstream stream;
	stream << std::hex << number;
	return stream.str();
}

bool Generic::String::is_number(const std::string& s)
{
	std::string::const_iterator it = s.begin();
	while (it != s.end() && std::isdigit(*it)) ++it;
	return !s.empty() && it == s.end();
}

std::wstring Generic::String::s2ws(const std::string& str)
{
	return std::wstring(str.begin(), str.end());
}

std::string Generic::String::ws2s(const std::wstring& wstr)
{
	return std::string(wstr.begin(), wstr.end());
}

void Generic::String::ltrim(std::string& s) {
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
		return !std::isspace(ch);
		}));
}

void Generic::String::rtrim(std::string& s) {
	s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
		return !std::isspace(ch);
		}).base(), s.end());
}

void Generic::String::replaceSymbolWithin(std::string& source, const char bounder[2], const char from, const char to)
{
	int counter = 0;
	for (int i = 0; i < source.length(); i++) {
		if (source[i] == bounder[0]) {
			counter++;
		}
		else if (source[i] == bounder[1]) {
			counter--;
		}
		else if (counter > 0 && source[i] == from) {
			source[i] = to;
		}
	}
}

std::string String::format(const std::string fmt_str, ...) {
	int size = ((int)fmt_str.size()) * 2 + 50;
	std::string str;
	va_list ap;
	while (1) {
		str.resize(size);
		va_start(ap, fmt_str);
		int n = vsnprintf((char*)str.data(), size, fmt_str.c_str(), ap);
		va_end(ap);
		if (n > -1 && n < size) {
			str.resize(n);
			return str;
		}
		if (n > -1)
			size = n + 1;
		else
			size *= 2;
	}
	return str;
}

std::string Date::format(std::chrono::system_clock::time_point time_point, std::string format)
{
	std::time_t time = std::chrono::system_clock::to_time_t(time_point);
	std::string s(40, '\0');

	struct tm newtime;
	localtime_s(&newtime, &time);

	std::strftime(&s[0], s.size(), format.c_str(), &newtime);

	std::string res;
	for (auto it : s) {
		if (it != '\0')
			res += it;
	}

	return res;
}
