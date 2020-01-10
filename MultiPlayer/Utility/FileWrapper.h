#pragma once


#include "main.h"
#include <filesystem>
#include "Utility/Generic.h"

//File System
namespace FS
{
	/*class Directory;
	class File;*/
	class Item
	{
	public:
		virtual bool isDir() = 0;
		virtual bool exists() = 0;
		virtual bool rename(std::string newName) = 0;
		virtual std::string getPath() = 0;
		virtual std::string getName() = 0;
		virtual bool remove() {
			return std::filesystem::remove(getPath());
		}
		virtual bool removeAll() {
			return std::filesystem::remove_all(getPath());
		}
	};

	class Directory : public Item
	{
	public:
		Directory() = default;
		Directory(std::string path) : m_path(path) {}

		Directory next(std::string path) {
			return Directory(m_path + '\\' + path);
		}

		Directory back() {
			std::size_t found = m_path.find_last_of("/\\");
			return Directory(m_path.substr(0, found));
		}

		bool createIfNotExists() {
			return (CreateDirectory(m_path.c_str(), NULL) ||
				ERROR_ALREADY_EXISTS == GetLastError());
		}

		bool exists() override {
			if (getPath().size() == 0)
				return false;

			DWORD dwAttrib = GetFileAttributes(getPath().c_str());
			return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
				(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
		}

		bool rename(std::string newName) override {
			return move(
				back().next(newName)
			);
		}

		bool move(FS::Directory newDir) {
			return MoveFile(
				getPath().c_str(),
				newDir.getPath().c_str()
			);
		}

		using itemList = std::list<std::shared_ptr<Item>>;
		itemList getItems();
		
		std::string getPath() override {
			return m_path;
		}

		std::string getName() override;

		bool isDir() override {
			return true;
		}
	private:
		std::string m_path;
	};


	class File : public Item
	{
	public:
		File() = default;
		File(Directory dir, std::string name, std::string format)
			: m_dir(dir), m_name(name), m_format(format)
		{}
		File(Directory dir, std::string filename) : m_dir(dir) {
			auto parts = parseFilename(filename);

			setName(parts.first);
			setFormat(parts.second);
		}
		File(std::string path) {
			auto path_parts = parsePath(path);
			auto file_parts = parseFilename(path_parts.second);
			
			m_dir = path_parts.first;
			setName(file_parts.first);
			setFormat(file_parts.second);
		}

		File& setName(std::string name) {
			m_name = name;
			return *this;
		}

		File& setFormat(std::string format) {
			m_format = format;
			return *this;
		}

		bool exists() override {
			return getPath().size() > 0 && getHandle() != INVALID_HANDLE_VALUE;
		}

		bool rename(std::string newName) override {
			return move(
				FS::File(getDirectory().getPath(), newName)
			);
		}

		bool move(FS::File newFile) {
			return MoveFile(
				getFilename().c_str(),
				newFile.getFilename().c_str()
			);
		}

		HANDLE getHandle() {
			WIN32_FIND_DATA FindFileData;
			HANDLE handle = FindFirstFile(getFilename().c_str(), &FindFileData);
			if (handle != INVALID_HANDLE_VALUE)
			{
				return handle;
				FindClose(handle);
			}
			return INVALID_HANDLE_VALUE;
		}

		std::ifstream getReadDescriptor() {
			return std::ifstream(
				getFilename()
			);
		}

		std::ifstream getWriteDescriptor() {
			return std::ifstream(
				getFilename()
			);
		}

		std::string getFormat() {
			return m_format;
		}

		std::string getFullname() {
			return m_name + '.' + m_format;
		}

		std::string getFilename() {
			return getDirectory().getPath() + '\\' + m_name + '.' + m_format;
		}

		std::string getName() override {
			return getFullname();
		}

		std::string getNameWithoutFormat() {
			return m_name;
		}

		std::string getPath() override {
			return getFilename();
		}

		Directory& getDirectory() {
			return m_dir;
		}

		bool isDir() override {
			return false;
		}
		
		static void exceptDirInPath(Directory dir, std::string& path) {
			auto dirPathSize = (dir.getPath() + "\\").size();
			path = path.substr(
				dirPathSize,
				path.size() - dirPathSize
			);
		}

		static std::pair<std::string, std::string> parseFilename(std::string filename) {
			std::size_t found = filename.find_last_of(".");
			return std::make_pair(
				filename.substr(0, found), filename.substr(found + 1)
			);
		}

		static std::pair<std::string, std::string> parsePath(std::string path) {
			std::size_t found = path.find_last_of("/\\");
			return std::make_pair(
				path.substr(0, found), path.substr(found + 1)
			);
		}

		static File getModule(HMODULE hm = NULL) {
			char path[256];
			GetModuleFileNameA(hm, path, sizeof(path));
			return File(path);
		}
	private:
		std::string m_name;
		std::string m_format;
		Directory m_dir;
	};


	namespace ClipBoard
	{
		class File
		{
		public:
			static void copy(FS::File file) {
				m_file = file;
				m_cutted = false;
			}

			static void cut(FS::File file) {
				copy(file);
				m_cutted = true;
			}

			static void pasteTo(FS::File targetFile) {
				std::filesystem::copy(m_file.getPath(), targetFile.getPath());
				if (m_cutted) {
					m_file.remove();
				}
			}

			static bool isFileValid() {
				return m_file.getPath().size() != 0 && m_file.exists();
			}

			static FS::File& getFile() {
				return m_file;
			}
		private:
			inline static FS::File m_file;
			inline static bool m_cutted = false;
		};
	};
	

	template<typename T>
	class FileDescriptor
	{
	public:
		FileDescriptor(File file, int Mode = std::ios::in) {
			m_desc.open(file.getFilename(), Mode);
		}
		~FileDescriptor() {
			if (isOpen()) {
				m_desc.close();
			}
		}

		virtual T getData() = 0;
		virtual void setData(const T& data) = 0;

		bool isOpen() {
			return m_desc.is_open();
		}
	protected:
		std::fstream m_desc;
	};


	class JsonFileDesc : public FileDescriptor<json>
	{
	public:
		JsonFileDesc(File file, int Mode = std::ios::in)
			: FileDescriptor<json>(file, Mode)
		{}

		json getData() override {
			std::string data(
				(std::istreambuf_iterator<char>(m_desc)),
				std::istreambuf_iterator<char>()
			);
			return json::parse(data);
		}

		void setData(const json& data) override {
			m_desc << data.dump(4).data();
		}
	};


	class TextFileDesc : public FileDescriptor<std::string>
	{
	public:
		TextFileDesc(File file, int Mode = std::ios::in)
			: FileDescriptor<std::string>(file, Mode)
		{}

		std::string getData() override {
			std::string data(
				(std::istreambuf_iterator<char>(m_desc)),
				std::istreambuf_iterator<char>()
			);
			return data;
		}

		void setData(const std::string& data) override {
			m_desc << data;
		}
	};

	class ScriptFileDesc : public TextFileDesc
	{
	public:
		ScriptFileDesc(File file, int Mode = std::ios::in)
			: TextFileDesc(file, Mode)
		{}
	};
};