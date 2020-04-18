#pragma once
#include "Buffer.h"

class StreamRecordWriter
{
public:
	StreamRecordWriter()
	{}

	int getWrittenLength() {
		return getStream().getOffset();
	}

	virtual void write() = 0;

	Buffer::Stream& getStream() {
		return m_bufferStream;
	}

	void setBufferStream(Buffer::Stream bufferStream) {
		m_bufferStream = bufferStream;
	}
private:
	Buffer::Stream m_bufferStream;
};

class StreamRecord
{
public:
	StreamRecord(Buffer::Stream* bufferStream, StreamRecordWriter* streamRecordWriter)
		: m_bufferStream(bufferStream), m_streamRecordWriter(streamRecordWriter)
	{}

	void write() {
		writeHeader();
		m_streamRecordWriter->setBufferStream(m_bufferStream);
		m_streamRecordWriter->write();
		writeEnd();
	}
private:
	void writeHeader() {
		m_size = m_bufferStream->getNext<int>();
		m_bufferStream->write(0);
	}

	void writeEnd() {
		*m_size = m_streamRecordWriter->getWrittenLength();
	}
protected:
	Buffer::Stream* m_bufferStream;
	StreamRecordWriter* m_streamRecordWriter;
	int* m_size;
};

class BufferIterator {
public:
	BufferIterator(Buffer* buffer)
		: m_buffer(buffer), m_bufferStream(buffer)
	{
		countSize();
	}

	bool hasNext() {//MYTODO: check offset
		return m_curSize > 0 && getOffset() + static_cast<UINT>(m_curSize) <= static_cast<UINT>(m_buffer->getContentOffset());
	}

	Buffer::Stream getStream() {
		Buffer::Stream bufferStream = m_bufferStream;
		m_bufferStream.move(m_curSize);
		countSize();
		return bufferStream;
	}

	int getOffset() {
		return m_bufferStream.getOffset();
	}
private:
	Buffer* m_buffer;
	Buffer::Stream m_bufferStream;
	int m_curSize;

	void countSize() {
		m_curSize = m_bufferStream.read<int>();
	}
};