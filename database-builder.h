#ifndef _DATABASE_BUILDER_H
#define _DATABASE_BUILDER_H 1

#include "db.h"

#include <chrono>
#include <fcntl.h>
#include <memory>
#include <random>
#include <stddef.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <zstd.h>

class PostingListBuilder;

// {0,0} means unknown or so current that it should never match.
// {-1,0} means it's not a directory.
struct dir_time {
	int64_t sec;
	int32_t nsec;

	bool operator<(const dir_time &other) const
	{
		if (sec != other.sec)
			return sec < other.sec;
		return nsec < other.nsec;
	}
	bool operator>=(const dir_time &other) const
	{
		return !(other < *this);
	}
};
constexpr dir_time unknown_dir_time{ 0, 0 };
constexpr dir_time not_a_dir{ -1, 0 };

struct FileEntry {
	std::string filename;
	uint64_t size;      // 文件大小（低56位）+ 标志位（高8位）
	uint64_t mtime_sec;  // 修改时间（秒）
	uint32_t mtime_nsec; // 修改时间（纳秒）

	// 标志位常量（高8位）
	static constexpr uint64_t FLAG_DIR = (1ULL << 63);
	static constexpr uint64_t FLAG_SYMLINK = (1ULL << 62);
	static constexpr uint64_t FLAG_HARDLINK = (1ULL << 61);
	static constexpr uint64_t FLAG_HIDDEN = (1ULL << 60);
	static constexpr uint64_t FLAG_EXEC = (1ULL << 59);
	static constexpr uint64_t FLAGS_MASK = 0xFF00000000000000ULL;
	static constexpr uint64_t SIZE_MASK = 0x00FFFFFFFFFFFFFFULL;

	// 获取真实文件大小（清除标志位）
	uint64_t get_size() const { return size & SIZE_MASK; }

	// 设置文件大小和标志位
	void set_size(uint64_t real_size, bool is_dir = false, bool is_symlink = false,
	              bool is_hardlink = false, bool is_hidden = false, bool is_exec = false) {
		size = (real_size & SIZE_MASK) |
		       (is_dir ? FLAG_DIR : 0) |
		       (is_symlink ? FLAG_SYMLINK : 0) |
		       (is_hardlink ? FLAG_HARDLINK : 0) |
		       (is_hidden ? FLAG_HIDDEN : 0) |
		       (is_exec ? FLAG_EXEC : 0);
	}

	// 检查标志位
	bool is_directory() const { return (size & FLAG_DIR) != 0; }
	bool is_symlink() const { return (size & FLAG_SYMLINK) != 0; }
	bool is_hardlink() const { return (size & FLAG_HARDLINK) != 0; }
	bool is_hidden() const { return (size & FLAG_HIDDEN) != 0; }
	bool is_executable() const { return (size & FLAG_EXEC) != 0; }
};

class DatabaseReceiver {
public:
	virtual ~DatabaseReceiver() = default;
	virtual void add_file(const FileEntry& entry) = 0;  // 传入完整的文件元数据
	virtual void flush_block() = 0;
	virtual void finish() { flush_block(); }

	// EncodingCorpus only.
	virtual size_t num_files_seen() const { return -1; }
};

class DictionaryBuilder : public DatabaseReceiver {
public:
	DictionaryBuilder(size_t blocks_to_keep, size_t block_size)
		: blocks_to_keep(blocks_to_keep), block_size(block_size) {}
	void add_file(const FileEntry& entry) override;
	void flush_block() override;
	std::string train(size_t buf_size);

private:
	const size_t blocks_to_keep, block_size;
	std::string current_block;
	uint64_t block_num = 0;
	size_t num_files_in_block = 0;

	std::mt19937 reservoir_rand{ 1234 };  // Fixed seed for reproducibility.
	bool keep_current_block = true;
	int64_t slot_for_current_block = -1;

	std::vector<std::string> sampled_blocks;
	std::vector<size_t> lengths;
};

class EncodingCorpus;

class DatabaseBuilder {
public:
	DatabaseBuilder(const char *outfile, gid_t owner, int block_size, std::string dictionary, bool check_visibility);
	DatabaseReceiver *start_corpus(bool store_dir_times);
	void set_next_dictionary(std::string next_dictionary);
	void set_conf_block(std::string conf_block);
	void finish_corpus();

private:
	FILE *outfp;
	std::string outfile;
	std::string temp_filename;
	Header hdr;
	const int block_size;
	std::chrono::steady_clock::time_point corpus_start;
	EncodingCorpus *corpus = nullptr;
	ZSTD_CDict *cdict = nullptr;
	std::string next_dictionary, conf_block;
};

#endif  // !defined(_DATABASE_BUILDER_H)
