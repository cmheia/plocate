#include "database-builder.h"
#include "db.h"
#include "dprintf.h"

#include <algorithm>
#include <arpa/inet.h>
#include <assert.h>
#include <chrono>
#include <getopt.h>
#include <dirent.h>
#include <iosfwd>
#include <locale.h>
#include <math.h>
#include <memory>
#include <random>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

using namespace std;
using namespace std::chrono;

bool use_debug = false;

enum {
	DBE_NORMAL = 0, /* A non-directory file */
	DBE_DIRECTORY = 1, /* A directory */
	DBE_END = 2 /* End of directory contents; contains no name */
};

// From mlocate.
struct db_header {
	uint8_t magic[8];
	uint32_t conf_size;
	uint8_t version;
	uint8_t check_visibility;
	uint8_t pad[2];
};

// From mlocate.
struct db_directory {
	uint64_t time_sec;
	uint32_t time_nsec;
	uint8_t pad[4];
};

string read_cstr(FILE *fp)
{
	string ret;
	for (;;) {
		int ch = getc(fp);
		if (ch == -1) {
			perror("getc");
			exit(1);
		}
		if (ch == 0) {
			return ret;
		}
		ret.push_back(ch);
	}
}

void handle_directory(FILE *fp, DatabaseReceiver *receiver)
{
	db_directory dummy;
	if (fread(&dummy, sizeof(dummy), 1, fp) != 1) {
		if (feof(fp)) {
			return;
		} else {
			perror("fread");
		}
	}

	string dir_path = read_cstr(fp);
	if (dir_path == "/") {
		dir_path = "";
	}

	for (;;) {
		int type = getc(fp);
		FileEntry entry;
		entry.filename = dir_path + "/" + read_cstr(fp);
		entry.size = 0;
		entry.mtime_sec = 0;

		if (type == DBE_NORMAL) {
			receiver->add_file(entry);
		} else if (type == DBE_DIRECTORY) {
			receiver->add_file(entry);
		} else {
			return;  // Probably end.
		}
	}
}

// 递归扫描
void scan_directory(int dirfd, const string& path, DatabaseReceiver *corpus) {
	DIR *dir = fdopendir(dirfd);
	if (!dir) {
		close(dirfd);
		return;
	}

	struct dirent *de;
	while ((de = readdir(dir)) != nullptr) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		string full_path = path + "/" + de->d_name;

		struct stat st;
		if (fstatat(dirfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
			continue;

		FileEntry entry;
		entry.filename = full_path;

		// 计算目录时间：取 ctime 和 mtime 的较大值（与原版 updatedb 一致）
#if defined(__linux__) && defined(st_ctim)
		int64_t ctime_sec = st.st_ctim.tv_sec;
		int32_t ctime_nsec = int32_t(st.st_ctim.tv_nsec);
		int64_t mtime_sec = st.st_mtim.tv_sec;
		int32_t mtime_nsec = int32_t(st.st_mtim.tv_nsec);

		// 比较并取较大值
		if (ctime_sec > mtime_sec || (ctime_sec == mtime_sec && ctime_nsec > mtime_nsec)) {
			entry.mtime_sec = ctime_sec;
			entry.mtime_nsec = ctime_nsec;
		} else {
			entry.mtime_sec = mtime_sec;
			entry.mtime_nsec = mtime_nsec;
		}
#else
		entry.mtime_sec = st.st_mtime;
		entry.mtime_nsec = 0;
#endif

		// 检查各种属性
		bool is_dir = S_ISDIR(st.st_mode);
		bool is_symlink = S_ISLNK(st.st_mode);
		bool is_hidden = (de->d_name[0] == '.');
		bool is_exec = (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
		bool is_hardlink = !is_dir && (st.st_nlink > 1);

		// 设置大小和标志位
		entry.set_size(st.st_size, is_dir, is_symlink, is_hardlink, is_hidden, is_exec);

		corpus->add_file(entry);

		if (is_dir) {
			int subfd = openat(dirfd, de->d_name, O_RDONLY | O_DIRECTORY);
			if (subfd != -1) {
				scan_directory(subfd, full_path, corpus);
			}
		}
	}

	closedir(dir);
}

void do_build(const char *scan_root, const char *outfile, int block_size)
{
	// 打开扫描根目录
	int root_fd = open(scan_root, O_RDONLY | O_DIRECTORY);
	if (root_fd == -1) {
		perror(scan_root);
		exit(1);
	}

	DatabaseBuilder db(outfile, /*owner=*/-1, block_size,
	                   /*dictionary=*/"", /*check_visibility=*/false);
	DatabaseReceiver *corpus = db.start_corpus(true);

	// 递归扫描目录
	scan_directory(root_fd, scan_root, corpus);

	dprintf("Read %zu files from %s\n", corpus->num_files_seen(), scan_root);
	db.finish_corpus();
	close(root_fd);
}

void usage()
{
	printf(
		"Usage: plocate-build MLOCATE_DB PLOCATE_DB\n"
		"\n"
		"Generate plocate index from mlocate.db, typically /var/lib/mlocate/mlocate.db.\n"
		"Normally, the destination should be /var/lib/mlocate/plocate.db.\n"
		"\n"
		"  -b, --block-size SIZE  number of filenames to store in each block (default 32)\n"
	        "  -l, --require-visibility FLAG  check visibility before reporting files\n"
		"      --help             print this help\n"
		"      --version          print version information\n");
}

void version()
{
	printf("plocate-build %s\n", PACKAGE_VERSION);
	printf("Copyright 2020 Steinar H. Gunderson\n");
	printf("License GPLv2+: GNU GPL version 2 or later <https://gnu.org/licenses/gpl.html>.\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n");
}

bool parse_bool(const string &str, bool *result)
{
	if (str == "0" || str == "no") {
		*result = false;
		return true;
	}
	if (str == "1" || str == "yes") {
		*result = true;
		return true;
	}
	return false;
}

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "block-size", required_argument, 0, 'b' },
		{ "require-visibility", required_argument, 0, 'l' },
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
		{ "debug", no_argument, 0, 'D' },  // Not documented.
		{ 0, 0, 0, 0 }
	};

	int block_size = 32;
	bool check_visibility = true;

	setlocale(LC_ALL, "");
	for (;;) {
		int option_index = 0;
		int c = getopt_long(argc, argv, "b:hpl:VD", long_options, &option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 'b':
			block_size = atoi(optarg);
			break;
		case 'l':
			if (!parse_bool(optarg, &check_visibility) != 0) {
				fprintf(stderr, "plocate-build: invalid value `%s' for --%s\n",
					 optarg, "require-visibility");
				exit(EXIT_FAILURE);
			}
			break;
		case 'h':
			usage();
			exit(0);
		case 'V':
			version();
			exit(0);
		case 'D':
			use_debug = true;
			break;
		default:
			exit(1);
		}
	}

	if (argc - optind != 2) {
		usage();
		exit(1);
	}

	do_build(argv[optind], argv[optind + 1], block_size);
	exit(EXIT_SUCCESS);
}
