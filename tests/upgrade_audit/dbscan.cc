#include <rocksdb/db.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

// The bzip2-sys archive expects its embedding application to provide this callback.
extern "C" void bz_internal_error(int code) {
    std::cerr << "bzip2 internal error " << code << '\n';
    std::abort();
}

static void u32(uint32_t v) {
    unsigned char b[] = {static_cast<unsigned char>(v >> 24), static_cast<unsigned char>(v >> 16),
                         static_cast<unsigned char>(v >> 8), static_cast<unsigned char>(v)};
    if (std::fwrite(b, 1, 4, stdout) != 4) std::exit(4);
}
static void bytes(const rocksdb::Slice& s) {
    if (std::fwrite(s.data(), 1, s.size(), stdout) != s.size()) std::exit(4);
}
int main(int argc, char** argv) {
    if (argc < 2) return 2;
    rocksdb::DBOptions opts;
    std::vector<std::string> names;
    auto status = rocksdb::DB::ListColumnFamilies(opts, argv[1], &names);
    if (!status.ok()) { std::cerr << status.ToString() << '\n'; return 1; }
    std::vector<rocksdb::ColumnFamilyDescriptor> descriptors;
    for (const auto& n : names) descriptors.emplace_back(n, rocksdb::ColumnFamilyOptions());
    std::vector<rocksdb::ColumnFamilyHandle*> handles;
    std::unique_ptr<rocksdb::DB> db;
    status = rocksdb::DB::OpenForReadOnly(opts, argv[1], descriptors, &handles, &db);
    if (!status.ok()) { std::cerr << status.ToString() << '\n'; return 1; }
    int result = 0;
    for (size_t i = 0; i < names.size(); ++i) {
        bool selected = argc == 2;
        for (int a = 2; a < argc; ++a) if (names[i] == argv[a]) selected = true;
        if (!selected) continue;
        u32(names[i].size()); bytes(names[i]);
        rocksdb::ReadOptions read;
        read.fill_cache = false;
        read.verify_checksums = true;
        std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(read, handles[i]));
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            if (it->key().size() >= UINT32_MAX || it->value().size() >= UINT32_MAX) return 3;
            u32(it->key().size()); u32(it->value().size());
            bytes(it->key()); bytes(it->value());
        }
        if (!it->status().ok()) { std::cerr << it->status().ToString() << '\n'; result = 1; break; }
        u32(UINT32_MAX); u32(0);
    }
    for (auto* h : handles) db->DestroyColumnFamilyHandle(h);
    db.reset();
    return result;
}
