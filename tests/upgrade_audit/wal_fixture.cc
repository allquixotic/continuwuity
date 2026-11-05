#include <rocksdb/db.h>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>

extern "C" void bz_internal_error(int) { std::abort(); }

// A real unflushed, MANIFEST-tracked WAL. The scanner must replay it without
// trying to clear tracking metadata through a writable recovery context.
int main(int argc, char** argv) {
    if (argc != 2 || std::filesystem::exists(argv[1])) return 2;
    rocksdb::Options options;
    options.create_if_missing = true;
    options.track_and_verify_wals_in_manifest = true;
    options.avoid_flush_during_shutdown = true;
    std::unique_ptr<rocksdb::DB> db;
    auto status = rocksdb::DB::Open(options, argv[1], &db);
    if (!status.ok()) { std::cerr << status.ToString(); return 1; }
    rocksdb::WriteOptions write;
    write.sync = true;
    status = db->Put(write, "retained", "synthetic");
    if (status.ok()) status = db->FlushWAL(true);
    if (!status.ok()) { std::cerr << status.ToString(); return 1; }
    return 0;
}
