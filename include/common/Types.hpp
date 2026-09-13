#pragma once

#include <string>
#include <vector>
#include <map>
#include <utility>
#include <librsync.h>
#include <msgpack.hpp>

/**
 * @brief A alias for a std::vector<char> to store file deltas
 */
using Delta = std::vector<char>;

/**
 * @brief A alias for a std::vector<char> to store file signatures
 */
using Signature = std::vector<char>;

/**
 * @brief Metadata for a single file
 */
struct FileInfo {
    std::optional<std::vector<char>> signature; ///< librsync signature of the file
    uint64_t version = 0; 

    MSGPACK_DEFINE(signature, version);
};

/**
 * @brief Pair containing file name and its information
 */
struct FileRecord {
    std::string fileName;
    FileInfo info;

    MSGPACK_DEFINE(fileName, info);
};


/**
 * @brief A file name paired with its delta bytes (librsync patch).
 */
struct FileDelta {
    std::string fileName;
    Delta delta;
};

/**
 * @brief A file name paired with its signature bytes.
 */
struct FileSignature {
    std::string fileName;
    Signature signature;
};

/**
 * @brief Maps a file's relative path to its current librsync signature.
 */
using RecordMap = std::map<std::string, FileInfo>;

/**
 * @brief Maps a file's relative path to its signature
 */
using SignatureMap = std::map<std::string, Signature>;

/**
 * @brief Maps a file's relative path to its signature
 */
using DeltaMap = std::map<std::string, Delta>;


struct FileCloser { void operator()(FILE* f) const { if (f) std::fclose(f); } };
using FilePtr = std::unique_ptr<FILE, FileCloser>;

struct SignatureDeleter { void operator()(rs_signature_t *sumset) const { if (sumset) rs_free_sumset(sumset); } };
using SignaturePtr = std::unique_ptr<rs_signature_t, SignatureDeleter>;
