#include <FileHandler.hpp>
#include <ThreadPool.hpp>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <Logging.hpp>

namespace filesystem = std::filesystem;

std::string FileHandler::sharedFolderPath;
void FileHandler::init(const std::string &path) {
  sharedFolderPath = path;
}

void FileHandler::patchFile(const FileDelta &delta) {
  std::string filePath = sharedFolderPath + delta.fileName;
  filesystem::path tmpFilePath = filePath;
  tmpFilePath += ".tmp";
  FilePtr file(std::fopen(filePath.c_str(), "rb"));
  FilePtr tmpFile(std::fopen(tmpFilePath.c_str(), "wb"));
  if (!file || !tmpFile) {
    std::perror("File opening failed");
    throw std::runtime_error("Failed to open file.");
  }
  rs_job_t *job = rs_patch_begin(rs_file_copy_cb, file.get());

  unsigned char out_chunk[CHUNK_SIZE];
  rs_buffers_t buf = {0};
  buf.next_in = const_cast<char*>(delta.delta.data());
  buf.avail_in = delta.delta.size();
  buf.eof_in = 1;

  rs_result result;
  do {
    buf.next_out = (char *)out_chunk;
    buf.avail_out = sizeof(out_chunk);

    result = rs_job_iter(job, &buf);

    size_t written = sizeof(out_chunk) - buf.avail_out;
    if (written > 0) {
      size_t n = std::fwrite(out_chunk, 1, written, tmpFile.get());
      if (n != written) {
        if (std::ferror(tmpFile.get())) {
          tmpFile.reset();
          filesystem::remove(tmpFilePath);
          throw std::runtime_error(std::string("Write failed: ") + std::strerror(errno));
        } else {
          tmpFile.reset();
          filesystem::remove(tmpFilePath);
          throw std::runtime_error("Write failed: short write.");
        }
      }
    }

  } while (result == RS_BLOCKED || (result == RS_DONE && buf.avail_in > 0));

  if (result != RS_DONE) {
    rs_job_free(job);
    tmpFile.reset();
    filesystem::remove(tmpFilePath);
    throw std::runtime_error(std::string("Failed to patch: ") + rs_strerror(result));
  }

  rs_job_free(job);

  // Move tmpFile to original file
  file.reset();
  tmpFile.reset();
  filesystem::rename(tmpFilePath, filePath);
}

SignatureMap FileHandler::generateSignatureBatch(const std::string &folderPath) {
  std::map<std::string, std::vector<char>> signatures;
  std::vector<std::string> fileNames;

  if (filesystem::exists(folderPath) && filesystem::is_directory(folderPath)) {
    for (const auto &entry : filesystem::directory_iterator(folderPath)) {
      std::string fileName = entry.path().filename().string();
      
      fileNames.push_back(fileName);
    }
  } else {
    throw std::runtime_error("Directory not found: " + folderPath);
  }

  for (auto &fileName : fileNames) {
    std::vector<char> buffer = FileHandler::generateSignature(fileName).signature;
    signatures.insert({fileName, std::move(buffer)});
  }

  return signatures;
}

FileSignature FileHandler::generateSignature(const std::string &fileName) {
  std::string filePath = sharedFolderPath + fileName;
  FilePtr file(std::fopen(filePath.data(), "rb"));
  if (!file) {
    std::perror("File opening failed");
    throw std::runtime_error("Failed to open file.");
  }

  // Get size of file
  std::fseek(file.get(), 0, SEEK_END);
  rs_long_t file_size = std::ftell(file.get());
  std::fseek(file.get(), 0, SEEK_SET);

  // Determine best arguments
  rs_magic_number magic = (rs_magic_number)0;
  size_t block_len = 0;
  size_t strong_len = 0;
  rs_result res;
  if ((res = rs_sig_args(file_size, &magic, &block_len, &strong_len)) != RS_DONE) {
    throw std::runtime_error(std::string("Failed to generate signature arguments: ") + rs_strerror(res));
  }

  // Create a tmp file to store signature in
  FilePtr sig_file(std::tmpfile());
  if ((res = rs_sig_file(file.get(), sig_file.get(), block_len, strong_len, magic, nullptr)) != RS_DONE) {
    throw std::runtime_error(std::string("Failed to generate signature file: ") + rs_strerror(res));
  }

  // Get size of sig_file
  std::fseek(sig_file.get(), 0, SEEK_END);
  rs_long_t sig_file_size = std::ftell(sig_file.get());
  if (sig_file_size < 0) {
    throw std::runtime_error("ftell failed on signature file");
  }
  std::fseek(sig_file.get(), 0, SEEK_SET);

  std::vector<char> buffer(sig_file_size);
  size_t bytesRead = std::fread(buffer.data(), 1, sig_file_size, sig_file.get());
  if (std::ferror(sig_file.get())) {
    throw std::runtime_error("Failed to read signature file.");
  } else if (std::feof(sig_file.get()) && bytesRead < sig_file_size) {
    throw std::runtime_error("Failed to read all signature file bytes.");
  }

  return {fileName, std::move(buffer)};
}


SignaturePtr FileHandler::loadSignatureFromBuffer(const std::vector<char> &buffer) {
  rs_signature_t *sumset = nullptr;
  rs_job_t *job = rs_loadsig_begin(&sumset);

  rs_buffers_t buf;
  buf.next_in = const_cast<char *>(buffer.data());
  buf.avail_in = buffer.size();
  buf.eof_in = 1;
  buf.next_out = nullptr;
  buf.avail_out = 0;

  rs_result res;
  do {
    res = rs_job_iter(job, &buf);
  } while (res == RS_BLOCKED);

  rs_job_free(job);

  if (res != RS_DONE) {
    if (sumset)
      rs_free_sumset(sumset);
    throw std::runtime_error(std::string("Failed to load signature: ") + rs_strerror(res));
  }

  res = rs_build_hash_table(sumset);
  if (res != RS_DONE) {
    rs_free_sumset(sumset);
    throw std::runtime_error(std::string("Failed to build hash table: ") + rs_strerror(res));
  }

  return std::unique_ptr<rs_signature_t, SignatureDeleter>(sumset);
}

FileDelta FileHandler::threadComputeDelta(const std::vector<char> &signatureBuffer, const std::string &filePath, const std::string &fileName) {
  FilePtr file(std::fopen(filePath.c_str(), "rb"));
  if (!file) {
    std::perror("File opening failed");
    throw std::runtime_error("Failed to open file.");
  }

  // Load signature from buffer and compute delta
  SignaturePtr clientSignature = loadSignatureFromBuffer(signatureBuffer);
  rs_result res;
  FilePtr deltaFile(std::tmpfile());
  res = rs_delta_file(clientSignature.get(), file.get(), deltaFile.get(), nullptr);
  if (res != RS_DONE) {
    throw std::runtime_error(std::string("Failed to generate delta file: ") + rs_strerror(res));
  }

  // Get size of deltaFile and allocate buffer for it
  std::fseek(deltaFile.get(), 0, SEEK_END);
  rs_long_t deltaBufferSize = std::ftell(deltaFile.get());
  if (deltaBufferSize < 0) {
    throw std::runtime_error("ftell failed on delta file");
  }
  std::fseek(deltaFile.get(), 0, SEEK_SET);
  std::vector<char> deltaBuffer(static_cast<size_t>(deltaBufferSize));

  // Read the bytes from the deltaFile into the buffer
  size_t bytesRead = std::fread(deltaBuffer.data(), 1, deltaBufferSize, deltaFile.get());
  if (std::ferror(deltaFile.get())) {
    throw std::runtime_error("Failed to read signature file.");
  } else if (std::feof(deltaFile.get()) && bytesRead < deltaBufferSize) {
    throw std::runtime_error("Failed to read all signature file bytes.");
  }

  return {fileName, std::move(deltaBuffer)};
}

Delta FileHandler::generateDelta(const FileSignature &toPatchSignaturePair) {
    std::string filePath = sharedFolderPath + toPatchSignaturePair.fileName;
    return FileHandler::threadComputeDelta(toPatchSignaturePair.signature, filePath, toPatchSignaturePair.fileName).delta;
}

DeltaMap FileHandler::generateDeltas(const SignatureMap &authoritativeSignature, const SignatureMap &toPatchSignature) {
  DeltaMap deltas;
  ThreadPool pool(CPU_CORES);

  std::vector<std::future<FileDelta>> fileToDeltaPairs;

  // For each signature, compute delta and add to pairs
  for (auto &[fileName, signatureBuffer] : toPatchSignature) {
    if (auto search = authoritativeSignature.find(fileName); search != authoritativeSignature.end()) {
      std::string filePath = sharedFolderPath + fileName;
      fileToDeltaPairs.push_back(pool.submit(&FileHandler::threadComputeDelta, signatureBuffer, filePath, fileName));
    } else {
      throw std::runtime_error("Failed to find client file name key in server map.");
    }
  }

  // Colllect results
  for (auto &fut : fileToDeltaPairs) {
    FileDelta result = fut.get();
    deltas.insert(std::move(std::make_pair(result.fileName, result.delta)));
  }

  return deltas;
}