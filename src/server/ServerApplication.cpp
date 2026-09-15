#include <FileHandler.hpp>
#include <Logging.hpp>
#include <ProtocolHandler.hpp>
#include <ServerApplication.hpp>
#include <Tools.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <librsync.h>
#include <msgpack.hpp>
#include <openssl/err.h>
#include <sys/poll.h>
#include <vector>

namespace filesystem = std::filesystem;

void ServerApplication::handleSSLSession(SSL *ssl) {
  ProtocolHandler protocolHandler(ssl);
  ProtocolHeader header;
  FileRecord record;

  std::size_t myLastSeen = globalUpdateCounter.load(std::memory_order_acquire);

  int fd = SSL_get_fd(ssl);
  while (true) {
    pollfd pfd{fd, POLLIN, 0};
    int ret = poll(&pfd, 1, /*timeout ms=*/10);

    if (ret < 0) {
      if (errno == EINTR)
        continue; // interrupted by a signal, just retry
      throw std::runtime_error(std::string("poll failed: ") + std::strerror(errno));
    }

    if (pfd.revents & (POLLERR | POLLHUP)) {
      break; // connection dropped
    }

    if (ret > 0 && (pfd.revents & POLLIN)) {
      // Read header bytes
      protocolHandler.readHeaderBytes(header);

      // Read stream bytes
      std::string buffer(header.streamLength, '\0');
      msgpack::object_handle result;
      protocolHandler.readStreamBytes(buffer, header.streamLength);
      msgpack::unpack(result, buffer.data(), header.streamLength);
      switch (header.command) {
      // When client file is out of date, they send this
      case Command::Signature: {
        FileRecord record;
        result.get().convert(record);

        // Calculate a delta for the client to patch with
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, FileDelta{record.fileName, FileHandler::generateDelta(FileSignature{record.fileName, record.info.signature.value()})});
        protocolHandler.writeHeaderBytes(Command::Delta, 0, sbuf.size());
        protocolHandler.writeStreamBytes(sbuf.data(), sbuf.size());

        FileRecord updatedRecord;
        updatedRecord.fileName = record.fileName;

        std::shared_lock<std::shared_mutex> lock(mtx); // Reading from signatures
        auto sigIt = signatures.find(updatedRecord.fileName);
        if (sigIt == signatures.end())
          throw std::runtime_error("File was not found, directory listings not synced!");
        auto &[fileName, info] = *sigIt;
        updatedRecord.info.version = info.version;

        sbuf.clear();
        msgpack::pack(sbuf, updatedRecord);
        protocolHandler.writeHeaderBytes(Command::Version, VERSION_WRITE, sbuf.size());
        protocolHandler.writeStreamBytes(sbuf.data(), sbuf.size());
        break;
      }
      // When client edits a file
      case Command::Update: {
        result.get().convert(record);

        /*
         * TODO: Check if file name is on the server
         * Use std::map.at()
         */

        std::shared_lock<std::shared_mutex> lock(mtx); // Reading from signatures
        auto sigIt = signatures.find(record.fileName);
        if (sigIt == signatures.end())
          throw std::runtime_error("File was not found, directory listings not synced!");
        auto &[fileName, servInfo] = *sigIt;

        if (record.info.version < servInfo.version) {
          protocolHandler.writeHeaderBytes(Command::Version, VERSION_PULL, 0);
          continue;
        }

        // Send signature, next step is Delta
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, servInfo.signature);
        protocolHandler.writeHeaderBytes(Command::Signature, 0, sbuf.size());
        protocolHandler.writeStreamBytes(sbuf.data(), sbuf.size());
        break;
      }
      case Command::Delta: {
        // Apply delta
        Delta delta;
        result.get().convert(delta);
        FileHandler::patchFile(FileDelta{record.fileName, delta});

        std::unique_lock<std::shared_mutex> lock(mtx); // Because changing version

        // Regenerate signature for that file and
        // Increment version and let client know
        auto sigIt = signatures.find(record.fileName);
        if (sigIt == signatures.end())
          throw std::runtime_error("File was not found, directory listings not synced!");
        auto &[fileName, info] = *sigIt;

        // Generate signature for new patch
        info.signature = FileHandler::generateSignature(fileName).signature;

        // Send new version to client
        auto &version = info.version;
        version += 1;
        FileRecord updatedRecord;
        updatedRecord.fileName = record.fileName;
        updatedRecord.info.version = version;

        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, updatedRecord);
        protocolHandler.writeHeaderBytes(Command::Version, VERSION_WRITE, sbuf.size());
        protocolHandler.writeStreamBytes(sbuf.data(), sbuf.size());

        LOG_DEBUG("Updating " << record.fileName << " to v" << version);

        /**
         * Announce to all clients that file was updated
         */
        notifyAllClients(record.fileName);

        break;
      }
      case Command::Version: {
        // Extract file records
        RecordMap records;
        result.get().convert(records);

        // Compare versions and then send file deltas and versions for files that are stale
        sendStaleDeltas(protocolHandler, records);
        break;
      }
      default:
        break;
      }
    }

    // Check for pending server-side file update
    std::size_t current = globalUpdateCounter.load(std::memory_order_acquire);
    if (current > myLastSeen) {
      // File update occured
      LOG_DEBUG("File update occured from another thread!");
      // Ask client for signatures
      std::string updatedFile;
      {
        std::lock_guard<std::mutex> lock(fileNameMtx);
        updatedFile = lastUpdatedFileName;
      }
      protocolHandler.writeHeaderBytes(Command::Signature, 0, updatedFile.size());
      protocolHandler.writeStreamBytes(updatedFile.data(), updatedFile.size());

      // Wait for signature and then calculate delta and send
      protocolHandler.readHeaderBytes(header);
      std::string buffer(header.streamLength, '\0');
      msgpack::object_handle result;
      protocolHandler.readStreamBytes(buffer, header.streamLength);
      msgpack::unpack(result, buffer.data(), header.streamLength);
      Signature signature;
      result.get().convert(signature);

      // Compute delta on that signature and send
      Delta delta = FileHandler::generateDelta(FileSignature{updatedFile, signature});
      protocolHandler.writeHeaderBytes(Command::Delta, 0, delta.size());
      protocolHandler.writeStreamBytes(delta.data(), delta.size());
      
      // Get version of that file
      std::shared_lock<std::shared_mutex> lock(mtx); // Reading from signatures
      auto sigIt = signatures.find(updatedFile);
      if (sigIt == signatures.end())
      throw std::runtime_error("File was not found, directory listings not synced!");
      auto &[fileName, info] = *sigIt;

      // Send version
      msgpack::sbuffer sbuf;
      msgpack::pack(sbuf, FileRecord{updatedFile, FileInfo{std::nullopt, info.version}});
      protocolHandler.writeHeaderBytes(Command::Version, VERSION_WRITE, sbuf.size());
      protocolHandler.writeStreamBytes(sbuf.data(), sbuf.size());

      myLastSeen = current;
    }
  }
}

void ServerApplication::sendStaleDeltas(ProtocolHandler &protocolHandler, RecordMap &records) {
  // Compare versions and then send file deltas and versions for files that are stale
  std::shared_lock<std::shared_mutex> lock(mtx);
  RecordMap staleFiles;
  for (auto &[fileName, info] : records) {
    auto sigIt = signatures.find(fileName);
    if (sigIt == signatures.end())
      throw std::runtime_error("File was not found, directory listings not synced!");
    auto &[serverFileName, serverInfo] = *sigIt;

    version_t serverVersion = serverInfo.version;
    if (info.version < serverVersion) {
      LOG_DEBUG("Client record for " << fileName << "(v" << info.version << ")" << " out of date, sending latest v" << serverVersion);
      staleFiles.emplace(fileName, FileInfo{FileHandler::generateDelta(FileSignature{fileName, info.signature.value()}), serverVersion});
    }
  }

  // Send those stale deltas and versions
  msgpack::sbuffer sbuf;
  msgpack::pack(sbuf, staleFiles);
  protocolHandler.writeHeaderBytes(Command::Version, VERSION_PULL, sbuf.size());
  protocolHandler.writeStreamBytes(sbuf.data(), sbuf.size());
}

void ServerApplication::run() {
  while (1) {
    ERR_clear_error(); // Before each new connection
    if (BIO_do_accept(acceptor.get()) <= 0) {
      /* Client went away before we accepted the connection */
      continue;
    }

    // Pop off acceptor chain and reset its state
    std::unique_ptr<BIO, BioDeleter> client(BIO_pop(acceptor.get()));
    LOG_INFO("New client connection");

    /* Associate new SSL handle */
    std::unique_ptr<SSL, SslDeleter> ssl(SSL_new(ctx.get()));
    if (!ssl) {
      std::cerr << "Error creating SSL handle for new connection: " << getLastSSLError() << std::endl;
      continue;
    }
    BIO *raw_client = client.release();
    SSL_set_bio(ssl.get(), raw_client, raw_client);

    /* Attempt an SSL handshake with the client */
    if (SSL_accept(ssl.get()) <= 0) {
      std::cerr << "Error performing SSL handshake with client: " << getLastSSLError() << std::endl;
      continue;
    }

    sessions.push_back(std::thread([this, ssl = std::move(ssl)]() mutable {
      try {
        this->handleSSLSession(ssl.get());
      } catch (const ConnectionClosed &) {
        LOG_INFO("Client connection closed.");
        SSL_shutdown(ssl.get());
      } catch (const std::exception &e) {
        LOG_INFO("Client connection closed.");
        LOG_ERROR("Error: " << e.what());
      }
    }));
  }
}

ServerApplication::ServerApplication(const ApplicationConfig &config) : config(config) {
  ctx.reset(SSL_CTX_new(TLS_server_method()));
  if (!ctx) {
    throw std::runtime_error("Failed to create SSL_CTX: " + getLastSSLError());
  }

  if (!SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION)) {
    throw std::runtime_error("Failed to set the minimum TLS protocol version: " + getLastSSLError());
  }

  SSL_CTX_set_options(ctx.get(), SSL_OP_IGNORE_UNEXPECTED_EOF | SSL_OP_NO_RENEGOTIATION);

  // Load the server's certificate *chain* file (PEM format)
  if (SSL_CTX_use_certificate_chain_file(ctx.get(), "chain.pem") <= 0) {
    throw std::runtime_error("Failed to load the server certificate chain file: " + getLastSSLError());
  }

  // Load corresponding private key
  if (SSL_CTX_use_PrivateKey_file(ctx.get(), "pkey.pem", SSL_FILETYPE_PEM) <= 0) {
    throw std::runtime_error("Error loading the server private key file, possible key/cert mismatch: " + getLastSSLError());
  }

  // Enable session caching
  const unsigned char cache_id[] = "application"; // Can be anything
  SSL_CTX_set_session_id_context(ctx.get(), cache_id, sizeof cache_id);
  SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_SERVER);
  SSL_CTX_sess_set_cache_size(ctx.get(), config.cacheSize); // Set server cache size
  SSL_CTX_set_timeout(ctx.get(), config.cacheTimeout);

  // Don't require mTLS (Certificate Based Authentication)
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, NULL);

  // Create acceptor BIO for clients
  acceptor.reset(BIO_new_accept(config.hostport.c_str()));
  if (!acceptor) {
    throw std::runtime_error("Error creating acceptor bio: " + getLastSSLError());
  }

  BIO_set_bind_mode(acceptor.get(), BIO_BIND_REUSEADDR);
  if (BIO_do_accept(acceptor.get()) <= 0) {
    throw std::runtime_error("Error setting up acceptor socket: " + getLastSSLError());
  }

  FileHandler::init(config.sharedFolderPath);

  // Initialize server file versions
  // TODO: Should be persistent (read from a file)
  // Generate client file records / signatures and zero out versions
  auto fileSignatures = FileHandler::generateSignatureBatch(config.sharedFolderPath);
  for (auto &[fileName, signature] : fileSignatures) {
    LOG_DEBUG("Initial record generation for " << fileName);
    signatures.emplace(fileName, FileInfo{signature, 1});
  }
}