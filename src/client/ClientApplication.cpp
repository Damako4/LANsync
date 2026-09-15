#include <ClientApplication.hpp>
#include <FileHandler.hpp>
#include <Logging.hpp>
#include <ProtocolHandler.hpp>
#include <Tools.hpp>
#include <UpdateListener.hpp>
#include <filesystem>
#include <iostream>
#include <map>
#include <msgpack.hpp>
#include <poll.h>
#include <thread>
#include <vector>

ClientApplication::ClientApplication(const ApplicationConfig &config) : config(config), listener(queue), processingVersionPull(false) {
  ctx.reset(SSL_CTX_new(TLS_client_method()));
  if (!ctx) {
    throw std::runtime_error("Failed to create SSL_CTX: " + getLastSSLError());
  }

  // Abort the handshake if certificate verification fails
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, NULL);
  // TODO: Change this to SSL_VERIFY_PEER for production

  /* Use the default trusted certificate store */
  if (!SSL_CTX_set_default_verify_paths(ctx.get())) {
    throw std::runtime_error(
        "Failed to set the default trusted certificate store: " +
        getLastSSLError());
  }

  if (!SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION)) {
    throw std::runtime_error(
        "Failed to set the minimum TLS protocol version: " + getLastSSLError());
  }

  std::string serverName = config.hostname + ":" + config.hostport;
  std::unique_ptr<BIO, BioDeleter> clientBio(BIO_new_connect(serverName.c_str()));
  if (!clientBio) {
    throw std::runtime_error("Error creating connect BIO: " + getLastSSLError());
  }

  LOG_INFO("Connecting to " << serverName << "...");
  if (BIO_do_connect(clientBio.get()) <= 0) {
    throw std::runtime_error("Failed to connect to server: " + getLastSSLError());
  }
  LOG_INFO("Connected!");

  // We want to reach out to server everytime that we start up to get latest file updates
  ssl.reset(SSL_new(ctx.get()));
  if (!ssl) {
    throw std::runtime_error("Failed to create the SSL object: " + getLastSSLError());
  }
  BIO *raw_client = clientBio.release();
  SSL_set_bio(ssl.get(), raw_client, raw_client);

  if (SSL_connect(ssl.get()) < 1) {
    if (SSL_get_verify_result(ssl.get()) != X509_V_OK) {
      std::string error(X509_verify_cert_error_string(SSL_get_verify_result(ssl.get())));
      throw std::runtime_error("Failed to connect to the server: Verify error: " + error);
    }
    throw std::runtime_error("Failed to connect to the server: " + getLastSSLError());
  }

  // Initialize file handler and protocol handler
  FileHandler::init(config.sharedFolderPath);
  protocolHandler.emplace(ssl.get());

  // Generate client file records / signatures and zero out versions
  auto fileSignatures = FileHandler::generateSignatureBatch(config.sharedFolderPath);
  for (auto &[fileName, signature] : fileSignatures) {
    LOG_DEBUG("Initial record generation for " << fileName);
    signatures.emplace(fileName, FileInfo{signature, 0});
  }

  // Setup file watcher
  fileWatcher.reset(new efsw::FileWatcher());
  // TODO: Add a specific watch for windows, this will only work for linux
  watchID = fileWatcher->addWatch(config.sharedFolderPath, &listener, RECURSIVE_FILE_WATCH);
  if (watchID < 0) {
    std::cerr << "addWatch failed with code: " << watchID << std::endl;
  }
  fileWatcher->watch();
}

void ClientApplication::run() {
  // Pull server versions (INITIAL REQUEST)
  msgpack::sbuffer sbuf;
  msgpack::pack(sbuf, signatures);
  protocolHandler.value().writeHeaderBytes(Command::Version, 0, sbuf.size());
  protocolHandler.value().writeStreamBytes(sbuf.data(), sbuf.size());

  // BLOCK until we get the FULL initial Version response before processing any file events
  int fd = SSL_get_fd(ssl.get());
  while (true) {
    // Process file events only when not doing version pull
    if (auto event = queue.pop(); !processingVersionPull && event) {
      handleEdit(event.value());
    }

    pollfd pfd{fd, POLLIN, 0};
    int ret = poll(&pfd, 1, /*timeout ms=*/100);

    if (ret < 0) {
      if (errno == EINTR)
        continue; // interrupted by a signal, just retry
      throw std::runtime_error(std::string("poll failed: ") + std::strerror(errno));
    }
    if (ret == 0) {
      continue; // timed out, nothing to read — loop back to check the queue
    }
    if (pfd.revents & (POLLERR | POLLHUP)) {
      break; // connection dropped
    }

    if (pfd.revents & POLLIN) {
      protocolHandler.value().readHeaderBytes(header);
      // Read stream bytes
      std::string buffer(header.streamLength, '\0');
      protocolHandler.value().readStreamBytes(buffer, header.streamLength);
      msgpack::object_handle result;
      msgpack::unpack(result, buffer.data(), header.streamLength);
      switch (header.command) {
      case Command::Signature: {
        // Send signature for our file
        std::string fileName;
        result.get().convert(fileName);
        auto sigIt = signatures.find(fileName);
        if (sigIt == signatures.end())
          throw std::runtime_error("File was not found, directory listings not synced!");
        auto &[fn, info] = *sigIt;
        protocolHandler.value().writeHeaderBytes(Command::Signature, 0, info.signature.value().size());
        protocolHandler.value().writeStreamBytes(info.signature.value().data(), info.signature.value().size());

        // Get delta and patch with it
        Delta delta;
        protocolHandler.value().readHeaderBytes(header);
        std::string deltaBuffer(header.streamLength, '\0');
        protocolHandler.value().readStreamBytes(deltaBuffer, header.streamLength);
        msgpack::unpack(result, buffer.data(), header.streamLength);

        result.get().convert(delta);
        FileHandler::patchFile(FileDelta{fileName, delta});
        
        // Now wait for version
        processingVersionPull = true;
      }
      case Command::Version: {
        if (header.flags & VERSION_WRITE) {
          // Update our version with server's authoritative version
          FileRecord updatedRecord;
          result.get().convert(updatedRecord);

          auto sigIt = signatures.find(updatedRecord.fileName);
          if (sigIt == signatures.end())
            throw std::runtime_error("File was not found, directory listings not synced!");
          auto &[fileName, info] = *sigIt;

          info.version = updatedRecord.info.version;
          LOG_DEBUG("Updating " << updatedRecord.fileName << " to v" << updatedRecord.info.version);
        } else if (header.flags & VERSION_PULL) {
          // Patch with the new deltas and versions
          RecordMap staleDeltas;
          result.get().convert(staleDeltas);
          for (auto &[fileName, serverInfo] : staleDeltas) {
            LOG_DEBUG("Updating " << fileName << " to v" << serverInfo.version);

            auto sigIt = signatures.find(fileName);
            if (sigIt == signatures.end())
              throw std::runtime_error("File was not found, directory listings not synced!");
            auto &[fn, info] = *sigIt;
            info.version = serverInfo.version;

            FileHandler::patchFile(FileDelta{fileName, serverInfo.signature.value()});

            // Generate new signature for patched file
            info.signature = FileHandler::generateSignature(fileName).signature;
          }
        }
        processingVersionPull = false;
      }
      default:
        break;
      }
    }
  }
  shutdown();
}

void ClientApplication::handleEdit(const FileEvent &event) {
  LOG_DEBUG("File " << event.fileName << " updated");
  msgpack::sbuffer sbuf;

  // Send server file record, containing fileName and version (Command::Update)
  auto sigIt = signatures.find(event.fileName);
  if (sigIt == signatures.end())
    throw std::runtime_error("File was not found, directory listings not synced!");
  auto &[fileName, info] = *sigIt;

  msgpack::pack(sbuf, FileRecord{fileName, FileInfo{std::nullopt, info.version}});
  protocolHandler.value().writeHeaderBytes(Command::Update, 0, sbuf.size());
  protocolHandler.value().writeStreamBytes(sbuf.data(), sbuf.size());

  // Receive Command::Signature or Command::Version if file out of date
  protocolHandler.value().readHeaderBytes(header);
  if (header.command == Command::Version) {
    // File out of date, send signature for server to generate delta with
    auto sigIt = signatures.find(fileName);
    if (sigIt == signatures.end())
      throw std::runtime_error("File was not found, directory listings not synced!");
    auto &record = *sigIt;

    sbuf.clear();
    msgpack::pack(sbuf, record); // Just pack the current record, it will contain updated signature.
    protocolHandler.value().writeHeaderBytes(Command::Signature, 0, sbuf.size());
    protocolHandler.value().writeStreamBytes(sbuf.data(), sbuf.size());

    // Patch with the delta we receive from the server
    FileDelta fileDelta;
    protocolHandler.value().readHeaderBytes(header);
    std::string buffer(header.streamLength, '\0');
    protocolHandler.value().readStreamBytes(buffer, header.streamLength);
    msgpack::unpack(result, buffer.data(), header.streamLength);

    result.get().convert(fileDelta);
    FileHandler::patchFile(fileDelta);
    LOG_DEBUG("File out of date, requesting newer version: " << event.fileName);

    // Generate new signature for patched file
    record.second.signature = FileHandler::generateSignature(fileName).signature;

    // Waiting for version, don't handle other file edits
    processingVersionPull = true;

    /**
     * TODO: Handle what happens when a client's version is stale,
     * right now it just overwrites the user's changes to that file
     */
    return;
  }

  std::string buffer(header.streamLength, '\0');
  protocolHandler.value().readStreamBytes(buffer, header.streamLength);
  msgpack::unpack(result, buffer.data(), header.streamLength);

  Signature serverSignature;
  result.get().convert(serverSignature);

  // Send Command::Delta
  sbuf.clear();
  msgpack::pack(sbuf, FileHandler::generateDelta(FileSignature{fileName, serverSignature}));
  protocolHandler.value().writeHeaderBytes(Command::Delta, 0, sbuf.size());
  protocolHandler.value().writeStreamBytes(sbuf.data(), sbuf.size());
}

void ClientApplication::shutdown() {
  if (!running)
    return;
  running = false;

  if (fileWatcher && watchID > 0) {
    fileWatcher->removeWatch(watchID);
  }
  fileWatcher.reset();

  if (ssl) {
    SSL_shutdown(ssl.get());
  }
}

ClientApplication::~ClientApplication() {
  shutdown();
}