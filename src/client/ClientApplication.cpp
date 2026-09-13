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

ClientApplication::ClientApplication(const ApplicationConfig &config) : config(config), listener(queue) {
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
  std::vector<std::string> fileNames;
  if (filesystem::exists(config.sharedFolderPath) && filesystem::is_directory(config.sharedFolderPath)) {
    for (const auto &entry : filesystem::directory_iterator(config.sharedFolderPath)) {
      std::string fileName = entry.path().filename().string();
      fileNames.push_back(fileName);
    }
  } else {
    throw std::runtime_error("Directory not found: " + config.sharedFolderPath);
  }
  for (auto &fileName : fileNames) {
    LOG_DEBUG("Initial record generation for " << fileName);
    FileInfo record;
    record.signature = FileHandler::generateSignature(fileName).signature;
    record.version = 0;
    signatures.insert({fileName, std::move(record)});
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
  // That initial packet (WE NEED TO SEND THIS)
  // TODO: At some point this, should just pull server versions
  msgpack::sbuffer sbuf;
  std::string ping = "Ping!";
  msgpack::pack(sbuf, ping);
  protocolHandler.value().writeHeaderBytes(Command::NotImplemented, /*flags=*/0, sbuf.size());
  protocolHandler.value().writeStreamBytes(sbuf.data(), sbuf.size());

  int fd = SSL_get_fd(ssl.get());
  while (true) {
    // Is there a file event from the listener thread?
    if (auto event = queue.pop()) {
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

        break;
      }
      case Command::Update: {

        break;
      }
      case Command::NotImplemented: {
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
  std::string fileName = event.fileName;
  msgpack::pack(sbuf, FileRecord{fileName, signatures[fileName]});
  // Send server file record, containing fileName and version
  protocolHandler.value().writeHeaderBytes(Command::Update, 0, sbuf.size());
  protocolHandler.value().writeStreamBytes(sbuf.data(), sbuf.size());

  // Receive signatures
  protocolHandler.value().readHeaderBytes(header);
  std::string buffer(header.streamLength, '\0');
  protocolHandler.value().readStreamBytes(buffer, header.streamLength);
  msgpack::unpack(result, buffer.data(), header.streamLength);
  Signature serverSignature;
  result.get().convert(serverSignature);

  // Calculate and send deltas to patch with
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