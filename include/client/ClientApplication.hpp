#pragma once

#include <Config.hpp>
#include <SslDeleters.hpp>
#include <map>
#include <memory>
#include <openssl/ssl.h>
#include <vector>
#include <efsw/efsw.hpp>
#include <UpdateListener.hpp>
#include <FileEventQueue.hpp>
#include <Types.hpp>
#include <ProtocolHandler.hpp>

#define RECURSIVE_FILE_WATCH 0

namespace filesystem = std::filesystem;

class ClientApplication {
public:
  /**
   * @brief Sets up the client's SSL context (TLS 1.2+, default trust store).
   * 
   * @param config Application settings
   */
  explicit ClientApplication(const ApplicationConfig &config);

  /**
   * @brief Connects to the server, exchanges initial signatures, and runs
   * the main client loop until the connection drops.
   */
  void run();

  /**
   * @brief Handles a file edit event by notifying server
   * 
   * @param event The file event that occured
   */
  void handleEdit(const FileEvent &event);


  /**
   * @brief Stops the file watcher and shuts down the SSL connection.
   *
   * Safe to call multiple times.
   */
  void shutdown();

  /**
   * @brief Ensures @ref shutdown runs on destruction.
   */
  ~ClientApplication();

private:
  ApplicationConfig config; ///< ApplicationConfig for the client
  RecordMap signatures; ///< RecordMap containing the clients latest signatures

  std::optional<ProtocolHandler> protocolHandler;

  std::unique_ptr<SSL_CTX, SslCtxDeleter> ctx;
  std::unique_ptr<SSL, SslDeleter> ssl;

  FileEventQueue queue; ///< File event queue
  UpdateListener listener; ///< Listener thread adding file events to clients @ref FileEventQueue
  std::unique_ptr<efsw::FileWatcher> fileWatcher; ///< File watcher thread to call @ref UpdateListener
  efsw::WatchID watchID = -1;
  bool running = false;
  bool processingVersionPull = false; ///< Flag to prevent reentrancy during version pull

  ProtocolHeader header;
  msgpack::object_handle result;
};