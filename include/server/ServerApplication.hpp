#pragma once

#include <openssl/ssl.h>
#include <memory>
#include <Config.hpp>
#include <SslDeleters.hpp>
#include <map>
#include <ProtocolHandler.hpp>
#include <Types.hpp>
#include <shared_mutex>

class ServerApplication {
public:
    /**
     * @brief Initializes the server's SSL context, loads TLS certificates,
     * binds the acceptor socket, and initialize @ref FileHandler with the 
     * shared folder in @p config
     *
     * @param config Application settings
     */
    ServerApplication(const ApplicationConfig& config);

    ~ServerApplication();
    
    /**
     * @brief Run the acceptor loop for clients, handling each client with 
     * @ref handleSSLSession
     */
    void run();
    
private:
    ApplicationConfig config; ///< ApplicationConfig for the server

    /**
     * @brief Send deltas for all files that are stale in @param records
     * 
     * @param ssl The active SSL connection to the client
     * @param records The client's RecordMap
     */
    void sendStaleDeltas(ProtocolHandler &protocolHandler, RecordMap &records);

    /**
     * @brief Handles an incoming SSL session and dispatch commands
     * 
     * Reads protocol headers and dispatches based on Command type
     * @param ssl The active SSL connection to the client
     */
    void handleSSLSession(SSL* ssl);

    RecordMap signatures; ///< RecordMap containing the servers latest signatures
    std::unique_ptr<BIO, BioDeleter> acceptor;
    std::unique_ptr<SSL_CTX, SslCtxDeleter> ctx;    

    mutable std::shared_mutex mtx; ///< Protects signatures
    std::vector<std::thread> sessions; ///< All active SSL session threads

    std::atomic<std::size_t> globalUpdateCounter{0}; ///< Generation counter file file updates

    std::string lastUpdatedFileName; ///< Last updated file
    std::mutex fileNameMtx; ///< Protects last updated file

    /**
     * @brief Notifies all session threads of file update by incrementing counter
     */
    void notifyAllClients(const std::string &fileName) { 
        {
            std::lock_guard<std::mutex> lock(fileNameMtx);
            lastUpdatedFileName = fileName;
        }
        globalUpdateCounter.fetch_add(1, std::memory_order_release); 
    };

    // Disallow copying / moving
    ServerApplication(const ServerApplication&) = delete;
    ServerApplication& operator=(const ServerApplication&) = delete;
};