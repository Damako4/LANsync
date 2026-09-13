#pragma once

#include <cstdint>
#include <openssl/ssl.h>
#include <string>
#include <map>
#include <vector>

#define FLAG_TEST 0x20

/**
 * @brief Thrown when the peer closes the connection cleanly before
 * any bytes of a new message were read.
 *
 * Distinct from std::runtime_error, which represents a genuine
 * protocol/TLS failure (e.g. a connection dropping mid-message).
 */
class ConnectionClosed : public std::exception {
public:
    const char* what() const noexcept override {
        return "Connection closed by peer";
    }
};

/**
 * @brief Enum defining the command being sent / recieved
 */
enum class Command : uint8_t {
    Signature = 0, ///<  Sending / recieving a @ref FileSignature
    Delta = 1, ///< Sending / recieving a @ref Delta
    Update = 2, ///< Sending / recieving a ping for file update
    Version = 3 ///< Sending / recieving file versions
};

/**
 * @brief Header sent before stream bytes
 */
struct ProtocolHeader {
    Command command; ///< Command being sent / received
    uint8_t flags; ///< Flags (not implemented)
    uint32_t streamLength; ///< Size of stream to expect
};
 
class ProtocolHandler {
public:
    /**
     * @brief Initialize @ref ProtocolHandler to use @p ssl for all subsequent read / write calls
     * 
     * @param ssl The SSL connection handle
     */
    explicit ProtocolHandler(SSL *ssl) : ssl(ssl) {}

    /**
     * @brief Read a ProtocolHeader from @p ssl into @p outHeader.
     *
     * @param ssl Pointer to the SSL connection to read from.
     * @param outHeader Reference to the ProtocolHeader to populate.
     * @throws ConnectionClosed if the peer disconnects before any header bytes are read.
     */
    void readHeaderBytes(ProtocolHeader &outHeader);

    /**
     * @brief Write a ProtocolHeader to @p ssl.
     *
     * @param ssl Pointer to the SSL connection to write to.
     * @param cmd The command type for this message.
     * @param flags Command-specific flags.
     * @param streamLength Number of bytes that will follow in the stream body.
     */
    void writeHeaderBytes(Command cmd, uint8_t flags, uint32_t streamLength);

    /**
     * @brief Write @p size bytes from @p bytes to @p ssl.
     *
     * @param ssl Pointer to the SSL connection to write to.
     * @param bytes Pointer to the data to send.
     * @param size Number of bytes to write.
     */
    void writeStreamBytes(const char *bytes, size_t size);

    /**
     * @brief Read @p bytesToRead bytes from @p ssl into @p buffer.
     *
     * @param ssl Pointer to the SSL connection to read from.
     * @param buffer Destination buffer; must already be sized to hold @p bytesToRead bytes.
     * @param bytesToRead Number of bytes to read.
     * @throws ConnectionClosed if the peer disconnects before any bytes are read.
     */
    void readStreamBytes(std::string &buffer, size_t bytesToRead);
private:
    SSL *ssl; ///< Private SSL handle
    /**
     * @brief Read exactly @p bytesToRead bytesfrom the @p ssl connection into @p destination 
     * 
     * @param ssl Pointer to the SSL connection to read from
     * @param destination Buffer to read into
     * @param bytesToRead The number of bytes to read
     */
    void readExact(void *destination, size_t bytesToRead);

    /**
     * @brief Write exactly @p bytesToWrite bytes from buffer @p source into connection @p ssl
     * 
     * @param ssl Pointer to the SSL connection to read from
     * @param destination Buffer to read from
     * @param bytesToRead The number of bytes to write 
     */
    void writeExact(const void *source, size_t bytesToWrite);
};