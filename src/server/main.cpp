#include <iostream>
#include <openssl/ssl.h>
#include <ServerApplication.hpp>
#include <ProtocolHandler.hpp>
#include <Logging.hpp>

int main(int, char**){
    ApplicationConfig config;
    config.cacheSize = 1024;
    config.cacheTimeout = 3600; // 1 hour
    config.hostport = "54458";
    config.readBufferSize = 1024;
    config.sharedFolderPath = "/home/damir/Documents/LANsync/shared-server/";

    try {
        ServerApplication app(config);
        app.run();
    } catch (const std::exception& e) {
        LOG_ERROR("Error: " << e.what());
        return EXIT_FAILURE;
    }
}
