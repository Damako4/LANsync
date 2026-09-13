#include <ClientApplication.hpp>
#include <iostream>
#include <Logging.hpp>

int main(int, char**){
    ApplicationConfig config;
    config.hostname = "127.0.0.1";
    config.hostport = "54458";
    config.readBufferSize = 1024;
    config.sharedFolderPath = "/home/damir/Documents/LANsync/shared-client/";

    try {
        ClientApplication app(config);
        app.run();
    } catch (const std::exception& e) {
        LOG_ERROR("Error: " << e.what());
        return EXIT_FAILURE;
    }
}