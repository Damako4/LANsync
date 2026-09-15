
# LANsync

A LAN-based file synchronization application that keeps a shared folder in sync across multiple clients on a local network, using delta-based updates


![C++](https://img.shields.io/badge/c%2B%2B-%2300599C.svg?style=for-the-badge&logo=cplusplus&logoColor=white)![CMake](https://img.shields.io/badge/CMake-%23008FBA.svg?style=for-the-badge&logo=cmake&logoColor=white)

📖 [Full API documentation](https://damako4.github.io/LANsync)

![App Screenshot](https://imgur.com/a/dx7b4m6)

## Requirements

- **CMake** ≥ 3.10
- **C++17**-compatible compiler (GCC or Clang)
- **OpenSSL** (development headers + libraries)
- **msgpack-cxx** (must be discoverable via CMake config mode)
- **librsync** (development headers + library)
- **efsw** (file system watcher library, debug build — `efsw-debug`)

On Arch-based systems these can be installed with:
```bash
sudo pacman -S cmake gcc openssl librsync
yay -S msgpack-cxx
yay -S efsw
```

On Debian/Ubuntu, most of these can be installed with:

```bash
sudo apt install cmake g++ libssl-dev librsync-dev
```

For `efsw`, see the [efsw repository](https://github.com/SpartanJ/efsw) for build instructions.
For `msgpack-cxx` see the [msgpack-c repository](https://github.com/msgpack/msgpack-c)

## Building

```bash
cmake -B build
cmake --build build
```
By default, the project builds in **Debug** mode if no build type is specified. To build a release/optimized version instead:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Usage

Start the server first (it listens for incoming client connections):

```bash
./build/lanfs_server
```

Then, on the same machine or another device on the same LAN, start the client:

```bash
./build/lanfs_client
```

