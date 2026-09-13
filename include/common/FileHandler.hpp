#pragma once

#include <vector>
#include <string>
#include <map>
#include <librsync.h>
#include <future>
#include <memory>
#include <vector>
#include <Types.hpp>

#define CHUNK_SIZE 65536

class FileHandler {
public:
    /**
     * @brief Initialize @ref FileHandler to use @p sharedFolderPath for all subsequent calls
     * 
     * @param sharedFolderPath The path of the shared folder
     */
    static void init(const std::string &sharedFolderPath);

    /**
     * @brief Patch file in @p delta with the delta contained
     * 
     * @param delta @ref FileDelta containing the fileName and delta
     */
    static void patchFile(const FileDelta &delta);
    
    /**
     * @brief Generate signature for @p fileName
     * 
     * @param fileName The name of the file
     * @return A FileSignature containing @p fileName and signature
     */
    static FileSignature generateSignature(const std::string &fileName);

    /**
     * @brief Generates signatures for all files in @p folderPath
     * 
     * @param folderPath The path of the folder
     * @return A SignatureMap containing file names mapped to signatures
     */
    static SignatureMap generateSignatureBatch(const std::string &folderPath);

    /**
     * @brief Generate a @ref Delta for a file
     * 
     * Computes the delta for the file in @p toPatchSignature pair with that pairs signature
     * @param toPatchSignaturePair The signature to generate delta for file against
     * @return The computed @ref Delta
     */
    static Delta generateDelta(const FileSignature &toPatchSignaturePair);

    /**
     * @brief Like @ref generateDelta but for a RecordMap
     * 
     * Generates a RecordMap containing deltas for every file in @p toPatchSignature,
    * computed in parallel using a thread pool.
     * @param authoritativeSignature The newest signature map, the source of truth
     * @param toPatchSignature The signature map for the files that are to be patched
     * @return A RecordMap containing the file names and deltas to patch with
     */
    static DeltaMap generateDeltas(const SignatureMap &authoritativeSignature, const SignatureMap &toPatchSignature);
private:
    static std::string sharedFolderPath;
    /**
     * @brief Return a pointer to a signature contained in a @p buffer
     * 
     * @param buffer The buffer containing the signature
     * @return A smart pointer to the signature
     */
    static SignaturePtr loadSignatureFromBuffer(const std::vector<char> &buffer);

    /**
     * @brief Compute the delta for @p signatureBuffer against @p fileName
     * 
     * @param signatureBuffer The buffer containing the signature
     * @param filePath The folder containing the file
     * @param fileName The name of the file
     * @return A pair with file name and computed computed
     */
    static FileDelta threadComputeDelta(const std::vector<char> &signatureBuffer, const std::string &filePath, const std::string &fileName);
};