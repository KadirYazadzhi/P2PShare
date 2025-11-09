#ifndef P2P_SHARE_STATE_HPP
#define P2P_SHARE_STATE_HPP

#include "../files/manifest.hpp"
#include "../files/file_sharer.hpp"
#include <string>

class ShareState {
public:
    // The default path for the state file.
    static constexpr const char* DEFAULT_STATE_FILE = ".p2p_state.json";

    ShareState(std::string state_file_path = DEFAULT_STATE_FILE);

    /**
     * @brief Adds a new shared file to the state file.
     * @param manifest The manifest of the file to share.
     * @param absolute_file_path The full path to the original file.
     */
    void add_share(const Manifest& manifest, const std::filesystem::path& absolute_file_path);

    /**
     * @brief Loads all shares from the state file into a FileSharer instance.
     * @param sharer The FileSharer instance to populate.
     */
    void load_shares_into(FileSharer& sharer);

private:
    std::string state_file_path_;
};

#endif //P2P_SHARE_STATE_HPP
