#ifndef P2P_LOGGER_HPP
#define P2P_LOGGER_HPP

#include <string>
#include <fstream>
#include <mutex>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>

enum class LogLevel {
    INFO,
    WARNING,
    ERROR,
    DEBUG
};

class Logger {
public:
    static Logger& instance();

    void init(const std::string& filename);
    void log(LogLevel level, const std::string& message);

    // Helper for easy logging
    template<typename... Args>
    void log_args(LogLevel level, Args... args) {
        std::stringstream ss;
        (ss << ... << args);
        log(level, ss.str());
    }

private:
    Logger() = default;
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::ofstream log_file_;
    std::mutex mutex_;
    
    std::string level_to_string(LogLevel level);
    std::string get_timestamp();
};

// Global macros for easier usage
#define LOG_INFO(...) Logger::instance().log_args(LogLevel::INFO, __VA_ARGS__)
#define LOG_WARN(...) Logger::instance().log_args(LogLevel::WARNING, __VA_ARGS__)
#define LOG_ERR(...)  Logger::instance().log_args(LogLevel::ERROR, __VA_ARGS__)
#define LOG_DEBUG(...) Logger::instance().log_args(LogLevel::DEBUG, __VA_ARGS__)

#endif // P2P_LOGGER_HPP
