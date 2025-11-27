#include "common/logger.hpp"

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

Logger::~Logger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void Logger::init(const std::string& filename) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_.is_open()) {
        log_file_.close();
    }
    log_file_.open(filename, std::ios::app);
}

void Logger::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string timestamp = get_timestamp();
    std::string level_str = level_to_string(level);
    
    // Construct log line
    std::stringstream ss;
    ss << "[" << timestamp << "] [" << level_str << "] " << message << "\n";
    std::string log_line = ss.str();

    // Write to file
    if (log_file_.is_open()) {
        log_file_ << log_line;
        log_file_.flush();
    }

    // Write to console (colored)
    std::string color_code;
    switch(level) {
        case LogLevel::INFO:    color_code = "\033[32m"; break; // Green
        case LogLevel::WARNING: color_code = "\033[33m"; break; // Yellow
        case LogLevel::ERROR:   color_code = "\033[31m"; break; // Red
        case LogLevel::DEBUG:   color_code = "\033[36m"; break; // Cyan
    }
    std::cout << color_code << log_line << "\033[0m";
}

std::string Logger::level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::DEBUG: return "DEBUG";
        default: return "UNKNOWN";
    }
}

std::string Logger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
    return ss.str();
}
