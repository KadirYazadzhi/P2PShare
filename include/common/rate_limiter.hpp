#ifndef P2P_RATE_LIMITER_HPP
#define P2P_RATE_LIMITER_HPP

#include <cstddef>
#include <chrono>
#include <mutex>

class RateLimiter {
public:
    RateLimiter(size_t max_rate_bytes_per_sec);

    // Try to consume bytes. Returns true if successful, false otherwise.
    bool try_consume(size_t bytes);

    // Refill the token bucket based on elapsed time.
    void refill();

    // Get the maximum rate in bytes per second.
    size_t get_max_rate() const;

    // Set a new maximum rate.
    void set_max_rate(size_t new_max_rate);

private:
    size_t max_rate_bytes_per_sec_;
    size_t tokens_in_bucket_;
    std::chrono::steady_clock::time_point last_refill_time_;
    std::mutex mutex_;
};

#endif // P2P_RATE_LIMITER_HPP
