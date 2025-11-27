#include "common/rate_limiter.hpp"
#include <chrono>
#include <algorithm> // For std::min
#include <iostream>  // For debugging, consider removing in final version

RateLimiter::RateLimiter(size_t max_rate_bytes_per_sec)
    : max_rate_bytes_per_sec_(max_rate_bytes_per_sec),
      tokens_in_bucket_(max_rate_bytes_per_sec), // Start with a full bucket
      last_refill_time_(std::chrono::steady_clock::now()) {}

bool RateLimiter::try_consume(size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_); // Acquire the lock
    refill(); // Refill tokens before trying to consume

    if (tokens_in_bucket_ >= bytes) {
        tokens_in_bucket_ -= bytes;
        return true;
    }
    return false;
}

void RateLimiter::refill() {
    auto now = std::chrono::steady_clock::now();
    // Calculate time elapsed since last refill
    std::chrono::duration<double> time_elapsed = now - last_refill_time_;
    double seconds_elapsed = time_elapsed.count();

    if (seconds_elapsed > 0) {
        // Calculate tokens to add based on elapsed time and max rate
        size_t tokens_to_add = static_cast<size_t>(seconds_elapsed * max_rate_bytes_per_sec_);
        // Add tokens, ensuring it doesn't exceed the max rate
        tokens_in_bucket_ = std::min(tokens_in_bucket_ + tokens_to_add, max_rate_bytes_per_sec_);
        last_refill_time_ = now; // Update last refill time
    }
}

size_t RateLimiter::get_max_rate() const {
    return max_rate_bytes_per_sec_; // Corrected typo here
}

void RateLimiter::set_max_rate(size_t new_max_rate) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_rate_bytes_per_sec_ = new_max_rate;
    refill(); // Adjust tokens based on new rate
}
