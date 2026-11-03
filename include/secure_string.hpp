#pragma once

#include <sodium.h>
#include <string>
#include <vector>
#include <cstring>

namespace pw {

/**
 * SecureString - bezpieczny kontener na wrażliwe dane
 * Automatycznie zeruje pamięć przy destrukcji
 */
class SecureString {
public:
    SecureString() = default;
    
    explicit SecureString(const std::string& str) 
        : data_(str.begin(), str.end()) {}
    
    explicit SecureString(const char* str) 
        : data_(str, str + std::strlen(str)) {}
    
    SecureString(const char* str, size_t len) 
        : data_(str, str + len) {}
    
    SecureString(size_t size, char c) 
        : data_(size, c) {}
    
    // Move constructor
    SecureString(SecureString&& other) noexcept 
        : data_(std::move(other.data_)) {
        other.clear();
    }
    
    // Move assignment
    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = std::move(other.data_);
            other.clear();
        }
        return *this;
    }
    
    // Blokada kopiowania
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    
    ~SecureString() {
        clear();
    }
    
    void clear() {
        if (!data_.empty()) {
            sodium_memzero(data_.data(), data_.size());
            data_.clear();
        }
    }
    
    void resize(size_t size) {
        data_.resize(size);
    }
    
    void reserve(size_t size) {
        data_.reserve(size);
    }
    
    void push_back(char c) {
        data_.push_back(c);
    }
    
    char* data() { return data_.data(); }
    const char* data() const { return data_.data(); }
    
    size_t size() const { return data_.size(); }
    size_t length() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    
    char& operator[](size_t i) { return data_[i]; }
    const char& operator[](size_t i) const { return data_[i]; }
    
    std::string to_string() const {
        return std::string(data_.begin(), data_.end());
    }
    
    // Iterators
    auto begin() { return data_.begin(); }
    auto end() { return data_.end(); }
    auto begin() const { return data_.begin(); }
    auto end() const { return data_.end(); }
    
    // Porównanie (constant-time)
    bool equals(const SecureString& other) const {
        if (data_.size() != other.data_.size()) {
            return false;
        }
        return sodium_memcmp(data_.data(), other.data_.data(), data_.size()) == 0;
    }

private:
    std::vector<char> data_;
};

/**
 * SecureBytes - bezpieczny kontener na dane binarne
 */
class SecureBytes {
public:
    SecureBytes() = default;
    
    explicit SecureBytes(size_t size) : data_(size) {}
    
    SecureBytes(const unsigned char* ptr, size_t size) 
        : data_(ptr, ptr + size) {}
    
    // Move
    SecureBytes(SecureBytes&& other) noexcept 
        : data_(std::move(other.data_)) {
        other.clear();
    }
    
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = std::move(other.data_);
            other.clear();
        }
        return *this;
    }
    
    // Blokada kopiowania
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    
    ~SecureBytes() {
        clear();
    }
    
    void clear() {
        if (!data_.empty()) {
            sodium_memzero(data_.data(), data_.size());
            data_.clear();
        }
    }
    
    void resize(size_t size) {
        data_.resize(size);
    }
    
    unsigned char* data() { return data_.data(); }
    const unsigned char* data() const { return data_.data(); }
    
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    
    unsigned char& operator[](size_t i) { return data_[i]; }
    const unsigned char& operator[](size_t i) const { return data_[i]; }
    
    auto begin() { return data_.begin(); }
    auto end() { return data_.end(); }
    auto begin() const { return data_.begin(); }
    auto end() const { return data_.end(); }

private:
    std::vector<unsigned char> data_;
};

} // namespace pw
