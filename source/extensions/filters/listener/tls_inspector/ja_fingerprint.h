#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {

// Helper classes to store values from TLS ClientHello in a delimited list
class JaList {
public:
  void operator()(uint16_t n);
  const std::string& str() { return string_list_; }

private:
  bool first_{true};
  std::string string_list_;
};

class JaSortedList {
public:
  enum class Format {
    Decimal,
    Hex,
  };

  void operator()(uint16_t n);
  void formatAppend(std::string& s, Format format, char delimiter,
                    std::function<bool(uint16_t)> filter);
  std::size_t size() { return list_.size() <= 99 ? list_.size() : 99; }

protected:
  std::vector<uint16_t> list_;
};

// Helper functions for creating JA4 fingerprint
char ja4Protocol(uint16_t tls_version, bool stream_socket);
std::string_view ja4TlsVersion(uint16_t tls_version);
std::string ja4Alpn(const std::vector<std::string>& protocols);

} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy