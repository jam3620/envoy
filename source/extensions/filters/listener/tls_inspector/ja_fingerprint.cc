#include "source/extensions/filters/listener/tls_inspector/ja_fingerprint.h"

#include <algorithm>

#include "openssl/ssl.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {

void JaList::operator()(uint16_t n) {
  if (!first_) {
    absl::StrAppend(&string_list_, "-");
  }
  absl::StrAppendFormat(&string_list_, "%d", n);
  first_ = false;
}

void JaSortedList::operator()(uint16_t n) { list_.push_back(n); }

void JaSortedList::formatAppend(std::string& s, Format format, char delimiter,
                                std::function<bool(uint16_t)> filter) {
  std::sort(list_.begin(), list_.end());
  bool first = true;
  for (uint16_t n : list_) {
    if (nullptr != filter && filter(n)) {
      continue;
    }

    if (!first) {
      absl::StrAppendFormat(&s, "%c", delimiter);
    }

    switch (format) {
    case Format::Hex:
      absl::StrAppendFormat(&s, "%04x", n);
      break;
    default:
      absl::StrAppendFormat(&s, "%d", n);
    }

    first = false;
  }
}

char ja4Protocol(uint16_t tls_version, bool stream_socket) {
  if (tls_version == DTLS1_VERSION || tls_version == DTLS1_2_VERSION) {
    return 'd';
  }

  return stream_socket ? 't' : 'q';
}

std::string_view ja4TlsVersion(uint16_t tls_version) {
  switch (tls_version) {
  case TLS1_3_VERSION:
    return "13";
  case TLS1_2_VERSION:
    return "12";
  case TLS1_1_VERSION:
    return "11";
  case TLS1_VERSION:
    return "10";
  case SSL3_VERSION:
    return "s3";
  case SSL2_VERSION:
    return "s2";
  case DTLS1_VERSION:
    return "d1";
  case DTLS1_2_VERSION:
    return "d2";
  }

  return "00";
}

char alpnValue(char c, bool first) {
  if (std::isalnum(c)) {
    return c;
  }

  std::string hex = absl::StrFormat("%02x", c);
  return first ? hex[0] : hex[1];
}

std::string ja4Alpn(const std::vector<std::string>& protocols) {
  if (protocols.empty() || protocols.front().empty()) {
    return "00";
  }

  return absl::StrFormat("%c%c", alpnValue(protocols[0].front(), true),
                         alpnValue(protocols[0].back(), false));
}

} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy