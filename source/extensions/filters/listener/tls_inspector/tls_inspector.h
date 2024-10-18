#pragma once

#include "envoy/event/file_event.h"
#include "envoy/event/timer.h"
#include "envoy/extensions/filters/listener/tls_inspector/v3/tls_inspector.pb.h"
#include "envoy/network/filter.h"
#include "envoy/network/fingerprint.h"
#include "envoy/stats/histogram.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {

/**
 * All stats for the TLS inspector. @see stats_macros.h
 */
#define ALL_TLS_INSPECTOR_STATS(COUNTER, HISTOGRAM)                                                \
  COUNTER(client_hello_too_large)                                                                  \
  COUNTER(tls_found)                                                                               \
  COUNTER(tls_not_found)                                                                           \
  COUNTER(alpn_found)                                                                              \
  COUNTER(alpn_not_found)                                                                          \
  COUNTER(sni_found)                                                                               \
  COUNTER(sni_not_found)                                                                           \
  HISTOGRAM(bytes_processed, Bytes)

/**
 * Definition of all stats for the TLS inspector. @see stats_macros.h
 */
struct TlsInspectorStats {
  ALL_TLS_INSPECTOR_STATS(GENERATE_COUNTER_STRUCT, GENERATE_HISTOGRAM_STRUCT)
};

enum class ParseState {
  // Parse result is out. It could be tls or not.
  Done,
  // Parser expects more data.
  Continue,
  // Parser reports unrecoverable error.
  Error
};

/**
 * Global configuration for TLS inspector.
 */
class Config {
public:
  Config(Stats::Scope& scope,
         const envoy::extensions::filters::listener::tls_inspector::v3::TlsInspector& proto_config,
         uint32_t max_client_hello_size = TLS_MAX_CLIENT_HELLO);

  const TlsInspectorStats& stats() const { return stats_; }
  bssl::UniquePtr<SSL> newSsl();
  void enableFingerprint(Network::Fingerprint f) {
    if (f >= Network::Fingerprint::NumFingerprints) {
      return;
    }
    fingerprints_[static_cast<std::underlying_type_t<Network::Fingerprint>>(f)] = true;
  }
  bool fingerprintEnabled(Network::Fingerprint f) const {
    if (f >= Network::Fingerprint::NumFingerprints) {
      return false;
    }
    return fingerprints_[static_cast<std::underlying_type_t<Network::Fingerprint>>(f)];
  }
  uint32_t maxClientHelloSize() const { return max_client_hello_size_; }
  uint32_t initialReadBufferSize() const { return initial_read_buffer_size_; }

  static constexpr size_t TLS_MAX_CLIENT_HELLO = 64 * 1024;
  static const unsigned TLS_MIN_SUPPORTED_VERSION;
  static const unsigned TLS_MAX_SUPPORTED_VERSION;

private:
  TlsInspectorStats stats_;
  bssl::UniquePtr<SSL_CTX> ssl_ctx_;
  std::array<bool, static_cast<std::underlying_type_t<Network::Fingerprint>>(
                       Network::Fingerprint::NumFingerprints)>
      fingerprints_;
  const uint32_t max_client_hello_size_;
  const uint32_t initial_read_buffer_size_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * TLS inspector listener filter.
 */
class Filter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Filter(const ConfigSharedPtr& config);

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override;
  size_t maxReadBytes() const override { return requested_read_bytes_; }

private:
  ParseState parseClientHello(const void* data, size_t len, uint64_t bytes_already_processed);
  ParseState onRead();
  void onALPN(const unsigned char* data, unsigned int len);
  void onServername(absl::string_view name);
  void setFingerprint(Network::Fingerprint type, const std::string& fingerprint);
  void createFingerprints(const SSL_CLIENT_HELLO* ssl_client_hello);
  uint32_t maxConfigReadBytes() const { return config_->maxClientHelloSize(); }

  ConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{};

  bssl::UniquePtr<SSL> ssl_;
  uint64_t read_{0};
  bool alpn_found_{false};
  bool clienthello_success_{false};
  // We dynamically adjust the number of bytes requested by the filter up to the
  // maxConfigReadBytes.
  uint32_t requested_read_bytes_;

  // Allows callbacks on the SSL_CTX to set fields in this class.
  friend class Config;
};

} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
