#pragma once

namespace Envoy {
namespace Network {

// Types of network related fingerprints
enum class Fingerprint : std::size_t {
  JA3,
  JA3N,
  JA4,
  NumFingerprints,
};

} // namespace Network
} // namespace Envoy