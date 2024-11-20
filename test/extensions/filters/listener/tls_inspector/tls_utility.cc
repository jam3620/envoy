#include "test/extensions/filters/listener/tls_inspector/tls_utility.h"

#include "source/common/common/assert.h"

#include "absl/strings/str_split.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Tls {
namespace Test {

std::vector<uint8_t> generateClientHello(uint16_t tls_min_version, uint16_t tls_max_version,
                                         const std::string& sni_name, const std::string& alpn) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_with_buffers_method()));

  SSL_CTX_set_min_proto_version(ctx.get(), tls_min_version);
  SSL_CTX_set_max_proto_version(ctx.get(), tls_max_version);

  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));

  // Ownership of these is passed to *ssl
  BIO* in = BIO_new(BIO_s_mem());
  BIO* out = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl.get(), in, out);

  SSL_set_connect_state(ssl.get());
  const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
  SSL_set_cipher_list(ssl.get(), PREFERRED_CIPHERS);
  if (!sni_name.empty()) {
    SSL_set_tlsext_host_name(ssl.get(), sni_name.c_str());
  }
  if (!alpn.empty()) {
    SSL_set_alpn_protos(ssl.get(), reinterpret_cast<const uint8_t*>(alpn.data()), alpn.size());
  }
  SSL_do_handshake(ssl.get());
  const uint8_t* data = nullptr;
  size_t data_len = 0;
  BIO_mem_contents(out, &data, &data_len);
  ASSERT(data_len > 0);
  std::vector<uint8_t> buf(data, data + data_len);
  return buf;
}

std::vector<uint8_t> parseCiphersForJAFingerprint(const std::string& ciphers_str, char delimiter,
                                                  int base) {
  std::vector<std::string> values = absl::StrSplit(ciphers_str, delimiter);
  std::vector<uint8_t> ciphers;
  for (const std::string& v : values) {
    uint16_t cipher = std::stoi(v, nullptr, base);
    ciphers.push_back((cipher & 0xff00) >> 8);
    ciphers.push_back(cipher & 0xff);
  }

  return ciphers;
}

std::vector<uint8_t> generateSupportedVersionsExtension(const std::vector<uint16_t>& versions) {
  std::uint8_t list_length = (versions.size() * sizeof(uint16_t)) & 0xff;
  std::uint16_t ext_length = list_length + 1;
  std::vector<uint8_t> supported_versions = {// Extension ID 43
                                             0x00, 0x2b,
                                             // length
                                             static_cast<uint8_t>((ext_length & 0xff00) >> 8),
                                             static_cast<uint8_t>(ext_length & 0xff),
                                             // list length
                                             list_length};
  // add on each version
  for (const std::uint16_t v : versions) {
    supported_versions.push_back((v & 0xff00) >> 8);
    supported_versions.push_back(v & 0xff);
  }

  return supported_versions;
}

std::vector<uint8_t> generateServerNameExtension() {
  return {// Extension ID 0
          0x00, 0x00,
          // length
          0x00, 0x16,
          // list length
          0x00, 0x14,
          // hostname type
          0x00,
          // name length
          0x00, 0x11,
          // name (www.envoyproxy.io)
          'w', 'w', 'w', '.', 'e', 'n', 'v', 'o', 'y', 'p', 'r', 'o', 'x', 'y', '.', 'i', 'o'};
}

std::vector<uint8_t> generateAlpnExtension(const std::vector<std::string>& protocols) {
  std::vector<uint8_t> protocols_extension;
  for (const std::string& p : protocols) {
    protocols_extension.emplace_back(p.size() & 0xff);
    for (const char c : p) {
      protocols_extension.emplace_back(c);
    }
  }

  uint16_t list_length = protocols_extension.size() & 0xffff;
  uint16_t ext_length = list_length + 2;
  std::vector<uint8_t> alpn_extension = {
      // Extension ID 16
      0x00, 0x10,
      // length
      static_cast<uint8_t>((ext_length & 0xff00) >> 8), static_cast<uint8_t>(ext_length & 0xff),
      // list length
      static_cast<uint8_t>((list_length & 0xff00) >> 8), static_cast<uint8_t>(list_length & 0xff)};
  alpn_extension.insert(alpn_extension.end(), protocols_extension.begin(),
                        protocols_extension.end());

  return alpn_extension;
}

std::vector<uint8_t> generateSignatureAlgorithms(const std::vector<uint16_t>& algos) {
  uint16_t list_length = (algos.size() * sizeof(uint16_t)) & 0xffff;
  uint16_t ext_length = list_length + 2;
  std::vector<uint8_t> signature_algorithms = {
      // Extension ID 13
      0x00, 0x0d,
      // length
      static_cast<uint8_t>((ext_length & 0xff00) >> 8), static_cast<uint8_t>(ext_length & 0xff),
      // list length
      static_cast<uint8_t>((list_length & 0xff00) >> 8), static_cast<uint8_t>(list_length & 0xff)};

  for (const std::uint16_t a : algos) {
    signature_algorithms.push_back((a & 0xff00) >> 8);
    signature_algorithms.push_back(a & 0xff);
  }

  return signature_algorithms;
}

std::vector<uint8_t>
generateExtensions(const std::string& extension_values, char delimiter, int base,
                   const std::unordered_map<int, std::vector<uint8_t>*>& extension_map) {
  std::vector<std::string> values = absl::StrSplit(extension_values, delimiter, absl::SkipEmpty());
  std::vector<uint8_t> extensions;
  for (const std::string& v : values) {
    int extension_id = std::stoi(v, nullptr, base);
    if (auto search = extension_map.find(extension_id);
        search != extension_map.end() && (*search).second != nullptr) {
      extensions.insert(extensions.end(), (*search).second->begin(), (*search).second->end());
    } else {
      extensions.push_back((extension_id & 0xff00) >> 8);
      extensions.push_back(extension_id & 0xff);
      extensions.push_back(0);
      extensions.push_back(0);
    }
  }

  return extensions;
}

std::vector<uint8_t> generateClientHelloForJATest(uint16_t tls_version,
                                                  const std::vector<uint8_t>& ciphers,
                                                  const std::vector<uint8_t>& extensions) {

  if (tls_version == TLS1_3_VERSION) {
    tls_version = TLS1_2_VERSION;
  }

  std::vector<uint8_t> clienthello = {// client version
                                      static_cast<uint8_t>((tls_version & 0xff00) >> 8),
                                      static_cast<uint8_t>(tls_version & 0xff),
                                      // client random (32 bytes)
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      // session id
                                      0};
  // cipher suite length and ciphers
  uint16_t ciphers_length = ciphers.size();
  clienthello.push_back((ciphers_length & 0xff00) >> 8);
  clienthello.push_back(ciphers_length & 0xff);
  clienthello.insert(std::end(clienthello), std::begin(ciphers), std::end(ciphers));
  // compression methods
  clienthello.push_back(0x01);
  clienthello.push_back(0x00);
  // extension length and extensions
  uint16_t extensions_length = extensions.size();
  clienthello.push_back((extensions_length & 0xff00) >> 8);
  clienthello.push_back(extensions_length & 0xff);
  clienthello.insert(std::end(clienthello), std::begin(extensions), std::end(extensions));

  // headers
  uint32_t clienthello_bytes = clienthello.size();
  uint16_t handshake_bytes = clienthello.size() + 4;
  std::vector<uint8_t> clienthello_message = {
      // record header
      0x16, 0x03, 0x01,
      // handshake bytes
      static_cast<uint8_t>((handshake_bytes & 0xff00) >> 8),
      static_cast<uint8_t>(handshake_bytes & 0xff),
      // handshake header
      0x01,
      // client hello bytes
      static_cast<uint8_t>((clienthello_bytes & 0xff0000) >> 16),
      static_cast<uint8_t>((clienthello_bytes & 0xff00) >> 8),
      static_cast<uint8_t>(clienthello_bytes & 0xff)};
  clienthello_message.insert(std::end(clienthello_message), std::begin(clienthello),
                             std::end(clienthello));

  return clienthello_message;
}

std::vector<uint8_t> generateClientHelloFromJA3Fingerprint(const std::string& ja3_fingerprint) {
  // fingerprint should have this format:
  //  SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
  // Example:
  //   769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
  std::vector<std::string> fingerprint = absl::StrSplit(ja3_fingerprint, ',');
  ASSERT(fingerprint.size() == 5);

  const uint16_t tls_version = std::stoi(fingerprint[0], nullptr);

  std::vector<uint8_t> ciphers = parseCiphersForJAFingerprint(fingerprint[1], '-', 10);

  std::unordered_map<int, std::vector<uint8_t>*> extensions_map;

  // elliptic curves extension
  constexpr uint16_t elliptic_curves_id = 0xa;
  std::vector<std::string> values = absl::StrSplit(fingerprint[3], '-', absl::SkipEmpty());
  uint16_t length = values.size() * 2;
  uint16_t ext_length = length + 2;
  std::vector<uint8_t> elliptic_curves = {(elliptic_curves_id & 0xff00) >> 8,
                                          elliptic_curves_id & 0xff,
                                          static_cast<uint8_t>((ext_length & 0xff00) >> 8),
                                          static_cast<uint8_t>(ext_length & 0xff),
                                          static_cast<uint8_t>((length & 0xff00) >> 8),
                                          static_cast<uint8_t>(length & 0xff)};
  for (const std::string& v : values) {
    uint16_t elliptic_curve = std::stoi(v, nullptr);
    elliptic_curves.push_back((elliptic_curve & 0xff00) >> 8);
    elliptic_curves.push_back(elliptic_curve & 0xff);
  }
  extensions_map[elliptic_curves_id] = &elliptic_curves;

  // elliptic curve point formats extension
  constexpr uint16_t elliptic_curve_point_formats_id = 0xb;
  values = absl::StrSplit(fingerprint[4], '-', absl::SkipEmpty());
  ext_length = values.size() + 1;
  std::vector<uint8_t> elliptic_curve_point_formats = {
      (elliptic_curve_point_formats_id & 0xff00) >> 8, elliptic_curve_point_formats_id & 0xff,
      static_cast<uint8_t>((ext_length & 0xff00) >> 8), static_cast<uint8_t>(ext_length & 0xff),
      static_cast<uint8_t>(values.size())};
  for (const std::string& v : values) {
    uint8_t elliptic_curve_point_format = std::stoi(v, nullptr);
    elliptic_curve_point_formats.push_back(elliptic_curve_point_format);
  }
  extensions_map[elliptic_curve_point_formats_id] = &elliptic_curve_point_formats;

  // server name extension
  constexpr uint16_t server_name_id = 0x0;
  std::vector<uint8_t> server_name = generateServerNameExtension();
  extensions_map[server_name_id] = &server_name;

  // signature algorithms extension
  constexpr uint16_t signature_algorithms_id = 0xd;
  std::vector<uint8_t> signature_algorithms = generateSignatureAlgorithms({0x403});
  extensions_map[signature_algorithms_id] = &signature_algorithms;

  // ALPN extension
  constexpr uint16_t alpn_id = 0x10;
  std::vector<uint8_t> alpn_extension = generateAlpnExtension({"HTTP/1.1"});
  extensions_map[alpn_id] = &alpn_extension;

  std::vector<uint8_t> extensions = generateExtensions(fingerprint[2], '-', 10, extensions_map);

  return generateClientHelloForJATest(tls_version, ciphers, extensions);
}

std::vector<uint8_t> generateClientHelloFromJA4Fingerprint(const std::string& ja4_fingerprint) {
  // fingerprint should have this format:
  //  <header>_<sorted ciphers>_<sorted extensions>_<optional signature algorithms>
  //
  // More details available here:
  //  https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

  std::vector<std::string> fingerprint = absl::StrSplit(ja4_fingerprint, '_');
  ASSERT(fingerprint.size() == 4 || fingerprint.size() == 3);

  // Parse header
  ASSERT(fingerprint[0].length() == 10);
  std::string_view protocol = {fingerprint[0].c_str(), 1};
  std::string_view tls_version = {fingerprint[0].c_str() + 1, 2};
  std::string_view sni = {fingerprint[0].c_str() + 3, 1};
  std::string_view num_cipher_suites = {fingerprint[0].c_str() + 4, 2};
  std::string_view num_extension = {fingerprint[0].c_str() + 6, 2};
  std::string_view first_alpn = {fingerprint[0].c_str() + 8, 2};

  std::vector<uint8_t> ciphers = parseCiphersForJAFingerprint(fingerprint[1], ',', 16);

  std::unordered_map<int, std::vector<uint8_t>*> extensions_map;

  // supported version extension
  const std::unordered_map<std::string_view, uint16_t> version_map{
      {"13", TLS1_3_VERSION}, {"12", TLS1_2_VERSION},  {"11", TLS1_1_VERSION},
      {"10", TLS1_VERSION},   {"s3", SSL3_VERSION},    {"s2", SSL2_VERSION},
      {"d1", DTLS1_VERSION},  {"d2", DTLS1_2_VERSION},
  };
  std::unordered_map<std::string_view, uint16_t>::const_iterator tls_version_pair =
      version_map.find(tls_version);
  ASSERT(tls_version_pair != version_map.end());
  constexpr uint16_t supported_versions_id = 0x2b;
  std::vector<uint8_t> supported_versions =
      generateSupportedVersionsExtension({(*tls_version_pair).second});
  extensions_map[supported_versions_id] = &supported_versions;

  // server name extension
  constexpr uint16_t server_name_id = 0x0;
  std::vector<uint8_t> server_name;
  if (sni == "d") {
    server_name = generateServerNameExtension();
    extensions_map[server_name_id] = &server_name;
  }

  // signature algorithms extension
  std::vector<uint8_t> signature_algorithms;
  if (fingerprint.size() == 4) {
    std::vector<std::string> values = absl::StrSplit(fingerprint[3], ',');
    std::vector<uint16_t> algos;
    for (const std::string& v : values) {
      algos.push_back(std::stoi(v, nullptr, 16));
    }
    constexpr uint16_t signature_algorithms_id = 0xd;
    signature_algorithms = generateSignatureAlgorithms(algos);
    extensions_map[signature_algorithms_id] = &signature_algorithms;
  }

  // ALPN extension
  constexpr uint16_t alpn_id = 0x10;
  std::vector<uint8_t> alpn_extension;
  if (first_alpn != "00") {
    std::vector<std::string> alpn_values;
    if (first_alpn == "h2") {
      alpn_values.push_back("h2");
    } else if (first_alpn == "h1") {
      alpn_values.push_back("http/1.1");
    }
    alpn_extension = generateAlpnExtension(alpn_values);
    extensions_map[alpn_id] = &alpn_extension;
  }

  // psk key exchange modes.  Values do not matter for JA4, just need
  // extension config to be valid.
  constexpr uint16_t pks_key_id = 0x2d;
  std::vector<uint8_t> pks_key_extension = {
      // ID
      0x00,
      0x2d,
      // Length
      0x00,
      0x02,
      // Mode
      0x01,
      0x01,
  };
  extensions_map[pks_key_id] = &pks_key_extension;

  // elliptic curves extension.  Values do not matter for JA4, just need
  // extension config to be valid.
  constexpr uint16_t elliptic_curves_id = 0xa;
  std::vector<uint16_t> values = {0x001d};
  uint16_t length = values.size() * 2;
  uint16_t ext_length = length + 2;
  std::vector<uint8_t> elliptic_curves = {(elliptic_curves_id & 0xff00) >> 8,
                                          elliptic_curves_id & 0xff,
                                          static_cast<uint8_t>((ext_length & 0xff00) >> 8),
                                          static_cast<uint8_t>(ext_length & 0xff),
                                          static_cast<uint8_t>((length & 0xff00) >> 8),
                                          static_cast<uint8_t>(length & 0xff)};
  for (const uint16_t v : values) {
    elliptic_curves.push_back((v & 0xff00) >> 8);
    elliptic_curves.push_back(v & 0xff);
  }
  extensions_map[elliptic_curves_id] = &elliptic_curves;

  std::vector<uint8_t> extensions = generateExtensions(fingerprint[2], ',', 16, extensions_map);

  // Add on SNI and ALPN if they exist.
  // JA4 fingerprint excludes these from the sorted extensions hash.
  for (const uint16_t id : {alpn_id, server_name_id}) {
    if (auto search = extensions_map.find(id);
        search != extensions_map.end() && (*search).second != nullptr) {
      extensions.insert(extensions.begin(), (*search).second->begin(), (*search).second->end());
    }
  }

  return generateClientHelloForJATest((*tls_version_pair).second, ciphers, extensions);
}

} // namespace Test
} // namespace Tls
} // namespace Envoy
