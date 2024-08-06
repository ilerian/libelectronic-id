/*
 * Copyright (c) 2020-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "electronic-ids/pcsc/EstEIDIDEMIA.hpp"
#include "electronic-ids/pcsc/FinEID.hpp"
#include "electronic-ids/pcsc/LatEIDIDEMIAv1.hpp"
#include "electronic-ids/pcsc/LatEIDIDEMIAv2.hpp"

#include "electronic-ids/pkcs11/Pkcs11ElectronicID.hpp"

#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include "magic_enum/magic_enum.hpp"

#include <map>
#include <numeric>

using namespace pcsc_cpp;
using namespace electronic_id;
using namespace std::string_literals;

namespace
{

using ElectronicIDConstructor = std::function<ElectronicID::ptr(const Reader&)>;

template <typename T>
constexpr auto constructor(const Reader& reader)
{
    return std::make_unique<T>(reader.connectToCard());
}

template <ElectronicID::Type value>
constexpr auto constructor(const Reader& /*reader*/)
{
    return std::make_unique<Pkcs11ElectronicID>(value);
}

// Supported cards.
const std::map<byte_vector, ElectronicIDConstructor> SUPPORTED_ATRS {
    // EstEID Idemia v1.0
    {{0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45, 0x1f, 0x83, 0x00,
      0x12, 0x23, 0x3f, 0x53, 0x65, 0x49, 0x44, 0x0f, 0x90, 0x00, 0xf1},
     constructor<EstEIDIDEMIAV1>},
    // FinEID v3.0
    {{0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0,
      0x85, 0x03, 0x00, 0xEF, 0x12, 0x00, 0xF6, 0x82, 0x90, 0x00},
     constructor<FinEIDv3>},
    // FinEID v3.1
    {{0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0,
      0x85, 0x04, 0x02, 0x1B, 0x12, 0x00, 0xF6, 0x82, 0x90, 0x00},
     constructor<FinEIDv3>},
    // FinEID v4.0
    {{0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0,
      0x85, 0x05, 0x00, 0x11, 0x12, 0x24, 0x60, 0x82, 0x90, 0x00},
     constructor<FinEIDv4>},
    // LatEID Idemia v1.0
    {{0x3b, 0xdd, 0x18, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x90, 0x4c, 0x41,
      0x54, 0x56, 0x49, 0x41, 0x2d, 0x65, 0x49, 0x44, 0x90, 0x00, 0x8c},
     constructor<LatEIDIDEMIAV1>},
    // LatEID Idemia v2.0
    {{0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45, 0x1f, 0x83, 0x00,
      0x12, 0x42, 0x8f, 0x53, 0x65, 0x49, 0x44, 0x0f, 0x90, 0x00, 0x20},
     constructor<LatEIDIDEMIAV2>},
    // LitEID
    {{0x3B, 0x9D, 0x18, 0x81, 0x31, 0xFC, 0x35, 0x80, 0x31, 0xC0, 0x69,
      0x4D, 0x54, 0x43, 0x4F, 0x53, 0x73, 0x02, 0x05, 0x05, 0xD3},
     constructor<ElectronicID::Type::LitEID>},
    // LitEID v2.0
    {{0x3B, 0x9D, 0x18, 0x81, 0x31, 0xFC, 0x35, 0x80, 0x31, 0xC0, 0x69,
      0x4D, 0x54, 0x43, 0x4F, 0x53, 0x73, 0x02, 0x06, 0x04, 0xD1},
     constructor<ElectronicID::Type::LitEID>},
    // HrvEID
    {{0x3b, 0xff, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x00, 0x31, 0xb9, 0x64,
      0x04, 0x44, 0xec, 0xc1, 0x73, 0x94, 0x01, 0x80, 0x82, 0x90, 0x00, 0x12},
     constructor<ElectronicID::Type::HrvEID>},
    // BelEID
    {{0x3b, 0x98, 0x13, 0x40, 0x0a, 0xa5, 0x03, 0x01, 0x01, 0x01, 0xad, 0x13, 0x11},
     constructor<ElectronicID::Type::BelEID>},
    // BelEID
    {{0x3B, 0x98, 0x94, 0x40, 0x0A, 0xA5, 0x03, 0x01, 0x01, 0x01, 0xAD, 0x13, 0x10},
     constructor<ElectronicID::Type::BelEID>},
    // BelEID
    {{0x3B, 0x98, 0x94, 0x40, 0xFF, 0xA5, 0x03, 0x01, 0x01, 0x01, 0xAD, 0x13, 0x10},
     constructor<ElectronicID::Type::BelEID>},
    // BelEID - https://github.com/Fedict/eid-mw/wiki/Applet-1.8
    {{0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0x80, 0x65, 0xb0,
      0x85, 0x04, 0x01, 0x20, 0x12, 0x0f, 0xff, 0x82, 0x90, 0x00},
     constructor<ElectronicID::Type::BelEID>},
    // CzeEID
    {{0x3b, 0x7e, 0x94, 0x00, 0x00, 0x80, 0x25, 0xd2, 0x03, 0x10, 0x01, 0x00, 0x56, 0x00, 0x00,
      0x00, 0x02, 0x02, 0x00},
     constructor<ElectronicID::Type::CzeEID>},
};

inline std::string byteVectorToHexString(const byte_vector& bytes)
{
    std::ostringstream hexStringBuilder;

    hexStringBuilder << std::setfill('0') << std::hex;

    for (const auto byte : bytes) {
        hexStringBuilder << std::setw(2) << static_cast<short>(byte);
    }

    return hexStringBuilder.str();
}

const auto SUPPORTED_ALGORITHMS = std::map<std::string, HashAlgorithm> {
    {"SHA-224"s, HashAlgorithm::SHA224},    {"SHA-256"s, HashAlgorithm::SHA256},
    {"SHA-384"s, HashAlgorithm::SHA384},    {"SHA-512"s, HashAlgorithm::SHA512},
    {"SHA3-224"s, HashAlgorithm::SHA3_224}, {"SHA3-256"s, HashAlgorithm::SHA3_256},
    {"SHA3-384"s, HashAlgorithm::SHA3_384}, {"SHA3-512"s, HashAlgorithm::SHA3_512},
};

} // namespace

namespace electronic_id
{

bool isCardSupported(const pcsc_cpp::byte_vector& atr)
{
    return SUPPORTED_ATRS.contains(atr);
}

ElectronicID::ptr getElectronicID(const pcsc_cpp::Reader& reader)
{
    try {
        const auto& eidConstructor = SUPPORTED_ATRS.at(reader.cardAtr);
        return eidConstructor(reader);
    } catch (const std::out_of_range&) {
        // It should be verified that the card is supported with isCardSupported() before
        // calling getElectronicID(), so it is a programming error if out_of_range occurs here.
        THROW(ProgrammingError,
              "Card with ATR '" + byteVectorToHexString(reader.cardAtr) + "' is not supported");
    }
}

bool ElectronicID::isSupportedSigningHashAlgorithm(const HashAlgorithm hashAlgo) const
{
    const auto& supported = supportedSigningAlgorithms();
    return std::find(supported.cbegin(), supported.cend(), hashAlgo) != supported.cend();
}

AutoSelectFailed::AutoSelectFailed(Reason r) :
    Error(std::string("Auto-select card failed, reason: ") + std::string(magic_enum::enum_name(r))),
    _reason(r)
{
}

VerifyPinFailed::VerifyPinFailed(const Status s, const observer_ptr<pcsc_cpp::ResponseApdu> ra,
                                 const int8_t r) :
    Error(std::string("Verify PIN failed, status: ") + std::string(magic_enum::enum_name(s))
          + (ra ? ", response: " + pcsc_cpp::bytes2hexstr(ra->toBytes()) : "")),
    _status(s), _retries(r)
{
}

HashAlgorithm::HashAlgorithm(const std::string& algoName)
{
    if (!SUPPORTED_ALGORITHMS.contains(algoName)) {
        THROW(ArgumentFatalError,
              "Hash algorithm is not valid, supported algorithms are "
                  + allSupportedAlgorithmNames());
    }
    value = SUPPORTED_ALGORITHMS.at(algoName);
}

HashAlgorithm::operator std::string() const
{
    const auto algoNameValuePair =
        std::find_if(SUPPORTED_ALGORITHMS.cbegin(), SUPPORTED_ALGORITHMS.cend(),
                     [this](const auto& pair) { return pair.second == value; });
    return algoNameValuePair != SUPPORTED_ALGORITHMS.cend() ? algoNameValuePair->first : "UNKNOWN";
}

std::string HashAlgorithm::allSupportedAlgorithmNames()
{
    static const auto SUPPORTED_ALGORITHM_NAMES = std::accumulate(
        std::next(SUPPORTED_ALGORITHMS.begin()), SUPPORTED_ALGORITHMS.end(),
        std::string(SUPPORTED_ALGORITHMS.begin()->first),
        [](auto result, const auto& value) { return result + ", "s + std::string(value.first); });
    return SUPPORTED_ALGORITHM_NAMES;
}

pcsc_cpp::byte_vector HashAlgorithm::rsaOID(const HashAlgorithmEnum hash)
{
    switch (hash) {
    case HashAlgorithm::SHA224:
        return {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
    case HashAlgorithm::SHA256:
        return {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    case HashAlgorithm::SHA384:
        return {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    case HashAlgorithm::SHA512:
        return {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
    case HashAlgorithm::SHA3_224:
        return {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c};
    case HashAlgorithm::SHA3_256:
        return {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20};
    case HashAlgorithm::SHA3_384:
        return {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30};
    case HashAlgorithm::SHA3_512:
        return {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x0A, 0x05, 0x00, 0x04, 0x40};
    default:
        THROW(ArgumentFatalError, "No OID for algorithm " + std::string(HashAlgorithm(hash)));
    }
}

CertificateType::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

JsonWebSignatureAlgorithm::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

SignatureAlgorithm::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

} // namespace electronic_id
