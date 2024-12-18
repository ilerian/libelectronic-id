/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
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

#include "Pkcs11ElectronicID.hpp"

#include "../common.hpp"

#include <map>

#ifdef _WIN32
#undef UNICODE
#include <Shlobj.h>
#include <Shlwapi.h>
#endif

using namespace electronic_id;
using namespace std::string_literals;
namespace fs = std::filesystem;

namespace
{

#ifdef _WIN32
inline auto getKnownFolderPath(REFKNOWNFOLDERID knownFolderId)
{
    PWSTR knownFolder = 0;
    SHGetKnownFolderPath(knownFolderId, 0, nullptr, &knownFolder);
    fs::path path = knownFolder;
    CoTaskMemFree(knownFolder);
    return path;
}

inline auto programFilesPath()
{
    return getKnownFolderPath(FOLDERID_ProgramFiles);
}

inline auto system32Path()
{
    return getKnownFolderPath(FOLDERID_System);
}
#endif

inline fs::path lithuanianPKCS11ModulePath(bool v2)
{
#ifdef _WIN32
    return programFilesPath()
        / (v2 ? L"PWPW/pwpw-card-pkcs11.dll" : L"Softemia/mcard/mcard-pkcs11.dll");
#elif defined(__APPLE__)
    static const std::string_view path1("/Library/PWPW-Card/lib/pwpw-card-pkcs11.so");
    static const std::string_view path2("/Library/mCard/lib/mcard-pkcs11.so");
    return v2 ? path1 : path2;
#else
    static const std::string_view path1("/usr/lib64/pwpw-card-pkcs11.so");
    static const std::string_view path2("/usr/lib/pwpw-card-pkcs11.so");
    static const std::string_view path3("/usr/lib/mcard-pkcs11.so");
    return v2 ? (fs::exists(path1) ? path1 : path2) : path3;
#endif
}

inline fs::path croatianPkcs11ModulePath()
{
#ifdef _WIN32
    return programFilesPath() / L"AKD/eID Middleware/pkcs11/AkdEidPkcs11_64.dll";
#elif defined __APPLE__
    return "/Library/AKD/eID Middleware/pkcs11/libEidPkcs11.so"; // NB! Not tested.
#else // Linux
    return "/usr/lib/akd/eidmiddleware/pkcs11/libEidPkcs11.so";
#endif
}

inline fs::path belgianPkcs11ModulePath()
{
#ifdef _WIN32
    return system32Path() / L"beidpkcs11.dll";
#elif defined __APPLE__
    return "/Library/Belgium Identity "
           "Card/Pkcs11/beid-pkcs11.bundle/Contents/MacOS/libbeidpkcs11.dylib";
#else // Linux
    return "/usr/lib/x86_64-linux-gnu/libbeidpkcs11.so.0";
#endif
}

inline fs::path eTokenPkcs11ModulePath()
{
#ifdef _WIN32
    return system32Path() / L"eToken.dll";
#elif defined __APPLE__
    return "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib";
#else // Linux
    return "/usr/lib/libeTPkcs11.so";
#endif
}

inline fs::path AKISPkcs11ModulePath()
{
#ifdef _WIN32
    return system32Path() / L"akisp11.dll";
#elif defined __APPLE__
    return "/usr/local/lib/libakisp11.dylib";
#else // Linux
    return "/usr/lib/libpkcs11wrapper.so";
#endif
}

inline fs::path ACSPkcs11ModulePath()
{
#ifdef _WIN32
    return system32Path() / L"akisp11.dll";
#elif defined __APPLE__
    return "/usr/local/lib/libacos5pkcs11.dylib";
#else // Linux
    return "/lib/libacospkcs11.so";
#endif
}

const std::map<Pkcs11ElectronicIDType, Pkcs11ElectronicIDModule> SUPPORTED_PKCS11_MODULES {
    // EstEIDIDEMIAV1 configuration is here only for testing,
    // it is not enabled in getElectronicID().
    {Pkcs11ElectronicIDType::EstEIDIDEMIAV1,
     {
         "EstEID IDEMIA v1 (PKCS#11)"s, // name
         ElectronicID::Type::EstEID, // type
         fs::u8path("opensc-pkcs11.so").make_preferred(), // path

         JsonWebSignatureAlgorithm::ES384, // authSignatureAlgorithm
         ELLIPTIC_CURVE_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
         3,
         false,
         false,
     }},
    {Pkcs11ElectronicIDType::LitEIDv2,
     {
         "Lithuanian eID (PKCS#11)"s, // name
         ElectronicID::Type::LitEID, // type
         lithuanianPKCS11ModulePath(true).make_preferred(), // path

         JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
         RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
         -1,
         false,
         false,
     }},
    {Pkcs11ElectronicIDType::LitEIDv3,
     {
         "Lithuanian eID (PKCS#11)"s, // name
         ElectronicID::Type::LitEID, // type
         lithuanianPKCS11ModulePath(false).make_preferred(), // path

         JsonWebSignatureAlgorithm::ES384, // authSignatureAlgorithm
         ELLIPTIC_CURVE_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
         3,
         false,
         false,
     }},
    {Pkcs11ElectronicIDType::HrvEID,
     {
         "Croatian eID (PKCS#11)"s, // name
         ElectronicID::Type::HrvEID, // type
         croatianPkcs11ModulePath().make_preferred(), // path

         JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
         RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
         3,
         true,
         false,
     }},
    {Pkcs11ElectronicIDType::BelEIDV1_7,
     {
         "Belgian eID v1.7 (PKCS#11)"s, // name
         ElectronicID::Type::BelEIDV1_7, // type
         belgianPkcs11ModulePath().make_preferred(), // path

         JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
         RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
         3,
         true,
         true,
     }},
    // https://github.com/Fedict/eid-mw/wiki/Applet-1.8
    {Pkcs11ElectronicIDType::BelEIDV1_8,
     {
         "Belgian eID v1.8 (PKCS#11)"s, // name
         ElectronicID::Type::BelEIDV1_8, // type
         belgianPkcs11ModulePath().make_preferred(), // path

         JsonWebSignatureAlgorithm::ES384, // authSignatureAlgorithm
         ELLIPTIC_CURVE_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
         3,
         true,
         true,
     }},
     {Pkcs11ElectronicIDType::AKIS_1,
      {
          "AKIS v_1 (PKCS#11)"s, // name
          ElectronicID::Type::AKIS_1, // type
          AKISPkcs11ModulePath().make_preferred(), // path

          JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
          RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
          3,
          false,
          false,
      }},
      {Pkcs11ElectronicIDType::AKIS_2,
        {
            "AKIS v_2 (PKCS#11)"s, // name
            ElectronicID::Type::AKIS_2, // type
            AKISPkcs11ModulePath().make_preferred(), // path

            JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
            RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
            3,
            false,
          false,
        }},


      {Pkcs11ElectronicIDType::AKIS_3,
          {
              "AKIS v_3 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_3, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_4,
          {
              "AKIS v_4 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_4, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_5,
          {
              "AKIS v_5 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_5, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_6,
          {
              "AKIS v_6 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_6, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_7,
          {
              "AKIS v_7 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_7, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_8,
          {
              "AKIS v_8 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_8, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_9,
          {
              "AKIS v_9 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_9, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_10,
          {
              "AKIS v_10 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_10, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_11,
          {
              "AKIS v_11 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_11, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_12,
          {
              "AKIS v_12 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_12, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_13,
          {
              "AKIS v_13 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_13, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_14,
          {
              "AKIS v_14 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_14, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_15,
          {
              "AKIS v_15 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_15, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_16,
          {
              "AKIS v_16 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_16, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_17,
          {
              "AKIS v_17 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_17, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_18,
          {
              "AKIS v_18 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_18, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_19,
          {
              "AKIS v_19 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_19, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_20,
          {
              "AKIS v_20 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_20, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_21,
          {
              "AKIS v_21 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_21, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
      {Pkcs11ElectronicIDType::AKIS_22,
          {
              "AKIS v_22 (PKCS#11)"s, // name
              ElectronicID::Type::AKIS_22, // type
              AKISPkcs11ModulePath().make_preferred(), // path
              JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
              RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
              3,
              false,
              false,
          }
      },
        {Pkcs11ElectronicIDType::AKIS_23,
         {
             "AKIS v_23 (PKCS#11)"s, // name
             ElectronicID::Type::AKIS_23, // type
             AKISPkcs11ModulePath().make_preferred(), // path
             JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
             RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
             3,
             false,
             false,
         }
        },
        {Pkcs11ElectronicIDType::AKIS_24,
         {
             "AKIS v_24 (PKCS#11)"s, // name
             ElectronicID::Type::AKIS_24, // type
             AKISPkcs11ModulePath().make_preferred(), // path
             JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
             RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
             3,
             false,
             false,
         }
        },
      {Pkcs11ElectronicIDType::eToken_1,
                {
                    "eToken 1 (PKCS#11)"s, // name
                    ElectronicID::Type::eToken_1, // type
                    eTokenPkcs11ModulePath().make_preferred(), // path
                    JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
                    RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
                    3,
                    true,
                    false
                }
        },
      {Pkcs11ElectronicIDType::eToken_2,
              {
                  "eToken 2 (PKCS#11)"s, // name
                  ElectronicID::Type::eToken_2, // type
                  eTokenPkcs11ModulePath().make_preferred(), // path
                  JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
                  RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
                  3,
                  true,
                  false
              }
      },
      {Pkcs11ElectronicIDType::ACS_1,
                {
                    "ACS 1 (PKCS#11)"s, // name
                    ElectronicID::Type::ACS_1, // type
                    ACSPkcs11ModulePath().make_preferred(), // path
                    JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
                    RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
                    3,
                    true,
                    false
                }
        },
};

const Pkcs11ElectronicIDModule& getModule(Pkcs11ElectronicIDType eidType)
{
    try {
        return SUPPORTED_PKCS11_MODULES.at(eidType);
    } catch (const std::out_of_range&) {
        THROW(ProgrammingError,
              "Unknown Pkcs11ElectronicIDType enum value '" + std::to_string(int(eidType)) + "'");
    }
}

} // namespace

Pkcs11ElectronicID::Pkcs11ElectronicID(pcsc_cpp::SmartCard::ptr _card,
                                       Pkcs11ElectronicIDType type) :
    ElectronicID(std::move(_card)),
    module(getModule(type)), manager(PKCS11CardManager::instance(module.path))
{
    bool seenAuthToken = false;
    bool seenSigningToken = false;

    for (const auto& token : manager->tokens()) {
        const auto certType = certificateType(token.cert);
        if (certType.isAuthentication()) {
            authToken = token;
            seenAuthToken = true;
        } else if (certType.isSigning()) {
            signingToken = token;
            seenSigningToken = true;
        }
    }
    if (!(seenAuthToken || seenSigningToken)) {
        THROW(SmartCardChangeRequiredError, "Either authentication or signing token is missing");
    }
}

pcsc_cpp::byte_vector Pkcs11ElectronicID::getCertificate(const CertificateType type) const
{
    return type.isAuthentication() ? authToken.cert : signingToken.cert;
}

ElectronicID::PinMinMaxLength Pkcs11ElectronicID::authPinMinMaxLength() const
{
    return {authToken.minPinLen, authToken.maxPinLen};
}

ElectronicID::PinRetriesRemainingAndMax Pkcs11ElectronicID::authPinRetriesLeft() const
{
    return {authToken.retry, module.retryMax};
}

pcsc_cpp::byte_vector Pkcs11ElectronicID::signWithAuthKey(const pcsc_cpp::byte_vector& pin,
                                                          const pcsc_cpp::byte_vector& hash) const
{
    try {
        validateAuthHashLength(authSignatureAlgorithm(), name(), hash);

        const auto signature =
            manager->sign(authToken, hash, authSignatureAlgorithm().hashAlgorithm(),
                          module.providesExternalPinDialog,
                          reinterpret_cast<const char*>(pin.data()), pin.size());
        return signature.first;
    } catch (const VerifyPinFailed& e) {
        // Catch and rethrow the VerifyPinFailed error with -1 to inform the caller of the special
        // case where the card does not return the remaining retry count. This is arguably a
        // somewhat inelegant workaround caused by module.retryMax not being available inside
        // PKCS11CardManager. We should eventually consider improving this.
        if (e.status() == VerifyPinFailed::Status::RETRY_ALLOWED && module.retryMax == -1) {
            throw VerifyPinFailed(VerifyPinFailed::Status::RETRY_ALLOWED, nullptr, -1);
        }
        throw;
    }
}

ElectronicID::PinMinMaxLength Pkcs11ElectronicID::signingPinMinMaxLength() const
{
    return {signingToken.minPinLen, signingToken.maxPinLen};
}

ElectronicID::PinRetriesRemainingAndMax Pkcs11ElectronicID::signingPinRetriesLeft() const
{
    return {signingToken.retry, module.retryMax};
}

ElectronicID::Signature Pkcs11ElectronicID::signWithSigningKey(const pcsc_cpp::byte_vector& pin,
                                                               const pcsc_cpp::byte_vector& hash,
                                                               const HashAlgorithm hashAlgo) const
{
    try {
        validateSigningHash(*this, hashAlgo, hash);

        // TODO: add step for supported algo detection before sign(), see if () below.
        auto signature =
            manager->sign(signingToken, hash, hashAlgo, module.providesExternalPinDialog,
                          reinterpret_cast<const char*>(pin.data()), pin.size());

        if (!module.supportedSigningAlgorithms.count(signature.second)) {
            THROW(SmartCardChangeRequiredError,
                  "Signature algorithm " + std::string(signature.second) + " is not supported by "
                      + name());
        }

        return signature;
    } catch (const VerifyPinFailed& e) {
        // Same issue as in signWithAuthKey().
        if (e.status() == VerifyPinFailed::Status::RETRY_ALLOWED && module.retryMax == -1) {
            throw VerifyPinFailed(VerifyPinFailed::Status::RETRY_ALLOWED, nullptr, -1);
        }
        throw;
    }
}
