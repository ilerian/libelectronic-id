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

#pragma once

#include "electronic-id/electronic-id.hpp"

#include "PKCS11CardManager.hpp"

namespace electronic_id
{

enum class Pkcs11ElectronicIDType {
    EstEIDIDEMIAV1,
    LitEIDv2,
    LitEIDv3,
    HrvEID,
    BelEIDV1_7,
    BelEIDV1_8,
    AKIS_1,
    AKIS_2,
    AKIS_3,
    AKIS_4,
    AKIS_5,
    AKIS_6,
    AKIS_7,
    AKIS_8,
    AKIS_9,
    AKIS_10,
    AKIS_11,
    AKIS_12,
    AKIS_13,
    AKIS_14,
    AKIS_15,
    AKIS_16,
    AKIS_17,
    AKIS_18,
    AKIS_19,
    AKIS_20,
    AKIS_21,
    AKIS_22,
    AKIS_23,
    AKIS_24,
    eToken_1,
    eToken_2,
    ACS_1,

};

struct Pkcs11ElectronicIDModule
{
    const std::string name;
    const ElectronicID::Type type;
    const std::filesystem::path path;

    const int8_t retryMax;
    const bool allowsUsingLettersAndSpecialCharactersInPin;
    const bool providesExternalPinDialog;
};

class Pkcs11ElectronicID : public ElectronicID
{
public:
    explicit Pkcs11ElectronicID(ElectronicID::Type type);

private:
    bool allowsUsingLettersAndSpecialCharactersInPin() const override
    {
        return module.allowsUsingLettersAndSpecialCharactersInPin;
    }

    bool providesExternalPinDialog() const override { return module.providesExternalPinDialog; }

    byte_vector getCertificate(const CertificateType type) const override;

    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override;
    PinMinMaxLength authPinMinMaxLength() const override;

    PinRetriesRemainingAndMax authPinRetriesLeft() const override;
    byte_vector signWithAuthKey(byte_vector&& pin, const byte_vector& hash) const override;

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override;
    PinMinMaxLength signingPinMinMaxLength() const override;

    PinRetriesRemainingAndMax signingPinRetriesLeft() const override;
    Signature signWithSigningKey(byte_vector&& pin, const byte_vector& hash,
                                 const HashAlgorithm hashAlgo) const override;

    void release() const override;
    std::string name() const override { return module.name; }
    Type type() const override { return module.type; }

    const Pkcs11ElectronicIDModule& module;
    mutable std::shared_ptr<PKCS11CardManager> manager;
    PKCS11CardManager::Token authToken;
    PKCS11CardManager::Token signingToken;
};

} // namespace electronic_id
