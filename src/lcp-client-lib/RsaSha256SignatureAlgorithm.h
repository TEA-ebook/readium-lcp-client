//
//  Created by Artem Brazhnikov on 11/15.
//  Copyright (c) 2014 Readium Foundation and/or its licensees. All rights reserved.
//
//

#ifndef __RSA_SHA256_SIGNATURE_ALGORITHM_H__
#define __RSA_SHA256_SIGNATURE_ALGORITHM_H__

#include "CryptoAlgorithmInterfaces.h"
#include "IncludeMacros.h"
#include "NonCopyable.h"

CRYPTOPP_INCLUDE_START
#include <cryptopp/rsa.h>
CRYPTOPP_INCLUDE_END

namespace lcp
{
    class RsaSha256SignatureAlgorithm : public ISignatureAlgorithm, public NonCopyable
    {
    public:
        explicit RsaSha256SignatureAlgorithm(const KeyType & publicKey);

        virtual std::string Name() const;

        virtual bool VerifySignature(
            const std::string & message,
            const std::string & signatureBase64
            );

        virtual bool VerifySignature(
            const unsigned char * message,
            size_t messageLength,
            const unsigned char * signature,
            size_t signatureLength
            );

    private:
        typedef CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier ThisVerifier;
        CryptoPP::RSA::PublicKey m_publicKey;
    };
}

#endif //__RSA_SHA256_SIGNATURE_ALGORITHM_H__
