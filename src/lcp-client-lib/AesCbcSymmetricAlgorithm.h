//
//  Created by Artem Brazhnikov on 11/15.
//  Copyright (c) 2014 Readium Foundation and/or its licensees. All rights reserved.
//
//

#ifndef __AES_CBC_SYMMETRIC_ALGORITHM_H__
#define __AES_CBC_SYMMETRIC_ALGORITHM_H__

#include "CryptoAlgorithmInterfaces.h"
#include "IncludeMacros.h"
#include "LcpTypedefs.h"
#include "NonCopyable.h"

CRYPTOPP_INCLUDE_START
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
CRYPTOPP_INCLUDE_END

namespace lcp
{
    class AesCbcSymmetricAlgorithm : public ISymmetricAlgorithm, public NonCopyable
    {
    public:
        enum KeySize
        {
            Key128,
            Key192,
            Key256
        };

    public:
        explicit AesCbcSymmetricAlgorithm(
            const KeyType & key,
            KeySize keySize = Key256
            );

        virtual std::string Name() const;

        virtual std::string Decrypt(
            const std::string & encryptedDataBase64
            );

        virtual size_t Decrypt(
            const unsigned char * data,
            size_t dataLength,
            unsigned char * decryptedData,
            size_t decryptedDataLength
            );

        virtual void Decrypt(
            IDecryptionContext * context,
            IReadableStream * stream,
            unsigned char * decryptedData,
            size_t decryptedDataLength
            );

        size_t PlainTextSize(IReadableStream * stream);

    private:
        size_t InnerDecrypt(
            const unsigned char * data,
            size_t dataLength,
            unsigned char * decryptedData,
            size_t decryptedDataLength,
            CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme padding
            );

        KeyType BuildIV(
            const unsigned char * data,
            size_t dataLength,
            const unsigned char ** cipherData,
            size_t * cipherSize
            );

    private:
        KeySize m_keySize;
        KeyType m_key;
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption m_decryptor;
    };
}

#endif //__AES_CBC_SYMMETRIC_ALGORITHM_H__
