//
//  Created by Artem Brazhnikov on 11/15.
//  Copyright (c) 2014 Readium Foundation and/or its licensees. All rights reserved.
//
//

#include "AlgorithmNames.h"
#include "Sha256HashAlgorithm.h"

namespace lcp
{
    std::string Sha256HashAlgorithm::Name() const
    {
        return AlgorithmNames::Sha256Id;
    }

    size_t Sha256HashAlgorithm::DigestSize() const
    {
        return CryptoPP::SHA256::DIGESTSIZE;
    }

    void Sha256HashAlgorithm::UpdateHash(const std::string & dataStr)
    {
        this->UpdateHash(reinterpret_cast<const unsigned char *>(dataStr.data()), dataStr.size());
    }

    void Sha256HashAlgorithm::UpdateHash(const unsigned char * data, const size_t dataLength)
    {
        m_sha256.Update(data, dataLength);
    }

    KeyType Sha256HashAlgorithm::Hash()
    {
        KeyType hash(CryptoPP::SHA256::DIGESTSIZE);
        m_sha256.Final(hash.data());
        return hash;
    }
}