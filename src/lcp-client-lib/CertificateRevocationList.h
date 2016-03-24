//
//  Created by Artem Brazhnikov on 11/15.
//  Copyright (c) 2014 Readium Foundation and/or its licensees. All rights reserved.
//
//

#ifndef __CERTIFICATE_REVOCATION_LIST_H__
#define __CERTIFICATE_REVOCATION_LIST_H__

#include <mutex>
#include "ICertificate.h"
#include "NonCopyable.h"

namespace lcp
{
    class CertificateRevocationList : public ICertificateRevocationList, public NonCopyable
    {
    public:
        CertificateRevocationList() = default;
        explicit CertificateRevocationList(const Buffer & crlRaw);
        
        // ICertificateRevocationList
        virtual void UpdateRevocationList(const Buffer & crlRaw);
        virtual bool HasThisUpdateDate() const;
        virtual std::string ThisUpdateDate() const;
        virtual bool HasNextUpdateDate() const;
        virtual std::string NextUpdateDate() const;
        virtual bool SerialNumberRevoked(const std::string & serialNumber) const;
        virtual const StringsSet & RevokedSerialNumbers() const;

    private:
        mutable std::mutex m_sync;
        std::string m_thisUpdate;
        std::string m_nextUpdate;
        StringsSet m_revokedSerialNumbers;
    };
}

#endif //__CERTIFICATE_REVOCATION_LIST_H__
