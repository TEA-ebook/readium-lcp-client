//
//  Created by Artem Brazhnikov on 11/15.
//  Copyright (c) 2014 Readium Foundation and/or its licensees. All rights reserved.
//
//

#ifndef __LINKS_LCP_NODE_H__
#define __LINKS_LCP_NODE_H__

#include <map>
#include <list>
#include "BaseLcpNode.h"
#include "public/ILinks.h"

namespace lcp
{
    class LinksLcpNode : public BaseLcpNode, public ILinks
    {
    public:
        // ILcpNode
        virtual void ParseNode(const rapidjson::Value & parentObject, JsonValueReader * reader);
        virtual Status VerifyNode(ILicense * license, IClientProvider * clientProvider, ICryptoProvider * cryptoProvider);
        virtual Status DecryptNode(ILicense * license, IKeyProvider * keyProvider, ICryptoProvider * cryptoProvider);

    public:
        // ILinks
        virtual IKeyValueIterator<std::string, Link> * Enumerate() const;
        virtual bool Has(const std::string & name) const;
        virtual bool GetLink(const std::string & name, Link & link) const;
        virtual bool HasMany(const std::string & name) const;
        virtual bool GetLinks(const std::string & name, std::vector<Link> & links) const;

    private:
        Link ParseLinkValues(const rapidjson::Value & linkObject, JsonValueReader * reader);

    private:
        typedef std::multimap<std::string, Link> LinksMap;
        typedef LinksMap::const_iterator LinksMapConstIt;
        LinksMap m_linksMultiMap;
    };
}

#endif //__LINKS_LCP_NODE_H__
