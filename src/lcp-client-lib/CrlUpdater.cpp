//
//  Created by Artem Brazhnikov on 11/15.
//  Copyright (c) 2014 Readium Foundation and/or its licensees. All rights reserved.
//
//

#include <algorithm>
#include <iterator>
#include <thread>
#include "CrlUpdater.h"
#include "SimpleMemoryWritableStream.h"
#include "DownloadInMemoryRequest.h"
#include "DateTime.h"
#include "ThreadTimer.h"

namespace lcp
{
    const int CrlUpdater::TenMinutesPeriod = 1000 * 60 * 10;
    
    CrlUpdater::CrlUpdater(
        INetProvider * netProvider,
        ICertificateRevocationList * revocationList,
        ThreadTimer * threadTimer,
        const std::string & defaultCrlUrl
        )
        : m_requestRunning(false)
        , m_netProvider(netProvider)
        , m_revocationList(revocationList)
        , m_threadTimer(threadTimer)
        , m_currentRequestStatus(Status(StatusCode::ErrorCommonSuccess))
    {
        if (!defaultCrlUrl.empty())
        {
            m_crlUrls.push_back(defaultCrlUrl);
        }
    }

    void CrlUpdater::UpdateCrlUrls(ICrlDistributionPoints * distributionPoints)
    {
        std::unique_lock<std::mutex> locker(m_downloadSync);

        if (distributionPoints != nullptr && distributionPoints->HasCrlDistributionPoints())
        {
            const StringsList & newUrls = distributionPoints->CrlDistributionPointUrls();
            std::copy_if(
                newUrls.begin(), newUrls.end(),
                std::back_inserter(m_crlUrls),
                [&](const std::string & val) { return (std::find(m_crlUrls.begin(), m_crlUrls.end(), val) == m_crlUrls.end()); }
            );
        }
    }

    bool CrlUpdater::ContainsUrl(const std::string & url)
    {
        std::unique_lock<std::mutex> locker(m_downloadSync);
        return (std::find(m_crlUrls.begin(), m_crlUrls.end(), url) != m_crlUrls.end());
    }

    bool CrlUpdater::ContainsAnyUrl() const
    {
        std::unique_lock<std::mutex> locker(m_downloadSync);
        return !m_crlUrls.empty();
    }

    void CrlUpdater::Update()
    {
        std::unique_lock<std::mutex> locker(m_downloadSync);
        
        // If the list will be changed, it won't affect current update
        StringsList curUrls = m_crlUrls;
        m_currentRequestStatus = Status(StatusCode::ErrorNetworkingRequestFailed);

        for (auto const & url : curUrls)
        {
            this->Download(url);
            m_conditionDownload.wait(locker, [&]() { return !m_requestRunning; });

            if (Status::IsSuccess(m_currentRequestStatus) || m_downloadRequest->Canceled())
            {
                break;
            }
        }
    }

    void CrlUpdater::Cancel()
    {
        std::unique_lock<std::mutex> locker(m_downloadSync);
        if (m_downloadRequest.get() != nullptr)
        {
            m_downloadRequest->SetCanceled(true);
        }
    }

    void CrlUpdater::Download(const std::string & url)
    {
        m_crlStream.reset(new SimpleMemoryWritableStream());
        m_downloadRequest.reset(new DownloadInMemoryRequest(url, m_crlStream.get()));
        m_netProvider->StartDownloadRequest(m_downloadRequest.get(), this);
        m_requestRunning = true;
    }

    void CrlUpdater::OnRequestStarted(INetRequest * request)
    {
    }

    void CrlUpdater::OnRequestProgressed(INetRequest * request, float progress)
    {
    }

    void CrlUpdater::OnRequestCanceled(INetRequest * request)
    {
        std::unique_lock<std::mutex> locker(m_downloadSync);
        m_requestRunning = false;
        m_conditionDownload.notify_one();
    }

    void CrlUpdater::OnRequestEnded(INetRequest * request, Status result)
    {
        try
        {
            std::unique_lock<std::mutex> locker(m_downloadSync);
            if (Status::IsSuccess(result))
            {
                m_revocationList->UpdateRevocationList(m_crlStream->Buffer());
                this->ResetNextUpdate();
            }
            m_currentRequestStatus = result;
            m_requestRunning = false;
            m_conditionDownload.notify_one();
        }
        catch (const std::exception & ex)
        {
            m_currentRequestStatus = Status(StatusCode::ErrorNetworkingRequestFailed, ex.what());
        }
    }

    void CrlUpdater::ResetNextUpdate()
    {
        if (m_revocationList->HasNextUpdateDate())
        {
            DateTime nextUpdate(m_revocationList->NextUpdateDate());
            if (nextUpdate > DateTime::Now())
            {
                m_threadTimer->SetUsage(ThreadTimer::TimePointUsage);
                m_threadTimer->SetTimePoint(ThreadTimer::ClockType::from_time_t(nextUpdate.ToTime()));
            }
            else
            {
                m_threadTimer->SetUsage(ThreadTimer::DurationUsage);
                m_threadTimer->SetDuration(ThreadTimer::DurationType(TenMinutesPeriod));
            }
        }
        else
        {
            m_threadTimer->SetUsage(ThreadTimer::DurationUsage);
            m_threadTimer->SetDuration(ThreadTimer::DurationType(TenMinutesPeriod));
        }
        m_threadTimer->SetAutoReset(true);
    }
}