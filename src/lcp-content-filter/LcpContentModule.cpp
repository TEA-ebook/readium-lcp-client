//
// Created by clebeaupin on 29/03/16.
//

#if FEATURES_READIUM

#include "IncludeMacros.h"

#include "public/LcpContentModule.h"
#include "public/LcpContentFilter.h"

READIUM_INCLUDE_START
#include <ePub3/container.h>
#include <ePub3/content_module_exception.h>
#include <ePub3/content_module_manager.h>
#include <ePub3/utilities/byte_stream.h>
READIUM_INCLUDE_END

#if DEBUG
#define LOG(msg) std::cout << "LCP: " << msg << std::endl
#else
#define LOG(msg)
#endif

static std::string const LcpLicensePath = "META-INF/license.lcpl";

namespace lcp {
    ePub3::string LcpContentModule::GetModuleName() {
        return ePub3::string("lcp");
    }

    void LcpContentModule::RegisterContentFilters() {

        if (LcpContentModule::lcpLicense == NULL) {
            throw ePub3::ContentModuleException("LcpContentModule::RegisterContentFilters() called before LCP license is obtained from LcpContentModule::ProcessFile()!");
        }
        LcpContentFilter::Register(LcpContentModule::lcpService, LcpContentModule::lcpLicense);
    }

    async_result<ContainerPtr> LcpContentModule::ProcessFile(const ePub3::string &path, ePub3::launch policy) {
        ContainerPtr container = Container::OpenContainerForContentModule(path);

        if(container == nullptr) {
            // Unable to open container
            return make_ready_future<ContainerPtr>(ContainerPtr(nullptr));
        }

        // Search for the lcpl file in META-INF
        bool licenseExists = container->FileExistsAtPath(LcpLicensePath);
        if (!licenseExists) {
            return make_ready_future<ContainerPtr>(ContainerPtr(nullptr));
        }

        // Read lcpl JSON file
        unique_ptr<ePub3::ByteStream> byteStream = container->ReadStreamAtPath(LcpLicensePath);
        if (byteStream == nullptr) {
            throw ePub3::ContentModuleException("Unable to read LCPL license");
        }

        char *buffer = nullptr;
        std::size_t bufferSize = byteStream->ReadAllBytes((void **) &buffer);
        byteStream->Close();

        if (buffer == nullptr) {
            throw ePub3::ContentModuleException("LCPL license is empty");
        }

        std::string licenseJson(buffer, bufferSize);
        free(buffer);

        ILicense* license = nullptr;
        ILicense** licensePTR = &license;

        Status status = LcpContentModule::lcpService->OpenLicense(
                path,
                licenseJson, licensePTR);

        if ((status.Code != StatusCode::ErrorCommonSuccess)
#if !DISABLE_LSD
            && (status.Code != StatusCode::LicenseStatusDocumentStartProcessing)
#endif //!DISABLE_LSD
                ) {
            throw ePub3::ContentModuleException("Unable to initialize LCPL license");
        }

        if ((*licensePTR) == nullptr) {
            throw ePub3::ContentModuleException("Unable to get LCPL license");
        }

#if !DISABLE_LSD
        if (status.Code == StatusCode::LicenseStatusDocumentStartProcessing) {

            // Should be non-blocking, to ensure that the exception below is captured on the app side and the main thread resumes activity to process the next events in the queue
            LcpContentModule::lcpStatusDocumentHandler->process((*licensePTR)); //LcpContentModule::lcpService, path

            // the caller gracefully degrades by interrupting the EPUB opening process (the call to lsdProcessingHandler->process() above will attempt again).
            throw ePub3::ContentModuleExceptionDecryptFlow("LCPL license status document processing...");
        }
#endif //!DISABLE_LSD

        if (!(*licensePTR)->Decrypted()) {

            // Should be non-blocking, to ensure that the exception below is captured on the app side and the main thread resumes activity to process the next events in the queue
            LcpContentModule::lcpCredentialHandler->decrypt((*licensePTR));

            // the caller gracefully degrades by interrupting the EPUB opening process (the call to credentialHandler->decrypt() above will attempt again).
            throw ePub3::ContentModuleExceptionDecryptFlow("LCPL license decrypt needs user passphrase input...");
        }

        // NOTE: LcpContentModule::RegisterContentFilters() needs LcpContentModule::lcpLicense to be set.
        LcpContentModule::lcpLicense = (*licensePTR);

        return make_ready_future<ContainerPtr>(ContainerPtr(container));
    }

    async_result<bool> LcpContentModule::ApproveUserAction(const UserAction &action) {
        async_result<bool> result;
        return result;
    }

    // static
    ILicense *LcpContentModule::lcpLicense = NULL;

    // static
    ILcpService *LcpContentModule::lcpService = NULL;

    // static
    ICredentialHandler *LcpContentModule::lcpCredentialHandler = NULL;
    IStatusDocumentHandler *LcpContentModule::lcpStatusDocumentHandler = NULL;

    void LcpContentModule::Register(ILcpService *const service,
                                    ICredentialHandler * credentialHandler,
                                    IStatusDocumentHandler * statusDocumentHandler) {
        LcpContentModule::lcpService = service;
        LcpContentModule::lcpCredentialHandler = credentialHandler;
        LcpContentModule::lcpStatusDocumentHandler = statusDocumentHandler;
        auto contentModule = std::make_shared<LcpContentModule>();
        ContentModuleManager::Instance()->RegisterContentModule(contentModule, "LcpContentModule");
    }
}

#endif // FEATURES_READIUM
