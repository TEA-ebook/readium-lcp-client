//
//  Created by Artem Brazhnikov on 11/15.
//  Copyright (c) 2014 Readium Foundation and/or its licensees. All rights reserved.
//
//

#ifndef __TEST_ACQUISITION_CALLBACK_H__
#define __TEST_ACQUISITION_CALLBACK_H__

#include <iostream>
#include "public/lcp.h"

class TestAcquisitionCallback : public lcp::IAcquisitionCallback
{
public:
    virtual void OnAcquisitionStarted(lcp::IAcquisition * acquisition)
    {
        std::cout << "Acquisition started!" << std::endl;
    }
    virtual void OnAcquisitionProgressed(lcp::IAcquisition * acquisition, float progress)
    {
        std::cout << "\rAcquisition progressed!" << progress;
    }
    virtual void OnAcquisitionCanceled(lcp::IAcquisition * acquisition)
    {
        std::cout << std::endl << "Acquisition canceled!" << std::endl;
    }
    virtual void OnAcquisitionEnded(lcp::IAcquisition * acquisition, lcp::Status result)
    {
        std::cout << std::endl << "Acquisition ended! Status: " << result.Code << " Ext: " << result.Extension << std::endl;
    }
};

#endif //__TEST_ACQUISITION_CALLBACK_H__
