//
//  CareAuthenticationProcessing.h
//  LCP Client (iOS)
//
//  Created by Daniel Fages on 20/03/2018.
//  Copyright © 2018 Readium. All rights reserved.
//

#import <Foundation/Foundation.h>

@class LCPLicense;
@class LCPService;
@protocol DeviceIdManager;

typedef enum {
    CARE_AUTHENT_OK,
    CARE_AUTHENT_ERROR,
    CARE_AUTHENT_NO_CARE,
    CARE_AUTHENT_NEED_CREDENTIALS
} CARE_AUTHENTICATION_RESULT;

@protocol CareAuthenticationProcessing_Events <NSObject>
- (void) onResult:(CARE_AUTHENTICATION_RESULT)result reason:(NSString *)reason;
@end

@interface CareAuthenticationProcessing : NSObject

- (instancetype)init:(LCPService *)service license:(LCPLicense*)license deviceIdManager:(id<DeviceIdManager>)deviceIdManager;

- (void)setDelegate:(id<CareAuthenticationProcessing_Events>)delegate;

- (void)start;

- (NSString *)getUserkey;

- (BOOL)getShouldRetry;

- (void)continueCareAuthenticationWithCredentials:(NSString *)user password:(NSString *)password;
- (void)continueCareAuthenticationWithToken:(NSString *)token;
@end
