//
//  CareAuthenticationProcessing.m
//  LCP Client (iOS)
//
//  Created by Daniel Fages on 20/03/2018.
//  Copyright © 2018 Readium. All rights reserved.
//

#import "CareAuthenticationProcessing.h"

#import "LCPStatusDocumentProcessing.h"

#import "ILicense.h"
#import "LCPLicense.h"

#import "ILcpService.h"
#import "LCPService.h"

#import "ILinks.h"

@interface CareAuthenticationProcessing () <NSURLSessionDataDelegate> {
}
@end

@implementation CareAuthenticationProcessing {
@private
    LCPService * _service;
    NSString * _epubPath;
    LCPLicense * _license;
    id<DeviceIdManager> _deviceIDManager;
    id<CareAuthenticationProcessing_Events> _delegate;
    NSString * _authentication_link;
    NSString * _userkey;
    BOOL _shouldRetry;
    
    bool _wasCancelled;
    //id<StatusDocumentProcessingListener> _statusDocumentProcessingListener;
    
    //NSString * _statusDocument_ID;
    //NSString * _statusDocument_STATUS; // ready, active, revoked, returned, cancelled, expired
    //NSString * _statusDocument_MESSAGE; // localized as per HTTP Accept-Language
    //NSString * _statusDocument_UPDATED_LICENSE; //ISO 8601 time and date
    //NSString * _statusDocument_UPDATED_STATUS; //ISO 8601 time and date
    //StatusDocumentLink* _statusDocument_LINK_LICENSE; // HTTP GET URL, no-template
    //StatusDocumentLink* _statusDocument_LINK_REGISTER;
    //StatusDocumentLink* _statusDocument_LINK_RETURN;
    //StatusDocumentLink* _statusDocument_LINK_RENEW;
    //NSString * _statusDocument_POTENTIAL_RIGHTS_END; // ISO 8601 time and date
    
    //NSMutableData *_data_TASK_DESCRIPTION_LCP_LSD_FETCH;
    //NSMutableData *_data_TASK_DESCRIPTION_LCP_LSD_REGISTER;
    //NSMutableData *_data_TASK_DESCRIPTION_LCP_FETCH;
    //NSMutableData *_data_TASK_DESCRIPTION_LCP_LSD_RETURN;
    //NSMutableData *_data_TASK_DESCRIPTION_LCP_LSD_RENEW;
    NSMutableData *_data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST;
    NSMutableData *_data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST;
    
    //DoneCallback _doneCallback_registerDevice;
    //DoneCallback _doneCallback_fetchAndInjectUpdatedLicense;
    //DoneCallback _doneCallback_doReturn;
    //DoneCallback _doneCallback_doRenew;
    
    bool _isInitialized;
}

NSString* TASK_DESCRIPTION_CARE_TOKEN_REQUEST = @"CARE_TOKEN_REQUEST";
NSString* TASK_DESCRIPTION_CARE_RESOURCE_REQUEST = @"CARE_RESOURCE_REQUEST";

- (instancetype)init:(LCPService *)service epubPath:(NSString *)epubPath license:(LCPLicense*)license deviceIdManager:(id<DeviceIdManager>)deviceIdManager
{
    self = [super init];
    if (self) {
        _service = service;
        _epubPath = epubPath;
        _license = license;
        _deviceIDManager = deviceIdManager;
        
        _wasCancelled = false;
        //_statusDocumentProcessingListener = nil;
        
        //_statusDocument_ID = @"";
        //_statusDocument_STATUS = @"";
        //_statusDocument_MESSAGE = @"";
        //_statusDocument_UPDATED_LICENSE = @"";
        //_statusDocument_UPDATED_STATUS = @"";
        //_statusDocument_LINK_LICENSE = nil;
        //_statusDocument_LINK_REGISTER = nil;
        //_statusDocument_LINK_RETURN = nil;
        //_statusDocument_LINK_RENEW = nil;
        //_statusDocument_POTENTIAL_RIGHTS_END = @"";
        
        //_data_TASK_DESCRIPTION_LCP_LSD_FETCH = nil;
        //_data_TASK_DESCRIPTION_LCP_LSD_REGISTER = nil;
        //_data_TASK_DESCRIPTION_LCP_FETCH = nil;
        _data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST = nil;
        _data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST = nil;
    }
    
    return self;
}

- (void)setDelegate:(id<CareAuthenticationProcessing_Events>)delegate {
    _delegate = delegate;
}

-(void) start {
    NSLog(@"CareAuthenticationProcessing: start");
    _shouldRetry = false;
    NSString *authentication_link = [_license linkAuthentication];
    NSLog(@"CareAuthenticationProcessing: authentication link:%@", authentication_link);
    
    if ([authentication_link length] <= 0) {
        _shouldRetry = false;
        if (_delegate != nil)
            [_delegate onResult:CARE_AUTHENT_NO_CARE reason:@"No authentication link"];
        return;
    }
    _authentication_link = authentication_link;
    
    NSMutableString *access_token;
    NSMutableString *refresh_token;
    NSDate *expires_date;
    BOOL got_token = [self getToken:authentication_link p_access_token:&access_token p_refresh_token:&refresh_token p_expires_date:&expires_date];
    if (got_token) {
        NSLog(@"Got token from cache");
        
        NSDate *currentDate = [NSDate date];
        if ([currentDate compare: expires_date] == NSOrderedDescending) {
            NSLog(@"token has expired");
            [self removeToken:authentication_link];
        }
        else {
            NSString *resource_url = [_license linkResource];
            if ([resource_url length] <= 0) {
                NSLog(@"No Resource URL in license");
                _shouldRetry = false;
                if (_delegate != nil)
                    [_delegate onResult:CARE_AUTHENT_NO_CARE reason:@"No Resource URL in license"];
                return;
            }
            
            [self newResourceRequest:resource_url token:access_token];
            return;
        }
    }
    if (_delegate != nil)
        [_delegate onResult:CARE_AUTHENT_NEED_CREDENTIALS reason:@"Need credentials"];
}

- (NSString *)getUserkey {
    return _userkey;
}

- (BOOL)getShouldRetry {
    return _shouldRetry;
}

- (void)continueCareAuthenticationWithCredentials:(NSString *)user password:(NSString *)password {
    [self newTokenRequest:_authentication_link user:user password:password];
}

-(void) newTokenRequest:(NSString *)tokenRequestUrl user:(NSString *)user password:(NSString *)password {
    NSLog(@"CareAuthenticationProcessing:newTokenRequest url=%@ user=%@ password=%@", tokenRequestUrl, user, password);
    
    NSURL *url = [NSURL URLWithString:tokenRequestUrl];
    
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    
    //NSString * locale = [[NSLocale preferredLanguages] objectAtIndex:0];
    //NSString* langCode = [NSString stringWithFormat:@"%@%@", locale, @",en-US;q=0.7,en;q=0.5"];
    
    NSURLSession * session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil]; //[NSOperationQueue mainQueue] // [[NSThread currentThread] isMainThread]
    
    NSMutableURLRequest* urlRequest = [[NSMutableURLRequest alloc] initWithURL:url];
    [urlRequest setHTTPMethod:@"POST"];
    [urlRequest setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    NSString *postBodyString = [[NSString alloc] initWithFormat:@"grant_type=password&username=%@&password=%@&scope=lcp:keys:read", user, password];
    NSData *postBody = [[NSData alloc] initWithBytes:[postBodyString UTF8String] length:[postBodyString length]];
    [urlRequest setHTTPBody:postBody];
    //[urlRequest setValue:langCode forHTTPHeaderField:@"Accept-Language"];
    
    
    NSURLSessionDataTask *task = [session dataTaskWithRequest:urlRequest];
    task.taskDescription = TASK_DESCRIPTION_CARE_TOKEN_REQUEST;
    
    [task resume];
}

-(void) newResourceRequest:(NSString *)resourceRequestUrl token:(NSString *)token{
    NSLog(@"CareAuthenticationProcessing:newResourceRequest url=%@ token=%@", resourceRequestUrl, token);
    
    NSString* queryStr = [NSString stringWithFormat:@"device_id=%@", [_deviceIDManager getDeviceID]];
    NSString *requrl2 = [resourceRequestUrl stringByReplacingOccurrencesOfString:@"{?device_id}" withString:[NSString stringWithFormat:@"?%@", queryStr]]; // TODO: smarter regexp?
    NSURL *url = [NSURL URLWithString:requrl2];
    
    NSLog(@"CareAuthenticationProcessing:newResourceRequest updated url=%@", requrl2);
    
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    
    //NSString * locale = [[NSLocale preferredLanguages] objectAtIndex:0];
    //NSString* langCode = [NSString stringWithFormat:@"%@%@", locale, @",en-US;q=0.7,en;q=0.5"];
    
    NSURLSession * session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil]; //[NSOperationQueue mainQueue] // [[NSThread currentThread] isMainThread]
    
    NSMutableURLRequest* urlRequest = [[NSMutableURLRequest alloc] initWithURL:url];
    [urlRequest setHTTPMethod:@"GET"];
    NSString *authentication_header = [[NSString alloc] initWithFormat:@"Bearer %@", token];
    NSLog(@"CareAuthenticationProcessing:newResourceRequest Authentication header: %@", authentication_header);
    [urlRequest setValue:authentication_header forHTTPHeaderField:@"Authorization"];
    //[urlRequest setValue:langCode forHTTPHeaderField:@"Accept-Language"];
    
    NSURLSessionDataTask *task = [session dataTaskWithRequest:urlRequest];
    task.taskDescription = TASK_DESCRIPTION_CARE_RESOURCE_REQUEST;
    
    [task resume];
}

/////////////////////////////////////////
//NSURLSessionDataDelegate
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler
{
    if ([dataTask.taskDescription isEqualToString:TASK_DESCRIPTION_CARE_TOKEN_REQUEST]) {
        
        _data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST = nil;
        
    }
    else if ([dataTask.taskDescription isEqualToString:TASK_DESCRIPTION_CARE_RESOURCE_REQUEST]) {
        
        _data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST = nil;
        
    }
    
    completionHandler(NSURLSessionResponseAllow);
}

/////////////////////////////////////////
//NSURLSessionDataDelegate
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data
{
    
    float progress = -1;
    float received = dataTask.countOfBytesReceived;
    float expected = dataTask.countOfBytesExpectedToReceive;
    if (expected > 0) {
        progress = received / expected;
    }
    
    
    if ([dataTask.taskDescription isEqualToString:TASK_DESCRIPTION_CARE_TOKEN_REQUEST]) {
        
        if (_data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST == nil) {
            _data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST = [NSMutableData dataWithCapacity:(expected>0?expected:2048)];
        }
        [_data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST appendData:data];
        
        return;
    }
    else if ([dataTask.taskDescription isEqualToString:TASK_DESCRIPTION_CARE_RESOURCE_REQUEST]) {
        
        if (_data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST == nil) {
            _data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST = [NSMutableData dataWithCapacity:(expected>0?expected:2048)];
        }
        [_data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST appendData:data];
        
        return;
    }
}

/////////////////////////////////////////
//NSURLSessionTaskDelegate
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
didCompleteWithError:(nullable NSError *)error
{
    NSInteger code = [(NSHTTPURLResponse *)task.response statusCode];
    
    if ([task.taskDescription isEqualToString:TASK_DESCRIPTION_CARE_TOKEN_REQUEST]) {
        
        if (error) {
            
            _data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST = nil;
            
            NSLog(@"%@", [NSString stringWithFormat:@"HTTP error (TASK_DESCRIPTION_CARE_TOKEN_REQUEST) [%@] => (%li) ... %@ [%li]", [(NSHTTPURLResponse *)task.originalRequest URL], code, error.domain, error.code]);
            
            _shouldRetry = false;
            if (_delegate != nil)
                [_delegate onResult:CARE_AUTHENT_ERROR reason:@"HTTP error during Token Request"];
            //if (!_wasCancelled) {
            //    [_statusDocumentProcessingListener onStatusDocumentProcessingComplete:self];
            //}
            
        } else if (code < 200 || code >= 300) {
            NSLog(@"%@", [NSString stringWithFormat:@"HTTP fail (TASK_DESCRIPTION_CARE_TOKEN_REQUEST) [%@] => (%li)", [(NSHTTPURLResponse *)task.response URL], code]);
            
            if (code==401)
                _shouldRetry = true;
            else
                _shouldRetry = false;
            
            NSString *reason = [[NSString alloc] initWithFormat:@"HTTP error %d during Token Request", code];
            try {
                NSString *json = [[NSString alloc] initWithData:_data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST encoding:NSUTF8StringEncoding];
                
                NSError *jsonError = nil;
                id rootJsonObj = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&jsonError];
                
                if ((jsonError == nil) && (rootJsonObj != nil)) {
                    BOOL okay = [NSJSONSerialization isValidJSONObject:rootJsonObj];
                    if (okay) {
                        NSString *error_description = [rootJsonObj valueForKey:@"error_description"];
                        if ((error_description != nil) && (error_description.length>0))
                            reason = error_description;
                    }
                }
            }
            catch (...) {
            }
            
            _data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST = nil;
            
            if (_delegate != nil)
                [_delegate onResult:CARE_AUTHENT_ERROR reason:reason];
            
            //if (!_wasCancelled) {
            //    [_statusDocumentProcessingListener onStatusDocumentProcessingComplete:self];
            //}
            
        } else {
            
            try {
                NSString *json = [[NSString alloc] initWithData:_data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST encoding:NSUTF8StringEncoding];
                _data_TASK_DESCRIPTION_CARE_TOKEN_REQUEST = nil;
                
                NSError *jsonError = nil;
                id rootJsonObj = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&jsonError];
                
                if (jsonError != nil) {
                    //ERROR
                    _shouldRetry = false;
                    if (_delegate != nil)
                        [_delegate onResult:CARE_AUTHENT_ERROR reason:@"JSON error during Token Request"];
                    return;
                }
                
                if (rootJsonObj == nil) {
                    //ERROR
                    _shouldRetry = false;
                     if (_delegate != nil)
                         [_delegate onResult:CARE_AUTHENT_ERROR reason:@"JSON error during Token Request"];
                    return;
                }
                
                BOOL okay = [NSJSONSerialization isValidJSONObject:rootJsonObj];
                if (!okay) {
                    //ERROR
                    _shouldRetry = false;
                     if (_delegate != nil)
                         [_delegate onResult:CARE_AUTHENT_ERROR reason:@"JSON error during Token Request"];
                    return;
                }
                
                NSString *access_token = [rootJsonObj valueForKey:@"access_token"];
                NSString *refresh_token = [rootJsonObj valueForKey:@"refresh_token"];
                NSInteger expires_in = [[rootJsonObj valueForKey:@"expires_in"] intValue];
                NSString *token_type = [rootJsonObj valueForKey:@"token_type"];
                                        
                NSLog(@"New token request result: access_token=%@ refresh_token=%@ expires_in=%d token_type=%@", access_token, refresh_token, expires_in, token_type);
                [self storeToken:_authentication_link access_token:access_token refresh_token:refresh_token expires_in:expires_in];
                NSString *resource_url = [_license linkResource];
                if ([resource_url length] <= 0) {
                    NSLog(@"No Resource URL in license");
                    _shouldRetry = false;
                    if (_delegate != nil)
                        [_delegate onResult:CARE_AUTHENT_NO_CARE reason:@"No Resource URL in license"];
                    return;
                }
                
                [self newResourceRequest:resource_url token:access_token];
            }
            catch (NSException *e) {
                NSLog(@"%@", [e reason]);
                _shouldRetry = false;
                 if (_delegate != nil)
                     [_delegate onResult:CARE_AUTHENT_ERROR reason:@"Exception during Token Request"];
            }
            catch (std::exception& e) {
                _shouldRetry = false;
                if (_delegate != nil)
                    [_delegate onResult:CARE_AUTHENT_ERROR reason:@"Exception during Token Request"];
            }
            catch (...) {
                _shouldRetry = false;
                if (_delegate != nil)
                    [_delegate onResult:CARE_AUTHENT_ERROR reason:@"Exception during Token Request"];
            }
        }
        
        return;
    }
    else if ([task.taskDescription isEqualToString:TASK_DESCRIPTION_CARE_RESOURCE_REQUEST]) {
        
        if (error) {
            
            _data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST = nil;
            
            NSLog(@"%@", [NSString stringWithFormat:@"HTTP error (TASK_DESCRIPTION_CARE_RESOURCE_REQUEST) [%@] => (%li) ... %@ [%li]", [(NSHTTPURLResponse *)task.originalRequest URL], code, error.domain, error.code]);
            _shouldRetry = false;
            if (_delegate != nil)
                [_delegate onResult:CARE_AUTHENT_ERROR reason:@"HTTP error during Resource Request"];
            //if (!_wasCancelled) {
            //    [_statusDocumentProcessingListener onStatusDocumentProcessingComplete:self];
            //}
            
        } else if (code < 200 || code >= 300) {
            NSLog(@"%@", [NSString stringWithFormat:@"HTTP fail (TASK_DESCRIPTION_CARE_RESOURCE_REQUEST) [%@] => (%li)", [(NSHTTPURLResponse *)task.response URL], code]);
            [self removeToken:_authentication_link];
            
            if (code==401) {
                _shouldRetry = true;
            }
            else
                _shouldRetry = false;
            
            NSString *reason = [[NSString alloc] initWithFormat:@"HTTP error %d during Resource_Request", code];
            try {
                NSString *json = [[NSString alloc] initWithData:_data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST encoding:NSUTF8StringEncoding];
                
                NSError *jsonError = nil;
                id rootJsonObj = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&jsonError];
                
                if ((jsonError == nil) && (rootJsonObj != nil)) {
                    BOOL okay = [NSJSONSerialization isValidJSONObject:rootJsonObj];
                    if (okay) {
                        NSString *error_description = [rootJsonObj valueForKey:@"error_description"];
                        if ((error_description != nil) && (error_description.length>0))
                            reason = error_description;
                    }
                }
            }
            catch (...) {
            }
            
            _data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST = nil;
            
            if (_delegate != nil)
                [_delegate onResult:CARE_AUTHENT_ERROR reason:reason];
            
            //if (!_wasCancelled) {
            //    [_statusDocumentProcessingListener onStatusDocumentProcessingComplete:self];
            //}
            
        } else {
            
            try {
                NSString *json = [[NSString alloc] initWithData:_data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST encoding:NSUTF8StringEncoding];
                _data_TASK_DESCRIPTION_CARE_RESOURCE_REQUEST = nil;
                
                NSError *jsonError = nil;
                id rootJsonObj = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&jsonError];
                
                if (jsonError != nil) {
                    //ERROR
                    _shouldRetry = false;
                    if (_delegate != nil)
                        [_delegate onResult:CARE_AUTHENT_ERROR reason:@"JSON error during Resource Request"];
                    return;
                }
                
                if (rootJsonObj == nil) {
                    //ERROR
                    _shouldRetry = false;
                    if (_delegate != nil)
                        [_delegate onResult:CARE_AUTHENT_ERROR reason:@"JSON error during Resource Request"];
                    return;
                }
                
                BOOL okay = [NSJSONSerialization isValidJSONObject:rootJsonObj];
                if (!okay) {
                    //ERROR
                    _shouldRetry = false;
                    if (_delegate != nil)
                        [_delegate onResult:CARE_AUTHENT_ERROR reason:@"JSON error during Resource Request"];
                    return;
                }
                
                NSString *userkey = [rootJsonObj valueForKey:@"user_key"];
                NSLog(@"New resource request result: userkey=%@", userkey);
                _userkey = userkey;
                if (_delegate != nil) {
                    [_delegate onResult:CARE_AUTHENT_OK reason:@"OK"];
                }
            }
            catch (NSException *e) {
                NSLog(@"%@", [e reason]);
                _shouldRetry = false;
                if (_delegate != nil)
                    [_delegate onResult:CARE_AUTHENT_ERROR reason:@"Exception during Resource Request"];
            }
            catch (std::exception& e) {
                _shouldRetry = false;
                if (_delegate != nil)
                    [_delegate onResult:CARE_AUTHENT_ERROR reason:@"Exception during Resource Request"];
            }
            catch (...) {
                _shouldRetry = false;
                if (_delegate != nil)
                    [_delegate onResult:CARE_AUTHENT_ERROR reason:@"Exception during Resource Request"];
            }
        }
        
        return;
    }
}

- (void)storeToken:(NSString *)token_url access_token:(NSString *)access_token refresh_token:(NSString *)refresh_token expires_in:(int)expires_in {
    NSDate *expiresDate = [[NSDate alloc] initWithTimeIntervalSinceNow:(NSTimeInterval)expires_in];
    NSLog(@"storeToken: token will expire at %@", [expiresDate descriptionWithLocale: [NSLocale currentLocale ]]);
    NSNumber *date1970 = [[NSNumber alloc] initWithFloat:[expiresDate timeIntervalSince1970]];
    NSDictionary *dict = @{@"access_token":access_token, @"refresh_token":refresh_token, @"expires_in":date1970};
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict
                                                       options:0
                                                         error:&error];
    if (error) {
        NSLog(@"storeToken: failed to create JSON object");
        return;
    }
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSLog(@"storeToken: JSON string:%@", jsonString);
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    [userDefaults setObject:jsonString forKey:token_url];
    [userDefaults synchronize];
}

- (BOOL)getToken:(NSString *)token_url p_access_token:(NSMutableString **)p_access_token p_refresh_token:(NSMutableString **)p_refresh_token p_expires_date:(NSDate **)p_expires_date {
    if (!p_access_token || !p_refresh_token || !p_expires_date) {
        NSLog(@"getToken: bad parameters");
        return false;
    }
    
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    NSString *jsonString = [userDefaults objectForKey:token_url];
    if (jsonString == nil)
        return false;
    NSError *jsonError = nil;
    id rootJsonObj = [NSJSONSerialization JSONObjectWithData:[jsonString dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&jsonError];
    if (jsonError != nil) {
        NSLog(@"getToken: JSON error");
        return false;
    }
    
    if (rootJsonObj == nil) {
        NSLog(@"getToken: JSON error");
        return false;
    }
    BOOL okay = [NSJSONSerialization isValidJSONObject:rootJsonObj];
    if (!okay) {
        NSLog(@"getToken: JSON error");
        return false;
    }
    
    *p_access_token = [[NSMutableString alloc] initWithString:[rootJsonObj valueForKey:@"access_token"]];
    NSLog(@"getToken: access_token=%@", *p_access_token);
    *p_refresh_token = [[NSMutableString alloc] initWithString:[rootJsonObj valueForKey:@"refresh_token"]];
    NSLog(@"getToken: refresh_token=%@", *p_refresh_token);
    NSNumber *date1970 = [rootJsonObj valueForKey:@"expires_in"];
    *p_expires_date = [[NSDate alloc] initWithTimeIntervalSince1970:[date1970 floatValue]];
    NSLog(@"getToken: expires_in=%@", [*p_expires_date descriptionWithLocale: [NSLocale currentLocale ]]);
    return true;
}

-(void)removeToken:(NSString *)token_url {
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    [userDefaults removeObjectForKey:token_url];
    [userDefaults synchronize];
}

/////////////////////////////////////////
/////////////////////////////////////////
/////////////////////////////////////////

@end
