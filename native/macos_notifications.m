#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>
#import <dispatch/dispatch.h>

typedef void (*TNNotificationCallback)(void *, int, const char *);

@interface TNNotificationDelegate : NSObject <UNUserNotificationCenterDelegate>
@end
@implementation TNNotificationDelegate
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
      willPresentNotification:(UNNotification *)notification
        withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completionHandler {
    completionHandler(UNNotificationPresentationOptionBanner | UNNotificationPresentationOptionList | UNNotificationPresentationOptionSound);
}
@end

static BOOL TNHasAppIdentity(void *context, TNNotificationCallback callback) {
    if (![[NSBundle mainBundle].bundleIdentifier isEqualToString:@"org.tunnelnest.rust"]) {
        callback(context, -1, "Open TunnelNest.app to use macOS notifications. A standalone tunnel executable does not have the required app identity.");
        return NO;
    }
    return YES;
}

static UNUserNotificationCenter *TNCenter(void) {
    static TNNotificationDelegate *delegate;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ delegate = [TNNotificationDelegate new]; });
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    center.delegate = delegate;
    return center;
}

// Every path calls back exactly once; strings remain valid for the callback duration.
void tn_notification_authorization(int request, void *context, TNNotificationCallback callback) {
    @autoreleasepool {
        if (!TNHasAppIdentity(context, callback)) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            UNUserNotificationCenter *center = TNCenter();
            [center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
                if (request && settings.authorizationStatus == UNAuthorizationStatusNotDetermined) {
                    [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound)
                                         completionHandler:^(BOOL granted, NSError *error) {
                        if (error) { callback(context, -1, error.localizedDescription.UTF8String); return; }
                        callback(context, granted ? 2 : 1, "");
                    }];
                } else {
                    callback(context, (int)settings.authorizationStatus, "");
                }
            }];
        });
    }
}

void tn_notification_send(const char *title, const char *body, void *context, TNNotificationCallback callback) {
    @autoreleasepool {
        if (!TNHasAppIdentity(context, callback)) return;
        NSString *notificationTitle = [NSString stringWithUTF8String:title];
        NSString *notificationBody = [NSString stringWithUTF8String:body];
        dispatch_async(dispatch_get_main_queue(), ^{
            UNUserNotificationCenter *center = TNCenter();
            [center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
                if (settings.authorizationStatus != UNAuthorizationStatusAuthorized && settings.authorizationStatus != UNAuthorizationStatusProvisional) {
                    callback(context, -1, "macOS notification permission is not granted. Enable TunnelNest in System Settings > Notifications, then retry.");
                    return;
                }
                UNMutableNotificationContent *content = [UNMutableNotificationContent new];
                content.title = notificationTitle;
                content.body = notificationBody;
                content.sound = [UNNotificationSound defaultSound];
                UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:[NSUUID UUID].UUIDString content:content trigger:nil];
                [center addNotificationRequest:request withCompletionHandler:^(NSError *error) {
                    callback(context, error ? -1 : 2, error ? error.localizedDescription.UTF8String : "");
                }];
            }];
        });
    }
}
