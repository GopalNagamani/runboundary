// Test-only private API client. Never linked into AgentVault or shipped as a broker.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <unistd.h>

@interface NSObject (AVSimulatorProbe)
- (id)initWithServiceName:(NSString *)name;
- (id)loadLibLaunchAtURL:(NSURL *)url error:(NSError **)error;
- (id)initWithConnection:(id)connection libLaunchInstance:(id)instance error:(NSError **)error;
- (BOOL)spawnInSession:(NSString *)session program:(NSString *)program
            arguments:(NSArray *)arguments environment:(NSDictionary *)environment
                  cwd:(NSString *)cwd standardInput:(NSFileHandle *)input
       standardOutput:(NSFileHandle *)output standardError:(NSFileHandle *)errorOutput
              binpref:(int)binpref flags:(unsigned long long)flags pid:(pid_t *)pid
     terminationQueue:(dispatch_queue_t)queue terminationHandler:(void (^)(int))handler
                error:(NSError **)error;
@end

// Reject changed private ABI before calling it, including individual argument
// types. Matching a selector name or argument count alone is insufficient.
static BOOL matches(Class cls, SEL selector, const char *encoding) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method) return NO;
    NSMethodSignature *actual = [NSMethodSignature signatureWithObjCTypes:method_getTypeEncoding(method)];
    NSMethodSignature *expected = [NSMethodSignature signatureWithObjCTypes:encoding];
    if (strcmp(actual.methodReturnType, expected.methodReturnType)
        || actual.numberOfArguments != expected.numberOfArguments) return NO;
    for (NSUInteger i = 0; i < actual.numberOfArguments; i++) {
        if (strcmp([actual getArgumentTypeAtIndex:i], [expected getArgumentTypeAtIndex:i])) return NO;
    }
    return YES;
}

static NSDictionary *outcome(BOOL accepted, NSError *error) {
    return @{@"accepted": [NSNumber numberWithBool:accepted],
             @"error": [NSNumber numberWithBool:error != nil],
             @"domain": error.domain ?: @"", @"code": @(error.code),
             @"description": error.description ?: @""};
}

int main(int argc, char **argv) { @autoreleasepool {
    if (argc != 2 && argc != 5) return 64;
    if (!dlopen("/Library/Developer/PrivateFrameworks/CoreSimulator.framework/CoreSimulator", RTLD_LAZY | RTLD_LOCAL)) return 70;
    Class connectionClass = NSClassFromString(@"SimLaunchHostConnection");
    Class clientClass = NSClassFromString(@"SimLaunchHostClient");
    BOOL supported = matches(connectionClass, @selector(initWithServiceName:), "@@:@")
        && matches(connectionClass, @selector(loadLibLaunchAtURL:error:), "@@:@^@")
        && matches(clientClass, @selector(initWithConnection:libLaunchInstance:error:), "@@:@@^@")
        && matches(clientClass, @selector(spawnInSession:program:arguments:environment:cwd:standardInput:standardOutput:standardError:binpref:flags:pid:terminationQueue:terminationHandler:error:), "B@:@@@@@@@@iQ^i@@?^@");
    if (argc == 2 && !strcmp(argv[1], "abi-check")) {
        // Reflection only: no connection object, RPC, runtime load or device boot.
        puts(supported ? "supported-private-abi" : "unsupported-private-abi");
        return supported ? 0 : 78;
    }
    if (!supported || argc != 5) return 78;
    NSString *library = [NSString stringWithUTF8String:argv[1]];
    NSString *program = [NSString stringWithUTF8String:argv[2]];
    NSString *report = [NSString stringWithUTF8String:argv[3]];
    NSString *marker = [NSString stringWithUTF8String:argv[4]];
    NSError *error = nil;
    id connection = [[connectionClass alloc] initWithServiceName:@"com.apple.CoreSimulator.SimLaunchHost-arm64"];
    id instance = [connection loadLibLaunchAtURL:[NSURL fileURLWithPath:library] error:&error];
    if (!instance || error) { puts("trusted-library-control-failed"); return 73; }
    id client = [[clientClass alloc] initWithConnection:connection libLaunchInstance:instance error:&error];
    if (!client || error) { puts("service-client-control-failed"); return 73; }

    // Fresh UUID only: never enumerate or address existing host Simulator sessions.
    NSString *session = [NSUUID UUID].UUIDString;
    // Do not send startNewSession. On the tested runtime an ordinary client
    // hits a fatal Swift identity assertion in the shared service. Its crash
    // was correlated separately; a connection interruption is not an NSError
    // authorization response and must never be treated as one.
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
    pid_t pid = -1;
    error = nil;
    // This fixed child only reads a synthetic canary and writes a marker.
    // No agent code, actual project, signing assets or host session is used.
    BOOL spawned = [client spawnInSession:session program:program arguments:@[program]
        environment:@{} cwd:[program stringByDeletingLastPathComponent]
        standardInput:nil standardOutput:nil standardError:nil binpref:0 flags:0 pid:&pid
        terminationQueue:queue terminationHandler:^(int status) {} error:&error];
    NSDictionary *spawnResult = outcome(spawned, error);
    if (spawned) {
        // The marker proves execution independently of the RPC result.
        for (int i = 0; i < 100 && access(marker.fileSystemRepresentation, F_OK); i++) usleep(50000);
    }
    NSDictionary *result = @{@"trusted_library_accepted": @YES,
        @"session_creation_attempted": @NO, @"spawn": spawnResult, @"pid": @(pid)};
    NSData *json = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    if (!json || ![json writeToFile:report atomically:YES]) return 74;
    return 0;
} }
