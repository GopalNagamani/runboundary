# Experimental Xcode compiler bridges

`ios-build` runs an unsigned Debug Simulator build in the ordinary filtered workspace
sandbox and sets `IBC_EXEC` and `ASSETCATALOG_EXEC` to per-build wrappers.
Source documents, compiled storyboard bundles and asset catalogs travel through
a bounded file protocol to the constrained compiler. Only that compiler can
receive the opt-in Simulator service authority; build scripts remain restricted.

`macos-ib-bridge-20261030T033908Z.log` records passing direct compiler denial
checks, actual typed XIB/localized storyboard/link jobs and the previous
synthetic app. This validates the companion-strings correction, including the
translation after linking. The actual WorldTableTennis build then failed at
`CompileAssetCatalogVariant`: direct `actool` could not discover Simulator
runtimes from the ordinary build sandbox. That task was outside `IBC_EXEC`.

The asset adapter now handles bounded catalog compilation and asset symbol
generation through the same compiler boundary. Native typed asset tests and
the fixture now include an app icon and named color. The first asset rerun in
`macos-ib-bridge-20261030T060702Z.log` stopped with a bare `ENOENT`; its shared
test unwrap did not identify the substep or missing file. Asset compiler inputs
and outputs now use absolute host-generated staging paths, and failures report
the native substep, expected output, bounded directory entries and compiler
diagnostics. A November 2 native rerun reached symbol generation but produced
no symbol files: the bridge omitted `--output-partial-info-plist` for symbol
jobs. Direct native reproduction confirmed that with an app icon selected,
actool exits successfully without symbols when that flag is absent; supplying
it produces the Swift, Objective-C and index files. The bridge now preserves
requested metadata arguments and supplies a host-generated metadata destination
for app-icon symbol jobs even when the caller does not request metadata.
The symbol operation still emits no partial plist; the existing empty metadata
reply remains necessary. The subsequent native run reached the Xcode fixture
but stopped at build preparation because the bridge rejected
`--print-asset-tag-combinations`. That XML catalog query now has its own typed
operation, using the same bounded catalog staging and compiler sandbox, with
no output destination or compile options. Native validation now checks a
nonempty tag result and requires the fixture to route tag discovery through
the broker. The updated isolated asset tests and full app build need a rerun;
a passing full application build has not been established.

From an initialized project with Xcode explicitly configured:

```sh
runb ios-build --workspace App.xcworkspace --scheme App \
  --simulator-runtime "/Library/Developer/CoreSimulator/Volumes/YOUR_VOLUME/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS YOUR_VERSION.simruntime"
```

Omitting the session builds a fresh filtered copy. To build pending agent edits,
put the retained session ID after `ios-build`. Original source is never applied.
Build-script edits in the copied workspace remain reviewable; a fresh build
with edits prints a new retained session ID. DerivedData, compiler homes and
broker state are disposable and are removed afterward. This command validates
a build; it does not export/install an app or import signing credentials. With
the compiler service option, Apple may create/launch private Interface Builder
devices and helpers during compilation. It uses two Xcode build jobs and does
not opt into TCP listeners.

## Resources requiring Simulator system content

To enable the compatibility path for the observed error:

```sh
runb ios-build --workspace App.xcworkspace --scheme App \
  --simulator-runtime "/Library/Developer/CoreSimulator/Volumes/YOUR_VOLUME/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS YOUR_VERSION.simruntime" \
  --allow-compiler-simulator-services
```

This option increases the compiler's host-service authority. Shared Apple
services can use host account state; the compiler's filesystem restrictions do
not establish confinement of service-mediated operations. Service/device state
may outlive the build despite removal of its disposable directories. Agent and
build-script profiles receive no service grants. Those processes can still
submit validated typed documents to the broker, so hostile-document behavior
remains relevant. The selection is captured by the host before the build;
request JSON, wrapper arguments and shared settings cannot enable it.

The default remains restricted and never retries with extra permissions.
No encoder preflight checks are bypassed. Direct compiler file/network controls,
bounded requests, artifact validation and publication rules apply in both modes.

## Request and artifact boundary

The Interface Builder wrapper parses a finite set of version, XIB compilation, storyboard
compilation and storyboard linking options. Deployment targets, module names,
devices and formats are validated again in the host. Arbitrary flags,
plugins/plugin directories, environment overrides, caller runtime paths
and unsupported operations fail without a fallback.
Project-specific options may therefore need additional validated operations.

The asset wrapper uses a separate finite parser for `actool` version and XML
asset-tag queries, Simulator catalog compilation and Swift/Objective-C
symbol/index generation.
It supports the observed app-icon, accent-color, PNG compression, on-demand
resource boolean, development region, deployment target and bundle identifier
options. Up to 16 catalogs with unique case-insensitive basenames are accepted.
Catalog files are read with the same no-follow directory capabilities, protected
path checks and combined 64 MiB/4096-entry budget. Arbitrary tool personas,
environment/plugin/runtime flags, external strings and asset-pack specifications
are rejected. The host selects the fixed `ibtoold --persona actool` operation;
the caller cannot select a different executable or increase service authority.

Catalog artifacts, partial plists and generated symbol files return as regular
bytes. Compiler output directories and symbol paths are absolute paths fixed inside staging;
the client maps them to validated DerivedData destinations. Symbol generation
does not produce `Assets.car`; it returns its requested side files and an empty
partial plist, since the later catalog compilation supplies app-icon metadata.
Asset dependency records describe the known staged inputs and returned files,
using the same remapper and fresh-build limitation as the IB adapter. They do
not claim all internal SDK reads. The asset compiler adds image/JSON parser and
Apple service workloads to the existing trust boundary; direct denial checks
do not establish confinement of service-mediated asset operations.

For compilation, `--companion-strings-file LOCALE:PATH` reads a regular `.strings`
file inside the copied workspace or DerivedData using the same bounded,
no-follow traversal as source documents. Up to 64 unique locales are accepted,
each at most 64 ASCII letters/digits with nonempty hyphen/underscore-separated
components, starting with a letter; `Base` and case-insensitive duplicates are
rejected. The host receives locale identifiers and bytes, chooses the staged
paths itself, and independently checks declared inputs. Each strings file is
limited to 8 MiB within the combined 64 MiB input budget. Version/link operations
cannot include the companion-strings flag. Compilation must target `Base.lproj`.
XIB compilation copies its strings immediately. Storyboard intermediates carry
locale identifiers and strings bytes under `RunBoundaryLocalization`, within the
artifact size/entry budget. The host rejects raw Apple strings-path manifests
and malformed/incomplete packages at the link boundary, and generates a fresh
`StringsFiles.plist` referring only to the new staged bytes. This also preserves
the compiled resource's strings filename. The linker never receives the bridge
package metadata, so it is not copied into the app. Link inputs retain a bounded
optional locale directory such as `Base.lproj`; localization is not flattened.
Compiled resources and final sibling locale strings are published within
DerivedData without replacing existing locale directories. Dependency records
include the strings inputs and remap them back to the copied build paths.

The wrapper reads only permitted source or generated storyboard files inside
the build sandbox. Requests contain bytes and safe resource names, optionally
prefixed by one validated locale directory for linking, not
host input/output paths. The host captures the approved Xcode/runtime selection
before launching the build and never reloads it from shared state. The compiler
receives only its staged inputs, private output/cache directories and approved
read-only SDK/runtime. Build scripts receive no additional Mach-service grants.

IPC uses the fresh private build home and needs no network permission. A random
per-build token separates sessions; callers within that build remain untrusted.
Every request is checked regardless of token possession. Versioned metadata is
limited to 1 MiB, payload bytes to 66 MiB, paths/files to 4096 entries, and the
queue to 128 entries and 1024 requests. Source documents remain limited to 8 MiB;
combined compiler inputs/primary artifacts to 64 MiB. Headers and raw file bytes
are framed separately; duplicate paths, traversal, overflow, trailing data,
links and special files are rejected. No host shell executes request content.

Atomic no-replace publication prevents partial frames and clobbered responses.
Host directory descriptors stay pinned; request symlinks are not followed.
Compiler jobs retain a 60-second deadline. Wrapper replies have a 180-second
deadline. Finishing/cancelling a build stops and joins its broker, cancelling
active compiler work before removing the private home.

Only validated regular artifact bytes return. The sandboxed wrapper pins the
DerivedData directory through no-follow traversal and publishes through that
directory capability; substituted ancestors are rejected. It cannot make the host write destinations
from a request. Partial plist output is preserved. Dependency-info paths are
remapped from the isolated staging paths to the actual copied source/build
paths; existing SDK records, if present, are retained by the remapper. Xcode's
ibtool does not support a dependency-export flag, so the adapter writes
records for its known staged inputs and validated outputs when requested. It
does not claim complete SDK-read tracking or reusable incremental build caches;
each `ios-build` starts with fresh DerivedData. The binary record format follows
[Swift Build's dependency-info implementation](https://github.com/swiftlang/swift-build/blob/main/Sources/SWBUtil/DependencyInfo.swift).

The compiler/runtime and shared Apple service remain trusted components.
These protocol controls do not prove every service-mediated operation or
hostile document is confined. Direct host-file/TCP denial tests and the older
library/unknown-session tests cover their stated behaviors only.

## Native validation

Run this from Terminal. It first checks actual typed version/XIB/metadata/
storyboard/link jobs and asset catalog/icon/symbol jobs, then builds a small
unsigned Xcode app whose XIB, storyboard and asset tasks must complete through
the broker. If all pass, the optional
project arguments run your actual application build:

```sh
bash scripts/test-macos-ib-bridge.sh --allow-compiler-simulator-services \
  --xcode-app /Applications/Xcode.app \
  --simulator-runtime "/Library/Developer/CoreSimulator/Volumes/iOS_23F77/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime" \
  --project "/Users/hariprakashb/Desktop/WTT-iOS 3" \
  --workspace WorldTableTennis-iOS.xcworkspace --scheme WorldTableTennis-iOS
```

With the service option, the script first checks direct host-file/TCP denials
for both compiler profiles, then runs typed jobs, the fixture and optional app
with service access enabled. Without it, the existing restricted mode is tested.
These direct checks do not certify service-mediated confinement. Rerun all typed
jobs for the added asset adapter; do not use `--from-fixture` for its first validation.

The script stops at the first failing stage and writes one report under
`test-results/`. Managed sessions here refuse nested `sandbox_apply`; that
refusal is a prerequisite failure rather than evidence of a successful bridge.

After the typed-job stage has passed for the current compiler code and runtime,
add `--from-fixture` immediately after the script name to resume at the Xcode
fixture and then the selected project. This mode records that the typed jobs
were not selected in the new report.

macOS `/var` and `/tmp` path spellings are normalized to `/private/var` and
`/private/tmp` before comparing build roots. The controller verifies those
root-owned system aliases before starting the build. The client performs only
the fixed prefix translation; it does not canonicalize arbitrary caller paths.
No-follow traversal and pinned output-directory capabilities still reject
substituted build/source symlinks.

The client traverses ancestors with search-only descriptors (`O_SEARCH` on
macOS), then opens the permitted build root for reading. Ancestors outside the
build roots retain metadata-only sandbox access; no directory-listing grant is
added. Errors identify the failing root, traversal component or queue operation.

Bridge compile jobs select Xcode's `LNEPhase2` local NIB encoder, retaining
unsupported-property preflight and normal fallback. This can still require
Simulator system content, as the actual application failure demonstrates. The
fixture also includes an animating large activity indicator with a named
color, covering the widget in the earlier failing application XIB. That fixture
and the opt-in compiler profile passed, including the localized storyboard
correction, in the October 30 report. The new asset adapter and fixture require
a full native rerun, including typed jobs; do not use `--from-fixture` for their
first validation.
