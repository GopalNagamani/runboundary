use runboundary::interface_builder::build::Files;
use std::path::PathBuf;

pub fn files() -> Files {
    [
        (
            "Assets.xcassets/Contents.json",
            include_bytes!("../fixtures/ib_build/Assets.xcassets/Contents.json").as_slice(),
        ),
        (
            "Assets.xcassets/AppIcon.appiconset/Contents.json",
            include_bytes!("../fixtures/ib_build/Assets.xcassets/AppIcon.appiconset/Contents.json")
                .as_slice(),
        ),
        (
            "Assets.xcassets/AppIcon.appiconset/Icon.png",
            include_bytes!("../fixtures/ib_build/Assets.xcassets/AppIcon.appiconset/Icon.png")
                .as_slice(),
        ),
        (
            "Assets.xcassets/FixtureAccent.colorset/Contents.json",
            include_bytes!(
                "../fixtures/ib_build/Assets.xcassets/FixtureAccent.colorset/Contents.json"
            )
            .as_slice(),
        ),
    ]
    .into_iter()
    .map(|(p, b)| (PathBuf::from(p), b.to_vec()))
    .collect()
}
