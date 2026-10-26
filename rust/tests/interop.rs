use serde::{Deserialize, Serialize};
use tunnelnest::sharing;
#[derive(Deserialize, Serialize)]
struct Fixture {
    code: String,
    password: String,
    name: String,
    mode: String,
    args: Vec<String>,
}
#[test]
fn imports_go_versions_and_reexports_compatible_profiles() {
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/go-shares.json")).unwrap();
    let mut reexported = vec![];
    for f in fixtures {
        let p = sharing::decode(&f.code, &f.password).unwrap();
        assert_eq!(p.name, f.name);
        assert_eq!(p.mode, f.mode);
        assert_eq!(p.args, f.args);
        let code = sharing::encode(p, &f.password).unwrap();
        reexported.push(Fixture { code, ..f });
    }
    if let Ok(path) = std::env::var("TUNNELNEST_REEXPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&reexported).unwrap()).unwrap();
    }
}
