use agent_guard_core::{CustomToolId, PolicyEngine, Tool};

#[test]
fn custom_tool_deserialization_cannot_bypass_identifier_validation() {
    let mut invalid = vec![
        String::new(),
        "x".repeat(65),
        "has space".to_string(),
        "has/slash".to_string(),
    ];
    for builtin in Tool::BUILTIN_NAMES {
        invalid.push((*builtin).to_string());
        invalid.push(builtin.to_ascii_uppercase());
    }
    for id in invalid {
        let encoded = serde_json::to_string(&id).unwrap();
        assert!(CustomToolId::new(&id).is_err());
        assert!(
            serde_json::from_str::<CustomToolId>(&encoded).is_err(),
            "JSON must reject {id:?}"
        );
        assert!(
            serde_yaml::from_str::<CustomToolId>(&encoded).is_err(),
            "YAML must reject {id:?}"
        );
        assert!(
            serde_json::from_value::<Tool>(serde_json::json!({"custom": id})).is_err(),
            "a custom tool must not masquerade as a builtin"
        );
    }
}

#[test]
fn valid_custom_tool_and_builtin_deserialization_preserve_wire_format() {
    let custom = Tool::Custom(CustomToolId::new("acme.query").unwrap());
    assert_eq!(
        serde_json::to_value(&custom).unwrap(),
        serde_json::json!({"custom":"acme.query"})
    );
    assert_eq!(
        serde_json::from_value::<Tool>(serde_json::to_value(&custom).unwrap()).unwrap(),
        custom
    );
    assert_eq!(
        serde_json::from_str::<Tool>("\"bash\"").unwrap(),
        Tool::Bash
    );
}

#[test]
fn anomaly_windows_outside_the_supported_clock_range_fail_at_load_time() {
    for field in ["rate_limit", "deny_fuse"] {
        let yaml = format!(
            "version: 1\nanomaly:\n  {field}:\n    window_seconds: {}\n",
            u64::MAX
        );
        let error =
            PolicyEngine::from_yaml_str(&yaml).expect_err("the clock cannot represent this window");
        assert!(error.to_string().contains("window_seconds"), "{error}");
    }
}
