use super::*;

#[test]
fn pr170_nested_aliases_keep_inherited_configuration() {
    let mirror = single_intent(
        "git -c remote.origin.mirror=true -c alias.q=push -c 'alias.p=!git q' p origin",
    );
    assert!(mirror.mirror, "{mirror:?}");
    let chained =
        single_intent("git -c alias.q=r -c alias.r=push -c 'alias.p=!git q' p origin main");
    assert_eq!(chained.remote.as_deref(), Some("origin"));
    assert_eq!(chained.policy_subjects(), vec!["git push"]);
}

#[test]
fn pr170_dynamic_shell_aliases_cannot_downgrade_outbound_intent() {
    for command in [
        r#"git -c 'alias.p=!f() { git push "$@"; }; f' p --force origin main"#,
        r#"git -c 'alias.p=!git "$1" "$2" origin main' p push --force"#,
        r#"git -c 'alias.p=!${COMMAND} "$@"' p --force origin main"#,
    ] {
        let intent = single_intent(command);
        assert!(
            intent.force && intent.mirror && intent.delete,
            "{command}: {intent:?}"
        );
        assert!(matches!(
            intent.detection,
            GitPushDetection::EmbeddedArgv { .. }
        ));
    }
}

#[test]
fn pr170_static_shell_aliases_keep_ordinary_and_non_outbound_forms() {
    for command in [
        "git -c 'alias.p=!git push' p origin main",
        r#"git -c "alias.p=!printf '%s' '\$literal'; git push" p origin main"#,
    ] {
        assert_eq!(single_intent(command).policy_subjects(), vec!["git push"]);
    }
    assert!(git_push_intents("git -c 'alias.s=!git status' s")
        .unwrap()
        .is_empty());
}

#[test]
fn pr170_environment_configuration_cannot_hide_an_alias() {
    for command in [
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p GIT_CONFIG_VALUE_0='push --mirror' git p origin",
        "env GIT_CONFIG_PARAMETERS=x git p origin",
        "export 'GIT_CONFIG_GLOBAL=/workspace/config'; git p origin",
        r#"export "GIT_CONFIG_PARAMETERS=$CONFIG"; git p origin"#,
        "export 'GIT_CONFIG_COUNT=1' 'GIT_CONFIG_KEY_0=remote.origin.mirror' 'GIT_CONFIG_VALUE_0=true'; git push origin",
    ] {
        let intent = single_intent(command);
        assert!(intent.force && intent.mirror && intent.delete, "{command}: {intent:?}");
    }
    for command in [
        "LANG=C git status",
        "git -c user.name=agent status",
        "git -c alias.s=status s",
    ] {
        assert!(git_push_intents(command).unwrap().is_empty(), "{command}");
    }
}

#[test]
fn normalizes_equivalent_push_entry_points() {
    for command in [
        "/usr/bin/git push origin main",
        "env git push origin main",
        "command git push origin main",
        "stdbuf -o0 git push origin main",
        "setsid -fw git push origin main",
        r#""git" push origin main"#,
        r#"g""it push origin main"#,
        r#"g\it push origin main"#,
        "git -C /workspace push origin main",
        "git --git-dir=/workspace/.git push origin main",
        "git-push origin main",
        "{ git push origin main; }",
    ] {
        let intents = git_push_intents(command).expect("valid shell");
        assert_eq!(intents.len(), 1, "push missing from {command:?}");
        assert!(intents[0].policy_subjects().contains(&"git push"));
    }
}

#[test]
fn classifies_destructive_push_semantics() {
    let cases = [
        ("git push -f origin main", "git push --force"),
        (
            "git -C repo push origin main --force-with-lease",
            "git push --force-with-lease",
        ),
        ("git push origin +main:main", "git push --force"),
        ("git push origin :main", "git push --delete"),
        ("git push --delete origin main", "git push --delete"),
        ("git push --mirror origin", "git push --mirror"),
    ];

    for (command, subject) in cases {
        let intents = git_push_intents(command).expect("valid shell");
        assert!(
            intents[0].policy_subjects().contains(&subject),
            "{command:?} did not produce {subject:?}: {:?}",
            intents[0]
        );
    }
}

#[test]
fn retains_repository_remote_and_refspec_scope() {
    let intent = git_push_intents(
        "git -C /workspace --git-dir=.git --work-tree=src push origin main:main tag:v1",
    )
    .expect("valid shell")
    .pop()
    .expect("push intent");

    assert_eq!(intent.directory_changes, ["/workspace"]);
    assert_eq!(intent.git_dir.as_deref(), Some(".git"));
    assert_eq!(intent.work_tree.as_deref(), Some("src"));
    assert_eq!(intent.remote.as_deref(), Some("origin"));
    assert_eq!(intent.refspecs, ["main:main", "tag:v1"]);
}

#[test]
fn positional_repository_overrides_repo_option_like_git() {
    let intent = git_push_intents("git push --repo=origin backup main")
        .expect("valid shell")
        .pop()
        .expect("push intent");

    assert_eq!(intent.remote.as_deref(), Some("backup"));
    assert_eq!(intent.refspecs, ["main"]);
}

#[test]
fn force_if_includes_alone_is_not_a_forced_push() {
    let intent = git_push_intents("git push --force-if-includes origin main")
        .expect("valid shell")
        .pop()
        .expect("push intent");

    assert!(intent.force_if_includes);
    assert!(!intent.force_with_lease);
    assert!(!intent.force);
    assert!(!intent.policy_subjects().contains(&"git push --force"));
}

#[test]
fn recognizes_send_pack_as_the_same_outbound_boundary() {
    for command in [
        "git send-pack origin main",
        "git-send-pack origin main",
        "git -C repo send-pack origin main",
        "git --exec-path send-pack origin main",
    ] {
        let intents = git_push_intents(command).expect("valid shell");
        assert_eq!(intents.len(), 1, "send-pack missing from {command:?}");
        assert!(intents[0].policy_subjects().contains(&"git push"));
    }

    for command in [
        "git send-pack --force origin main",
        "git-send-pack -f origin main",
        "git send-pack --force-with-lease origin main",
        "git send-pack --mirror origin",
        "git send-pack origin +main:main",
    ] {
        let intents = git_push_intents(command).expect("valid shell");
        assert_eq!(intents.len(), 1, "send-pack missing from {command:?}");
        assert!(
            intents[0].policy_subjects().contains(&"git push --force")
                || intents[0].policy_subjects().contains(&"git push --mirror"),
            "destructive send-pack was not canonicalized: {command:?}"
        );
    }
}

#[test]
fn conservatively_recognizes_git_intent_after_unknown_prefix_tokens() {
    for command in [
        "firejail --quiet git push origin main",
        "bwrap --ro-bind / / git push origin main",
        "torsocks git-send-pack origin main",
        "flatpak-spawn --host /usr/bin/git send-pack origin main",
        r#"probe "git" "push" origin main"#,
    ] {
        let intents = git_push_intents(command).expect("valid shell");
        assert_eq!(
            intents.len(),
            1,
            "embedded Git intent missing from {command:?}"
        );
        assert!(intents[0].policy_subjects().contains(&"git push"));
        assert!(matches!(
            intents[0].detection,
            GitPushDetection::EmbeddedArgv { .. }
        ));
    }

    for command in [
        "firejail git push --force origin main",
        "cpulimit -l 50 -- git push origin +main:main",
        "ssh-agent git-send-pack --mirror origin",
        "echo git push --force origin main",
        "probe git status git push --force origin main",
    ] {
        let intents = git_push_intents(command).expect("valid shell");
        assert_eq!(
            intents.len(),
            1,
            "embedded Git intent missing from {command:?}"
        );
        assert!(
            intents[0].force || intents[0].mirror,
            "destructive strength was lost for {command:?}: {:?}",
            intents[0]
        );
    }
}

fn single_intent(command: &str) -> GitPushIntent {
    let mut intents = git_push_intents(command).expect("valid shell");
    assert_eq!(intents.len(), 1, "expected one intent for {command:?}");
    intents.pop().expect("one intent")
}

/// Git accepts any unambiguous prefix of a long option. A recognizer that
/// only matched full spellings classified abbreviated destructive flags as
/// an ordinary push.
#[test]
fn abbreviated_destructive_options_keep_their_meaning() {
    for (command, subject) in [
        ("git push --mirr origin", "git push --mirror"),
        (
            "git push --force-w origin main",
            "git push --force-with-lease",
        ),
        (
            "git push --force-w=main:abc origin main",
            "git push --force-with-lease",
        ),
        ("git push --del origin main", "git push --delete"),
        ("git send-pack --mirr origin", "git push --mirror"),
        (
            "git send-pack --force-w origin main",
            "git push --force-with-lease",
        ),
    ] {
        let intent = single_intent(command);
        assert!(
            intent.policy_subjects().contains(&subject),
            "{command:?} must produce {subject:?}: {intent:?}"
        );
    }
}

#[test]
fn prune_is_classified_as_remote_ref_removal() {
    for command in [
        "git push --prune origin refs/heads/*:refs/heads/*",
        "git push --pru origin refs/heads/*:refs/heads/*",
    ] {
        let intent = single_intent(command);
        assert!(intent.delete, "{command:?} removes remote refs: {intent:?}");
        assert!(intent.policy_subjects().contains(&"git push --delete"));
    }
}

#[test]
fn non_destructive_long_options_stay_ordinary() {
    for command in [
        "git push --force-if-includes origin main",
        "git push --dry-run origin main",
        "git push --porcelain origin main",
        "git push --follow-tags origin main",
        "git push --no-prune origin main",
    ] {
        assert_eq!(
            single_intent(command).policy_subjects(),
            vec!["git push"],
            "{command:?} is an ordinary push"
        );
    }
}

/// Command-line config can make a plain-looking push destructive.
#[test]
fn command_line_config_that_changes_push_semantics_is_modeled() {
    let mirror = single_intent("git -c remote.origin.mirror=true push origin");
    assert!(mirror.mirror, "{mirror:?}");

    let forced =
        single_intent("git -c remote.origin.push=+refs/heads/main:refs/heads/main push origin");
    assert!(forced.force, "{forced:?}");

    let removal = single_intent("git -c remote.origin.push=:refs/heads/main push origin");
    assert!(removal.delete, "{removal:?}");

    let from_env = single_intent("git --config-env=remote.origin.push=REFSPEC push origin");
    assert!(from_env.force && from_env.delete, "{from_env:?}");

    let disabled = single_intent("git -c remote.origin.mirror=false push origin main");
    assert!(
        !disabled.mirror,
        "an explicit false is not a mirror: {disabled:?}"
    );

    let unrelated = single_intent("git -c user.name=agent push origin main");
    assert_eq!(unrelated.policy_subjects(), vec!["git push"]);
}

#[test]
fn config_injected_through_the_environment_is_assumed_destructive() {
    for command in [
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=k GIT_CONFIG_VALUE_0=v git push origin main",
        "env GIT_CONFIG_PARAMETERS=x git push origin main",
        "export GIT_CONFIG_GLOBAL=/tmp/cfg; git push origin main",
    ] {
        let intent = single_intent(command);
        assert!(
            intent.force && intent.mirror && intent.delete,
            "{command:?} injects config this module cannot read: {intent:?}"
        );
    }
}

/// An alias defined on the command line hid the push from recognition.
#[test]
fn command_line_aliases_are_followed_to_the_push() {
    let plain = single_intent("git -c alias.p=push p --force origin main");
    assert!(plain.force, "{plain:?}");
    assert_eq!(plain.remote.as_deref(), Some("origin"));

    let options_in_alias = single_intent("git -c 'alias.p=push --mirror' p origin");
    assert!(options_in_alias.mirror, "{options_in_alias:?}");

    let shell = single_intent("git -c 'alias.p=!git push' p origin main");
    assert!(shell.policy_subjects().contains(&"git push"));
    assert!(matches!(
        shell.detection,
        GitPushDetection::EmbeddedArgv { .. }
    ));

    let shell_config =
        single_intent("git -c remote.origin.mirror=true -c 'alias.p=!git push' p origin");
    assert!(shell_config.mirror, "{shell_config:?}");

    let looping = single_intent("git -c alias.p=p p origin main");
    assert!(
        looping.force && looping.mirror && looping.delete,
        "{looping:?}"
    );

    assert!(
        git_push_intents("git -c alias.st=status st")
            .expect("valid shell")
            .is_empty(),
        "an alias for a non-outbound command is not a push"
    );
}

#[test]
fn quoted_git_push_text_is_not_an_executable_intent() {
    for command in [
        "grep -r 'git push --force' src",
        "echo 'git push origin main'",
    ] {
        assert!(
            git_push_intents(command).expect("valid shell").is_empty(),
            "one quoted data token must not become executable Git intent: {command:?}"
        );
    }
    assert!(
        git_push_intents("echo git status")
            .expect("valid shell")
            .is_empty(),
        "non-outbound Git words must not become a push intent"
    );
}
