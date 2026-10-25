"""Component inventory behavior: inclusion, ordering, scope, and CPE
collisions that never deduplicate component instances."""

from helpers import component_by_name, component_names, default_config, default_facts, dep, fragment, pkg, render_docs


def test_all_recipe_components_appear_sorted_by_identity():
    facts = default_facts(fragments={
        "zlib": fragment(pkgs=[pkg("zlib", "1.3", "ref-z")]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b"),
                                  pkg("busybox", "1.30", "ref-b30")]),
        "app": fragment(pkgs=[pkg("app", "0.1", "ref-app")]),
    })
    sbom, _vex, _logs = render_docs(facts)

    assert component_names(sbom) == ["app", "busybox", "busybox", "zlib"]
    assert [c["version"] for c in sbom["components"][1:3]] == ["1.30", "1.36"]


def test_scope_marks_runtime_against_build_time_recipes():
    facts = default_facts(
        fragments={
            "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
            "cmake": fragment(pkgs=[pkg("cmake", "3.0", "ref-c")]),
        },
        runtime_recipes=["busybox"],
    )
    sbom, _vex, _logs = render_docs(facts)

    assert component_by_name(sbom, "busybox")["scope"] == "required"
    assert component_by_name(sbom, "cmake")["scope"] == "excluded"


def test_scope_assignment_can_be_disabled():
    facts = default_facts(config=default_config(add_component_scopes=False),
                          fragments={
                              "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
                              "cmake": fragment(pkgs=[pkg("cmake", "3.0", "ref-c")]),
                          },
                          runtime_recipes=["busybox"])
    sbom, _vex, _logs = render_docs(facts)

    assert all("scope" not in c for c in sbom["components"])


def test_recipes_sharing_a_cpe_remain_separate_component_instances():
    shared_cpe = "cpe:2.3:*:*:widget:1.0:*:*:*:*:*:*:*"
    facts = default_facts(fragments={
        "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a", cpe=shared_cpe)]),
        "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b", cpe=shared_cpe)]),
    })
    sbom, _vex, _logs = render_docs(facts)

    widgets = [c for c in sbom["components"] if c["name"] == "widget"]
    assert [c["bom-ref"] for c in widgets] == ["ref-a", "ref-b"]
    assert all(c["cpe"] == shared_cpe for c in widgets)


def test_dependency_resolves_to_the_instance_its_recipe_names():
    # A dependency on widget-b reaches widget-b's instance even though
    # widget-a contributes a colliding component of the same name.
    shared_cpe = "cpe:2.3:*:*:widget:1.0:*:*:*:*:*:*:*"
    facts = default_facts(fragments={
        "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a", cpe=shared_cpe)]),
        "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b", cpe=shared_cpe)]),
        "consumer": fragment(pkgs=[pkg("consumer", "1", "ref-c")],
                             dependencies=[dep("ref-c", ["widget-b"])]),
    })
    sbom, _vex, _logs = render_docs(facts)

    entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-c")
    assert entry["dependsOn"] == ["ref-b"]


def test_colliding_instances_keep_their_own_dependency_entries():
    shared_cpe = "cpe:2.3:*:*:widget:1.0:*:*:*:*:*:*:*"
    facts = default_facts(fragments={
        "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a", cpe=shared_cpe)],
                             dependencies=[dep("ref-a", ["libc"])]),
        "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b", cpe=shared_cpe)],
                             dependencies=[dep("ref-b", ["libc"])]),
        "libc": fragment(pkgs=[pkg("libc", "2.40", "ref-libc")]),
    })
    sbom, _vex, _logs = render_docs(facts)

    for ref in ("ref-a", "ref-b"):
        entry = next(e for e in sbom["dependencies"] if e["ref"] == ref)
        assert entry["dependsOn"] == ["ref-libc"]


def test_fragment_input_is_not_mutated():
    frag = fragment(pkgs=[pkg("busybox", "1.36", "ref-b")])
    facts = default_facts(fragments={"busybox": frag})
    render_docs(facts)

    assert "scope" not in frag["pkgs"][0]
