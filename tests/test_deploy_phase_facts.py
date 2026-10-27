"""Rootfs-phase fact persistence for the deploy-phase regeneration.

The facts derived from the package manager's view of the assembled root
filesystem (`image_list_installed_packages` -> dnf) only exist inside
do_rootfs's pseudo environment; re-deriving them in do_deploy_cyclonedx
fails the task. The rootfs phase therefore persists its assembled facts
into WORKDIR and the deploy phase loads them instead of re-deriving.
These tests exec the adapter's assembly functions under a stubbed
BitBake/oe environment (the same seam as
test_deployable_files.run_collect_deploy_files); the dnf stub raises, so
any deploy-phase call to the package manager fails loudly.
"""
import ast
import json
import os
import sys
import types

import pytest

import meta_cyclonedx

BBCLASS = os.path.join(os.path.dirname(meta_cyclonedx.__file__),
                       "..", "classes", "cyclonedx-export.bbclass")

FACTS_NAME = "cyclonedx-rootfs-facts.json"

# Facts the rootfs phase assembles; the deploy phase must reuse them verbatim.
PERSISTED = {
    "runtime_recipes": ["base-files", "busybox", "optee-os"],
    "image_install_recipes": ["optee-os", "packagegroup-core-boot"],
    "recipes": ["base-files", "busybox", "cmake", "optee-os"],
    "runtime_edges": {"base-files": ["busybox"], "busybox": []},
    "fragments": {
        "base-files": {"name": "base-files"},
        "busybox": {"name": "busybox"},
        "cmake": {"name": "cmake"},
        "optee-os": {"name": "optee-os"},
    },
}


def class_function(name):
    """One top-level function's AST from the class file (mixed syntax)."""
    with open(BBCLASS) as class_file:
        lines = class_file.read().splitlines(keepends=True)
    body = []
    wanted = f"def {name}("
    task_header = f"python {name}() {{"
    for index, line in enumerate(lines):
        if line.startswith(wanted) or line.rstrip() == task_header:
            body.append(f"def {name}(d):\n" if line.rstrip() == task_header
                        else line)
            for following in lines[index + 1:]:
                if following.strip() and not following[0].isspace():
                    break
                body.append(following)
            break
    if not body:
        raise AssertionError(f"{name} not found in {BBCLASS}")
    return next(node for node in ast.parse("".join(body)).body
                if isinstance(node, ast.FunctionDef))


class Fatal(Exception):
    """Raised in place of bb.fatal."""


def run_export(tmp_path, variables, deploy_phase=False,
               functions=()):
    """Exec the named adapter functions under a stubbed BitBake environment.

    Returns (facts, events, calls): the facts handed to the renderer
    (None if it was never reached), the bb events, and the names of the
    stubbed derivations that were invoked. The package-manager stub
    raises: a deploy phase that still asks dnf fails the test.
    """
    workdir = tmp_path / "work"
    workdir.mkdir(exist_ok=True)
    pkgdata = tmp_path / "pkgdata"
    (pkgdata / "runtime-reverse").mkdir(parents=True)
    pndata = tmp_path / "pndata" / "all"
    pndata.mkdir(parents=True)
    for recipe in PERSISTED["recipes"]:
        (pndata / f"{recipe}.json").write_text(
            json.dumps(PERSISTED["fragments"][recipe]))
    export_dir = tmp_path / "export"
    facts_dir = tmp_path / "tmp-export"

    vars = {
        "PN": "core-image-minimal",
        "WORKDIR": str(workdir),
        "PKGDATA_DIR": str(pkgdata),
        "CYCLONEDX_PNDATA": str(tmp_path / "pndata"),
        "SSTATE_ARCHS": "qemux86_64 all",
        "CYCLONEDX_EXPORT_DIR": str(export_dir),
        "CYCLONEDX_TMP_EXPORT_DIR": str(facts_dir),
        "CYCLONEDX_EXPORT_SBOM": "core-image.cyclonedx.bom.json",
        "CYCLONEDX_EXPORT_VEX": "core-image.cyclonedx.vex.json",
        "CYCLONEDX_SPEC_VERSION": "1.6",
        **variables,
    }
    events = []
    calls = []
    rendered = {}

    class _BBUtils:
        @staticmethod
        def mkdirhier(path):
            os.makedirs(path, exist_ok=True)

    class _BBData:
        @staticmethod
        def inherits_class(klass, d):
            return klass == "image" and vars.get("_IMAGE_RECIPE") == "1"

    class _BB:
        data = _BBData
        utils = _BBUtils

        @staticmethod
        def debug(level, message):
            events.append(("debug", str(message)))

        @staticmethod
        def note(message):
            events.append(("note", str(message)))

        @staticmethod
        def warn(message):
            events.append(("warn", str(message)))

        @staticmethod
        def error(message):
            events.append(("error", str(message)))

        @staticmethod
        def fatal(message):
            events.append(("fatal", str(message)))
            raise Fatal(str(message))

    def image_list_installed_packages(d):
        calls.append("image_list_installed_packages")
        if vars.get("_INSTALLED_PACKAGES_ERROR"):
            raise AssertionError(
                "the deploy phase must not ask the package manager")
        return iter(vars.get("_INSTALLED_PACKAGES", ["pkg-busybox"]))

    def read_pkgdatafile(path):
        return {"PN": {"pkg-busybox": "busybox",
                       "pkg-base-files": "base-files"}[os.path.basename(path)]}

    def list_image_install_recipes(d):
        calls.append("list_image_install_recipes")
        return set(vars.get("_IMAGE_INSTALL_RECIPES", ["packagegroup-core-boot"]))

    def list_buildtime_recipes(d):
        calls.append("list_buildtime_recipes")
        return set(vars.get("_BUILDTIME_RECIPES", ["cmake"]))

    def build_runtime_dependency_edges(d):
        calls.append("build_runtime_dependency_edges")
        image_list_installed_packages(d)
        return {recipe: set(deps)
                for recipe, deps in vars.get("_EDGES", {"busybox": ["base-files"]}).items()}

    def collect_debug_sources(d, recipes):
        return {}

    def collect_file_inventory(d, recipes):
        calls.append("collect_file_inventory")
        return {"/bin/busybox": [{"path": "/bin/busybox"}]}

    def collect_deploy_files(d):
        calls.append("collect_deploy_files")
        return []

    module = types.ModuleType("adapter_under_test")
    module.bb = _BB
    module.os = os

    # `from oe.rootfs import ...` resolves through sys.modules, so the
    # package manager stub must be installed as a module, not just as a
    # class-file global.
    oe_module = types.ModuleType("oe")
    rootfs_module = types.ModuleType("oe.rootfs")
    rootfs_module.image_list_installed_packages = image_list_installed_packages
    packagedata_module = types.ModuleType("oe.packagedata")
    packagedata_module.read_pkgdatafile = read_pkgdatafile
    oe_module.rootfs = rootfs_module
    oe_module.packagedata = packagedata_module
    fake_modules = {"oe": oe_module, "oe.rootfs": rootfs_module,
                    "oe.packagedata": packagedata_module}

    module.oe = oe_module

    def _stub(name, value):
        def stub(d, *args):
            calls.append(name)
            return value() if callable(value) else value
        return stub

    module.list_image_install_recipes = list_image_install_recipes
    module.list_buildtime_recipes = list_buildtime_recipes
    module.build_runtime_dependency_edges = build_runtime_dependency_edges
    module.collect_debug_sources = collect_debug_sources
    module.collect_file_inventory = collect_file_inventory
    module.collect_deploy_files = collect_deploy_files
    module.resolve_license_data = _stub("resolve_license_data", [])
    module.generate_layer_references = _stub("generate_layer_references", [])
    module.resolve_extra_image_sbom_paths = _stub(
        "resolve_extra_image_sbom_paths", [])
    module.write_cyclonedx_image_data = _stub(
        "write_cyclonedx_image_data", None)
    module.cyclonedx_sbom_cve_check_enabled = _stub(
        "cyclonedx_sbom_cve_check_enabled", False)
    module._cyclonedx_log = object()

    class _Renderer:
        def render(self, facts):
            rendered.update(facts)
            rendered["facts"] = facts
            return {"sbom": {"document": "sbom"}, "vex": {"document": "vex"}}

        def serialize_report(self, report):
            return json.dumps(report)

    module._cyclonedx_renderer = lambda d: _Renderer()

    tree = ast.Module(body=[class_function(name)
                            for name in ("read_json", "write_json",
                                         "list_runtime_recipes",
                                         "list_runtime_recipes_from_packages",
                                         *functions)],
                      type_ignores=[])
    saved_modules = {name: sys.modules.get(name) for name in fake_modules}
    sys.modules.update(fake_modules)
    try:
        exec(compile(tree, BBCLASS, "exec"), module.__dict__)
        module.export_cyclonedx(_Data(vars), deploy_phase=deploy_phase)
    finally:
        for name, previous in saved_modules.items():
            if previous is None:
                del sys.modules[name]
            else:
                sys.modules[name] = previous
    return rendered.get("facts"), events, calls


class _Data:
    def __init__(self, vars):
        self._vars = vars

    def getVar(self, name, default=None):
        return self._vars.get(name, default)

    def getVarFlag(self, flag, name):
        return ""

    def expand(self, value):
        return value


def persisted_facts(tmp_path, content=None):
    path = tmp_path / "work" / FACTS_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(PERSISTED if content is None else content))
    return path


def test_deploy_phase_reuses_persisted_facts_without_the_package_manager(tmp_path):
    # The final generation under a profile loads the rootfs-phase facts;
    # the stubbed dnf raises if the adapter ever asks it again.
    persisted_facts(tmp_path)
    (tmp_path / "work" / "cyclonedx-file-inventory.json").write_text(
        json.dumps({"/bin/busybox": [{"path": "/bin/busybox"}]}))
    facts, events, calls = run_export(
        tmp_path, {"_IMAGE_RECIPE": "1",
                   "CYCLONEDX_PROFILE": "TR-03183-2",
                   "_INSTALLED_PACKAGES_ERROR": "1"},
        deploy_phase=True, functions=("export_cyclonedx",))
    assert ("fatal",) not in [e[0] for e in events]
    assert "image_list_installed_packages" not in calls
    assert facts["runtime_recipes"] == PERSISTED["runtime_recipes"]
    assert facts["image_install_recipes"] == PERSISTED["image_install_recipes"]
    assert facts["runtime_edges"] == {"base-files": ["busybox"],
                                      "busybox": []}
    assert facts["fragments"] == PERSISTED["fragments"]


def test_deploy_phase_without_persisted_facts_fails_deterministically(tmp_path):
    with pytest.raises(Fatal) as excinfo:
        run_export(tmp_path, {"_IMAGE_RECIPE": "1",
                              "CYCLONEDX_PROFILE": "TR-03183-2",
                              "_INSTALLED_PACKAGES_ERROR": "1"},
                   deploy_phase=True, functions=("export_cyclonedx",))
    message = str(excinfo.value)
    assert FACTS_NAME in message
    assert "do_rootfs" in message


def test_rootfs_phase_persists_the_assembled_facts(tmp_path):
    facts, _events, _calls = run_export(
        tmp_path, {"_IMAGE_RECIPE": "1",
                   "CYCLONEDX_PROFILE": "TR-03183-2",
                   "_INSTALLED_PACKAGES": ["pkg-busybox", "pkg-base-files"],
                   "_IMAGE_INSTALL_RECIPES": ["packagegroup-core-boot"],
                   "_BUILDTIME_RECIPES": ["cmake", "busybox"],
                   "CYCLONEDX_EXTRA_RUNTIME_RECIPES": "optee-os",
                   "_EDGES": {"busybox": ["base-files"]}},
        functions=("export_cyclonedx",))
    stored = json.loads((tmp_path / "work" / FACTS_NAME).read_text())
    assert stored["runtime_recipes"] == facts["runtime_recipes"]
    assert stored["image_install_recipes"] == facts["image_install_recipes"]
    assert stored["runtime_edges"] == facts["runtime_edges"]
    assert stored["fragments"] == facts["fragments"]
    assert stored["runtime_recipes"] == ["base-files", "busybox", "optee-os"]
    assert stored["image_install_recipes"] == ["optee-os",
                                               "packagegroup-core-boot"]
    assert stored["recipes"] == ["base-files", "busybox", "cmake", "optee-os"]
    assert stored["runtime_edges"] == {"busybox": ["base-files"]}
    assert sorted(stored["fragments"]) == sorted(stored["recipes"])


def test_nonprofile_generation_persists_nothing(tmp_path):
    facts, _events, calls = run_export(
        tmp_path, {"_IMAGE_RECIPE": "1",
                   "_INSTALLED_PACKAGES": ["pkg-busybox"]},
        functions=("export_cyclonedx",))
    assert not (tmp_path / "work" / FACTS_NAME).exists()
    assert facts["runtime_recipes"] == ["busybox"]
    assert "image_list_installed_packages" in calls  # derived live, as before


def test_nonimage_recipe_persists_nothing_even_with_a_profile(tmp_path):
    _facts, _events, _calls = run_export(
        tmp_path, {"CYCLONEDX_PROFILE": "TR-03183-2",
                   "_INSTALLED_PACKAGES": ["pkg-busybox"]},
        functions=("export_cyclonedx",))
    assert not (tmp_path / "work" / FACTS_NAME).exists()
