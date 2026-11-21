#!/usr/bin/env python3
"""source_to_baseline.py Spring 추출 시험 — 컨트롤러 매핑 · 설정으로 열린 actuator · 경로 변수 형식.

    python standardize/api-bom/test_spring_extract.py

가짜 Spring 프로젝트를 시험 안에서 만든다. 실제 앱(spring-petclinic) 대조는 verify/petclinic/ 참고.
"""
import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "source_to_baseline.py")

OWNER = '''
package demo;

/**
 * Called before each and every @RequestMapping annotated method.   <- 주석 속 글자는 매핑이 아니다
 */
@Controller
@RequestMapping("/owners/{ownerId}")
class PetController {
    // @GetMapping("/commented-out")
    @GetMapping("/pets/new")
    public String initCreationForm(@PathVariable("ownerId") int ownerId) { return "form"; }

    @PostMapping({ "/pets/{petId}/edit", "/pets/{petId}/update" })
    public String processUpdate(@PathVariable("petId") int petId) { return "redirect:/"; }

    @RequestMapping(value = "/export", method = { RequestMethod.GET, RequestMethod.POST })
    public String export() { return "x"; }
}
'''

API = '''
package demo;

@Controller
class VetController {
    @GetMapping("/vets.html")
    public String page() { return "vets"; }

    @GetMapping({ "/vets" })
    public @ResponseBody Vets json() { return null; }

    @ResponseBody
    @GetMapping(path = "/vets/{id}", produces = "application/json")
    public Vet one(@PathVariable UUID id) { return null; }
}
'''

REST = '''
package demo;

@RestController
@RequestMapping("/api")
class StatusController {
    @GetMapping("status")
    public String status() { return "ok"; }
}
'''

POM = "<project><dependencies><dependency><artifactId>spring-boot-starter-actuator</artifactId></dependency></dependencies></project>"


def make_project(root, props):
    java = Path(root, "src/main/java/demo")
    java.mkdir(parents=True)
    (java / "PetController.java").write_text(OWNER, encoding="utf-8")
    (java / "VetController.java").write_text(API, encoding="utf-8")
    (java / "StatusController.java").write_text(REST, encoding="utf-8")
    res = Path(root, "src/main/resources")
    res.mkdir(parents=True)
    (res / "application.properties").write_text(props, encoding="utf-8")
    Path(root, "pom.xml").write_text(POM, encoding="utf-8")


def run(*args):
    out = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True, encoding="utf-8", check=True)
    return out.stdout


def extract(root):
    return {r["endpoint_key"]: r for r in csv.DictReader(io.StringIO(run("extract", root)))}


class SpringExtract(unittest.TestCase):
    def test_controller_mappings(self):
        with tempfile.TemporaryDirectory() as d:
            make_project(d, "management.endpoints.web.exposure.include=health,env\n")
            rows = extract(d)
            code = {k: r["kind"] for k, r in rows.items() if r["kind"] != "config"}
            self.assertEqual(code, {
                "GET /owners/{id}/pets/new": "page",          # 클래스 접두어 + 메서드 경로
                "POST /owners/{id}/pets/{id}/edit": "page",   # 경로 여러 개
                "POST /owners/{id}/pets/{id}/update": "page",
                "GET /owners/{id}/export": "page",            # @RequestMapping + RequestMethod 여러 개
                "POST /owners/{id}/export": "page",
                "GET /vets.html": "page",
                "GET /vets": "api",                           # @ResponseBody (반환형 앞)
                "GET /vets/{id}": "api",                      # @ResponseBody (애노테이션 위)
                "GET /api/status": "api",                     # @RestController, 앞 슬래시 없는 경로
            })
            self.assertNotIn("GET /", rows)                   # 주석 속 @RequestMapping
            self.assertFalse(any("commented-out" in k for k in rows))
            self.assertEqual(rows["GET /vets"]["decision"], "review")       # 화면에 안 쓰이는 데이터 API = 확인 대상
            self.assertEqual(rows["GET /vets.html"]["decision"], "active")
            self.assertTrue(rows["GET /owners/{id}/pets/new"]["source"].endswith("PetController.java:11"))

    def test_actuator_from_config(self):
        with tempfile.TemporaryDirectory() as d:
            make_project(d, "management.endpoints.web.exposure.include=*\n"
                            "management.endpoints.web.exposure.exclude=env,beans\n"
                            "management.endpoints.web.base-path=/manage\n")
            cfg = {k for k, r in extract(d).items() if r["kind"] == "config"}
            self.assertIn("GET /manage", cfg)
            self.assertIn("GET /manage/threaddump", cfg)
            self.assertIn("POST /manage/loggers/{id}", cfg)                # 쓰기 작업
            self.assertNotIn("GET /manage/env", cfg)                       # exclude
            self.assertNotIn("GET /manage/beans", cfg)
            self.assertFalse(any(k.startswith("GET /actuator") for k in cfg))

    def test_actuator_default_is_health_only(self):
        with tempfile.TemporaryDirectory() as d:
            make_project(d, "spring.application.name=demo\n")
            cfg = {k for k, r in extract(d).items() if r["kind"] == "config"}
            self.assertEqual(cfg, {"GET /actuator", "GET /actuator/health"})

    def test_no_actuator_dependency(self):
        with tempfile.TemporaryDirectory() as d:
            make_project(d, "management.endpoints.web.exposure.include=*\n")
            Path(d, "pom.xml").write_text("<project/>", encoding="utf-8")
            self.assertFalse(any(r["kind"] == "config" for r in extract(d).values()))

    def test_path_param_types_reach_openapi(self):
        with tempfile.TemporaryDirectory() as d:
            make_project(d, "management.endpoints.web.exposure.include=health\n")
            csv_path, bom_path = Path(d, "baseline.csv"), Path(d, "bom.json")
            csv_path.write_text(run("extract", d), encoding="utf-8")
            bom_path.write_text(run("cyclonedx", str(csv_path), d, "--app", "demo"), encoding="utf-8")
            spec = json.loads(run("openapi", str(bom_path), "--include-pages"))
            params = lambda path, m: [(p["name"], p["schema"]) for p in spec["paths"][path][m]["parameters"]]
            self.assertEqual(params("/owners/{id}/pets/new", "get"), [("id", {"type": "integer"})])
            self.assertEqual(params("/owners/{id}/pets/{id2}/edit", "post"),   # 이름 겹침 방지 id2
                             [("id", {"type": "integer"}), ("id2", {"type": "integer"})])
            self.assertNotIn("/vets/{id}", spec["paths"])                      # review → 허용 목록 밖
            self.assertNotIn("/actuator/health", spec["paths"])                # config 기본값 review → 밖
            bom = json.loads(bom_path.read_text(encoding="utf-8"))
            self.assertEqual(bom["metadata"]["component"]["name"], "demo")
            self.assertIn({"ref": "app:demo"}, bom["dependencies"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
