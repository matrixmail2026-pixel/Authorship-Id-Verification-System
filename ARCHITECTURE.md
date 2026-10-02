# Authorship Verification System — Architecture Diagram

## Current State vs. Recommended Structure

### 📊 Current Repository Structure

```
Authorship-Id-Verification-System/
│
├── 📄 README.md                          # Project documentation
├── 📄 Readme.md                          # Duplicate documentation
├── 📄 LICENSE                            # GPL-3.0
│
├── 🐍 Finite-State-Recovery-Engine.py    # Single monolithic file (~1,872 lines)
│                                         # Contains: LT codec, GF(2) solver,
│                                         # Raptor encoder, crypto, tests, demo
│
├── 🖼️  image_d1778830.jpg                # Supporting image assets
├── 🖼️  1790413269034.jpg
├── 🖼️  3a487b80-a9cb-11f1-9e1c-4f46d89710d8 (1).png
│
└── 📁 .github/
    └── 📁 workflows/
        └── 📄 python-package-conda.yml   # CI: conda build, lint, pytest
```

**Issues with current structure:**
- ❌ Single monolithic file (1,872 lines)
- ❌ No separate tests directory
- ❌ Missing `environment.yml` (referenced in CI but not in repo)
- ❌ No module hierarchy
- ❌ Documentation files not in docs/ folder
- ❌ No setup.py / pyproject.toml
- ❌ Images at root level

---

## 🏗️ Recommended Project Architecture

```
Authorship-Id-Verification-System/
│
├── 📄 README.md                          # Main project overview
├── 📄 LICENSE                            # GPL-3.0
├── 📄 pyproject.toml                     # Modern Python packaging
├── 📄 setup.py                           # Legacy compatibility
├── 📄 environment.yml                    # Conda environment (fix CI)
├── 📄 ARCHITECTURE.md                    # This file
│
├── 📁 src/
│   └── 📁 authorship_verification/       # Main package
│       ├── 📄 __init__.py               # Package exports
│       │
│       ├── 📁 core/                      # Core cryptographic primitives
│       │   ├── 📄 __init__.py
│       │   ├── 📄 merkle_tree.py        # Merkle tree & SHA-256 hashing
│       │   ├── 📄 certificates.py       # Ed25519 certificate generation/verification
│       │   └── 📄 crypto_utils.py       # Shared crypto utilities
│       │
│       ├── 📁 encoding/                  # Data transformation & recovery
│       │   ├── 📄 __init__.py
│       │   ├── 📄 soliton.py            # Robust Soliton distribution
│       │   ├── 📄 lt_codec.py           # LT Encoder/Decoder
│       │   ├── 📄 raptor.py             # Raptor-style encoder/decoder
│       │   ├── 📄 constraints.py        # GF(2) constraint representation
│       │   └── 📄 solver.py             # GF(2) linear solver
│       │
│       ├── 📁 state_machine/             # Finite-state recovery engine
│       │   ├── 📄 __init__.py
│       │   ├── 📄 state.py              # AllThingsState class
│       │   ├── 📄 boundary.py           # Boundary/closure detection
│       │   └── 📄 recovery.py           # State recovery orchestration
│       │
│       └── 📁 cli/                       # Command-line interface
│           ├── 📄 __init__.py
│           ├── 📄 main.py               # CLI entrypoint
│           ├── 📄 demo.py               # Demonstration commands
│           └── 📄 experiment.py         # Experiment runner
│
├── 📁 tests/                             # Test suite
│   ├── 📄 __init__.py
│   ├── 📄 conftest.py                   # Pytest fixtures
│   │
│   ├── 📁 unit/                          # Unit tests
│   │   ├── 📄 test_crypto.py            # Core crypto tests
│   │   ├── 📄 test_soliton.py           # Soliton distribution tests
│   │   ├── 📄 test_lt_codec.py          # LT encoder/decoder tests
│   │   ├── 📄 test_gf2_solver.py        # GF(2) solver tests
│   │   ├── 📄 test_raptor.py            # Raptor encoder tests
│   │   └── 📄 test_state_machine.py     # State machine tests
│   │
│   └── 📁 integration/                   # Integration tests
│       ├── 📄 test_full_recovery.py     # End-to-end recovery
│       ├── 📄 test_certificate.py       # Certificate gen/verify flow
│       └── 📄 test_tamper_detection.py  # Tamper detection scenarios
│
├── 📁 docs/                              # Extended documentation
│   ├── 📄 THEORY.md                     # Detailed cryptographic theory
│   ├── 📄 API.md                        # Public API reference
│   ├── 📄 EXAMPLES.md                   # Usage examples
│   ├── 📄 ALGORITHMS.md                 # Algorithm descriptions
│   └── 📁 images/                       # Documentation images
│       ├── 📄 image_d1778830.jpg
│       ├── 📄 1790413269034.jpg
│       └── 📄 3a487b80-a9cb-11f1-9e1c-4f46d89710d8.png
│
├── 📁 .github/
│   ├── 📁 workflows/
│   │   ├── 📄 python-package-conda.yml  # Conda build CI
│   │   ├── 📄 tests.yml                 # Test matrix (Python versions)
│   │   └── 📄 lint.yml                  # Code quality checks
│   │
│   └── 📁 ISSUE_TEMPLATE/
│       ├── 📄 bug_report.md
│       └── 📄 feature_request.md
│
└── 📄 .gitignore                         # Standard Python .gitignore
```

---

## 📦 Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────┐
│                       CLI / Demo Layer                      │
│                    (authorship_verification.cli)            │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ├─→ State Machine Layer
                 │   (authorship_verification.state_machine)
                 │       ├── state.py
                 │       ├── boundary.py
                 │       └── recovery.py
                 │
                 └─→ Encoding Layer
                     (authorship_verification.encoding)
                         ├── lt_codec.py ────→ soliton.py
                         ├── raptor.py ────→ lt_codec.py
                         ├── solver.py ────→ constraints.py
                         └── constraints.py
                             │
                             └─→ Core Layer
                                 (authorship_verification.core)
                                     ├── crypto_utils.py
                                     ├── certificates.py
                                     └── merkle_tree.py
                                         ├── Uses: SHA-256
                                         ├── Uses: Ed25519
                                         └── Uses: ECDSA
```

---

## 🔄 Data Flow Architecture

### Certificate Generation & Verification Flow

```
┌────────────────────┐
│  Source Code File  │
└─────────┬──────────┘
          │
          ├─→ ┌─────────────────────────────┐
          │   │ SHA-256 Hash Computation    │ (crypto_utils.py)
          │   │ → Document Integrity       │
          │   └────────────┬────────────────┘
          │                │
          └─→ ┌────────────▼────────────────┐
              │ Ed25519 Key Generation      │ (certificates.py)
              │ → Private/Public Key Pair   │
              └────────────┬────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │ Metadata Canonicalization       │ (certificates.py)
          │ {author, engine, timestamp...}  │
          └────────────┬────────────────────┘
                       │
          ┌────────────▼────────────────┐
          │ Sign Metadata with Private  │ (certificates.py)
          │ → ECDSA Signature           │
          └────────────┬────────────────┘
                       │
          ┌────────────▼────────────────┐
          │ Certificate Object Created  │
          │ {metadata, pubkey, sig}     │
          └────────────┬────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
        ├─→ Storage/Distribution      ├─→ Verification Flow
        │                             │
        │                    ┌────────▼────────┐
        │                    │ Load Certificate│
        │                    │ + Source Code   │
        │                    └────────┬────────┘
        │                             │
        │                    ┌────────▼────────┐
        │                    │ Verify Signature│
        │                    │ with Public Key │
        │                    └────────┬────────┘
        │                             │
        │                    ┌────────▼──────────┐
        │                    │ Verify SHA-256    │
        │                    │ Integrity         │
        │                    └────────┬──────────┘
        │                             │
        │                    ┌────────▼──────────┐
        │                    │ VERIFIED or FAIL  │
        │                    └───────────────────┘
        │
        └─────────────────────────────────────────→ (returned to user)
```

---

### LT / Raptor Recovery Flow

```
┌─────────────────────────────────┐
│ Source Data (k symbols)         │
│ [0x12, 0x34, 0x56, 0x78, 0x9A] │
└────────────┬────────────────────┘
             │
             ├─→ LT Encoder (lt_codec.py)
             │   1. Sample degree from Soliton distribution (soliton.py)
             │   2. XOR random subset of source symbols
             │   3. Generate constraint packet (seed, data)
             │
             └─→ ┌──────────────────────────┐
                 │ Constraint Packets Queue │
                 │ (lossy channel, may drop)│
                 └────────────┬─────────────┘
                              │
                 ┌────────────▼──────────────┐
                 │ AllThingsDecoder (core)   │
                 │                          │
                 │ 1. Receive packets       │
                 │ 2. Store as GF(2)        │
                 │    constraints           │
                 │ 3. Ripple/Peel phase:    │
                 │    - Solve degree-1      │
                 │    - Back-substitute     │
                 │    - Propagate known     │
                 │    - Repeat until fixed  │
                 │                          │
                 │ 4. Boundary check:       │
                 │    - All states known?   │
                 │    - Inconsistent?       │
                 │    - Unsolved but can't  │
                 │      reduce?             │
                 │                          │
                 │ 5. Residual Recovery:    │
                 │    - Extract unresolved  │
                 │      equations           │
                 │    - Solve with GF(2)    │
                 │      linear solver       │
                 │      (solver.py)         │
                 │    - Back-substitute &   │
                 │      rebuild            │
                 │                          │
                 └────────────┬──────────────┘
                              │
                 ┌────────────▼──────────────┐
                 │ Recovered Source         │
                 │ (or FAILURE if boundary) │
                 └──────────────────────────┘
```

---

## 🧪 Testing Strategy

### Unit Test Layers

| Layer | Test File | Coverage |
|-------|-----------|----------|
| **Core Crypto** | `test_crypto.py` | SHA-256, Ed25519, signature verification |
| **Soliton Distribution** | `test_soliton.py` | Robust Soliton probabilities, sampling |
| **LT Codec** | `test_lt_codec.py` | Encoder packet gen, determinism, seed safety |
| **GF(2) Solver** | `test_gf2_solver.py` | Linear system solving, rank/pivot detection, inconsistency |
| **Raptor Encoder** | `test_raptor.py` | Precode gen, combined symbol encoding, determinism |
| **State Machine** | `test_state_machine.py` | State transitions, closure detection, boundary conditions |

### Integration Test Layers

| Test File | Scenario |
|-----------|----------|
| `test_full_recovery.py` | End-to-end encode → channel loss → decode → verify identity |
| `test_certificate.py` | Gen cert → sign → verify → fingerprint consistency |
| `test_tamper_detection.py` | Tamper payload → cert fails, unmodified → cert passes |

---

## 🔧 Build & CI/CD Pipeline

### Proposed GitHub Actions Workflow

```
.github/workflows/
│
├── tests.yml
│   └── On: [push, pull_request]
│       ├── Python 3.9, 3.10, 3.11, 3.12
│       ├── OS: ubuntu-latest, macos-latest, windows-latest
│       ├── Steps:
│       │   ├── Checkout
│       │   ├── Set up Python
│       │   ├── pip install -e .[dev]
│       │   ├── pytest --cov=authorship_verification
│       │   └── Upload coverage to codecov
│       │
│       └── Status Badge: [![Tests](https://github.com/.../workflows/tests.yml/badge.svg)]()
│
├── lint.yml
│   └── On: [push, pull_request]
│       ├── Steps:
│       │   ├── black --check src/ tests/
│       │   ├── isort --check-only src/ tests/
│       │   ├── flake8 src/ tests/ --max-line-length=120
│       │   ├── mypy src/ --strict
│       │   └── pylint src/
│       │
│       └── Status Badge: [![Lint](https://github.com/.../workflows/lint.yml/badge.svg)]()
│
└── python-package-conda.yml  (EXISTING — should be retained/refactored)
    └── On: [push]
        ├── Set up conda
        ├── pip install -e .[dev]
        ├── pytest
        └── Coverage report
```

---

## 📋 Configuration Files to Create

### pyproject.toml
```toml
[build-system]
requires = ["setuptools>=61", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "authorship-verification"
version = "0.1.0"
description = "Cryptographic framework for immutable digital authorship proof"
authors = [
    {name = "Christopher Thomas Ronio", email = "..."},
    {name = "Jeremy James Grice Rosa", email = "..."}
]
license = {text = "GPL-3.0"}
requires-python = ">=3.9"
dependencies = [
    "cryptography>=41.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "black>=23.0",
    "isort>=5.0",
    "flake8>=6.0",
    "mypy>=1.0",
    "pylint>=3.0",
]

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--cov=authorship_verification --cov-report=html"

[tool.black]
line-length = 88

[tool.isort]
profile = "black"
```

### environment.yml (Fix for CI)
```yaml
name: authorship-verification
channels:
  - conda-forge
  - defaults
dependencies:
  - python=3.10
  - pip
  - pip:
    - -e .
    - pytest
    - pytest-cov
    - cryptography>=41.0.0
    - black
    - isort
    - flake8
    - mypy
```

---

## 🎯 Refactoring Roadmap

### Phase 1: Structural Reorganization (Week 1)
- [ ] Create `src/authorship_verification/` package
- [ ] Split monolithic file into modules (10 files)
- [ ] Create `tests/` directory structure
- [ ] Add `pyproject.toml`, `setup.py`, `environment.yml`
- [ ] Move images to `docs/images/`
- [ ] Update `.gitignore`

### Phase 2: Testing & CI/CD (Week 2)
- [ ] Write unit tests for each module (~50 tests)
- [ ] Write integration tests (~15 tests)
- [ ] Create GitHub Actions workflows
- [ ] Set up coverage reporting
- [ ] Add linting & type checking

### Phase 3: Documentation (Week 3)
- [ ] Move docs to `docs/` folder
- [ ] Create `API.md` with module exports
- [ ] Add docstrings to all public functions
- [ ] Create example scripts in `docs/examples/`
- [ ] Add architecture diagram to README

### Phase 4: Polish & Release (Week 4)
- [ ] Version bump (0.1.0)
- [ ] Release notes & CHANGELOG
- [ ] Tag release on GitHub
- [ ] Update badges in README
- [ ] Prepare PyPI submission (optional)

---

## 📚 Key Metrics After Refactor

| Metric | Before | After |
|--------|--------|-------|
| **Main files** | 1 | 15 |
| **Package hierarchy** | Flat | Modular (4 layers) |
| **Test coverage** | 0% | ~85%+ |
| **Documentation** | README + code | 5 dedicated docs |
| **CI/CD workflows** | 1 (incomplete) | 3 (complete) |
| **Lines per file** | ~1,872 | ~150–300 avg |
| **Type annotations** | None | Full coverage |
| **Linting** | flake8 only | flake8 + black + isort + mypy + pylint |

---

## 🚀 Benefits of This Architecture

✅ **Maintainability** — Modular code is easier to debug, test, and extend  
✅ **Scalability** — New features can be added without touching core  
✅ **Testability** — Unit isolation enables thorough test coverage  
✅ **Professionalism** — Standard Python layout attracts contributors  
✅ **Documentation** — Clear separation enables dedicated API docs  
✅ **CI/CD** — Automated testing & linting catches issues early  
✅ **Packaging** — `pyproject.toml` enables proper package distribution  
✅ **Onboarding** — New developers understand repo structure instantly  

---

## 📞 Next Steps

Would you like me to:

1. **Auto-generate the new directory structure** (create skeleton files)?
2. **Refactor one module at a time** (e.g., extract `core/crypto_utils.py`)?
3. **Create the pyproject.toml & GitHub Actions workflows** (CI/CD setup)?
4. **Generate unit tests** for the modules?
5. **Merge duplicate README files** into one clean version?

Let me know which phase to start with!
