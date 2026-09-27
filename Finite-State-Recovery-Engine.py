"""
======================================================================
{ALL_THINGS}
Cryptographically Certified Finite-State Constraint & Recovery Engine
======================================================================

Author:
    Christopher Thomas Ronio

Framework:
    {ALL_THINGS}

Cryptographic identity:
    Ed25519 signature
    SHA-256 source commitment

Structural pipeline:

    SOURCE STATES
         |
         v
    TRANSFORMATION
         |
         v
    CONSTRAINTS
         |
         v
    OBSERVATION
         |
         v
    PEELING
         |
         +----------------------+
         |                      |
         v                      v
      CLOSED                BOUNDARY
                                |
                                v
                         GF(2) RECOVERY
                                |
                                v
                             CLOSED

Cryptographic pipeline:

    SOURCE CODE
         |
         v
       SHA-256
         |
         v
      METADATA
         |
         v
      Ed25519
         |
         v
     CERTIFICATE
         |
         v
      VERIFY
         |
         +---- hash matches
         |
         +---- signature valid
         |
         v
       VERIFIED

Important:
    The certificate proves integrity/authenticity of the signed
    artifact relative to the generated Ed25519 key.

    It does NOT mathematically prove the correctness of the
    {ALL_THINGS} theory itself.

    The GF(2) engine is a finite-state computational model.
"""


import hashlib
import json
import math
import random
import time
from collections import defaultdict

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


# ======================================================================
# 0. {ALL_THINGS} STATE MODEL
# ======================================================================

class AllThingsState:
    """
    Generic finite-state representation.

    A system contains:

        STATES
        KNOWN STATES
        UNRESOLVED STATES
        BOUNDARY
        CLOSURE
    """

    def __init__(self, values):
        self.values = list(values)
        self.k = len(self.values)

    @property
    def known(self):
        return sum(
            value is not None
            for value in self.values
        )

    @property
    def unresolved(self):
        return self.k - self.known

    @property
    def closed(self):
        return self.unresolved == 0

    def boundary(self):
        return {
            "total": self.k,
            "known": self.known,
            "unresolved": self.unresolved,
            "closed": self.closed,
        }


# ======================================================================
# 1. ROBUST SOLITON DISTRIBUTION
# ======================================================================

def robust_soliton(k, c=0.1, delta=0.05):
    """
    Robust Soliton distribution over degrees 1..k.

    Returns:
        normalized probabilities where result[0] = P(degree=1)
    """

    if k < 1:
        raise ValueError("k must be >= 1")

    if not (0 < delta < 1):
        raise ValueError("delta must be in (0, 1)")

    # Ideal Soliton distribution
    rho = [0.0] * (k + 1)

    rho[1] = 1.0 / k

    for degree in range(2, k + 1):
        rho[degree] = (
            1.0 /
            (degree * (degree - 1))
        )

    # Robust correction
    tau = [0.0] * (k + 1)

    R = (
        c *
        math.log(k / delta) *
        math.sqrt(k)
        if c > 0
        else 0.0
    )

    if R > 0:

        K = int(k / R)

        K = max(
            1,
            min(K, k)
        )

        for degree in range(1, K):
            tau[degree] = (
                R /
                (degree * k)
            )

        correction = (
            R *
            math.log(R / delta) /
            k
        )

        tau[K] += correction

    mu = [
        rho[d] + tau[d]
        for d in range(k + 1)
    ]

    beta = sum(mu)

    if beta <= 0:
        raise ValueError(
            "degenerate distribution"
        )

    return [
        value / beta
        for value in mu
    ][1:]


def sample_degree(mu, rng):
    """Inverse-CDF degree sampling."""

    random_value = rng.random()
    cumulative = 0.0

    for index, probability in enumerate(mu):

        cumulative += probability

        if random_value <= cumulative:
            return index + 1

    return len(mu)


# ======================================================================
# 2. LT TRANSFORMATION
# ======================================================================

class LTEncoder:
    """
    Transform source states into XOR constraint packets.

    Each packet is deterministic with respect to its seed.
    """

    def __init__(
        self,
        source,
        c=0.1,
        delta=0.05,
    ):

        self.source = list(source)
        self.k = len(self.source)

        if self.k < 1:
            raise ValueError(
                "source must not be empty"
            )

        self.c = c
        self.delta = delta

        self.mu = robust_soliton(
            self.k,
            c,
            delta,
        )

    def packet(self, seed):

        rng = random.Random(seed)

        degree = sample_degree(
            self.mu,
            rng,
        )

        indices = rng.sample(
            range(self.k),
            degree,
        )

        data = 0

        for index in indices:
            data ^= self.source[index]

        return seed, data


# ======================================================================
# 3. GF(2) CONSTRAINT
# ======================================================================

class Constraint:
    """
    Represents:

        XOR(x_i for i in indices) = value

    over GF(2).
    """

    def __init__(
        self,
        indices,
        value,
    ):

        self.indices = set(indices)
        self.value = value

    @property
    def degree(self):
        return len(self.indices)

    def reduce(
        self,
        index,
        value,
    ):

        if index not in self.indices:
            return False

        self.indices.remove(index)
        self.value ^= value

        return True


# ======================================================================
# 4. GF(2) LINEAR SOLVER
# ======================================================================

def gf2_solve(
    equations,
    variables,
):
    """
    Solve:

        XOR(x_i for i in S_j) = b_j

    over GF(2).

    Returns:
        dictionary of uniquely determined variables

    Returns None when the residual system is inconsistent
    or underdetermined.
    """

    variables = sorted(variables)

    if not variables:
        return {}

    position = {
        variable: bit
        for bit, variable in enumerate(variables)
    }

    rows = []

    for equation in equations:

        mask = 0

        for variable in equation.indices:

            if variable in position:
                mask ^= (
                    1 <<
                    position[variable]
                )

        rows.append([
            mask,
            equation.value,
        ])

    rank = 0
    pivot_columns = []

    for column in range(len(variables)):

        pivot = None

        for row in range(
            rank,
            len(rows),
        ):

            if rows[row][0] & (
                1 << column
            ):

                pivot = row
                break

        if pivot is None:
            continue

        rows[rank], rows[pivot] = (
            rows[pivot],
            rows[rank],
        )

        for row in range(len(rows)):

            if row == rank:
                continue

            if rows[row][0] & (
                1 << column
            ):

                rows[row][0] ^= (
                    rows[rank][0]
                )

                rows[row][1] ^= (
                    rows[rank][1]
                )

        pivot_columns.append(column)
        rank += 1

    # Detect:
    #
    #     0 = nonzero
    #
    for mask, value in rows:

        if mask == 0 and value != 0:
            return None

    # Unique solution requires full rank.
    if rank < len(variables):
        return None

    solution = {}

    for row, column in enumerate(
        pivot_columns
    ):

        solution[
            variables[column]
        ] = rows[row][1]

    return solution


# ======================================================================
# 5. {ALL_THINGS} DECODER
# ======================================================================

class AllThingsDecoder:

    def __init__(
        self,
        k,
        c=0.1,
        delta=0.05,
        enable_residual=True,
    ):

        if k < 1:
            raise ValueError(
                "k must be >= 1"
            )

        self.k = k
        self.c = c
        self.delta = delta

        self.enable_residual = (
            enable_residual
        )

        self.mu = robust_soliton(
            k,
            c,
            delta,
        )

        self.constraints = {}
        self.next_id = 0

        self.by_symbol = defaultdict(set)
        self.ripple = set()

        self.decoded = [
            None
            for _ in range(k)
        ]

        self.solved_count = 0
        self.received = 0
        self.inconsistent = False

    # ------------------------------------------------------------------
    # RECEIVE
    # ------------------------------------------------------------------

    def add(
        self,
        seed,
        data,
    ):

        self.received += 1

        rng = random.Random(seed)

        degree = sample_degree(
            self.mu,
            rng,
        )

        indices = set(
            rng.sample(
                range(self.k),
                degree,
            )
        )

        # Eliminate already known states.
        for index in list(indices):

            value = self.decoded[index]

            if value is not None:

                data ^= value
                indices.remove(index)

        # Completely reduced equation.
        if not indices:

            if data != 0:
                self.inconsistent = True
                return False

            return True

        equation = Constraint(
            indices,
            data,
        )

        equation_id = self.next_id
        self.next_id += 1

        self.constraints[
            equation_id
        ] = equation

        for index in indices:

            self.by_symbol[
                index
            ].add(equation_id)

        if equation.degree == 1:
            self.ripple.add(
                equation_id
            )

        return True

    # ------------------------------------------------------------------
    # REDUCTION
    # ------------------------------------------------------------------

    def _reduce_constraint(
        self,
        equation_id,
        index,
        value,
    ):

        equation = self.constraints.get(
            equation_id
        )

        if equation is None:
            return

        if not equation.reduce(
            index,
            value,
        ):
            return

        self.by_symbol[
            index
        ].discard(
            equation_id
        )

        if equation.degree == 1:

            self.ripple.add(
                equation_id
            )

        elif equation.degree == 0:

            if equation.value != 0:
                self.inconsistent = True

            del self.constraints[
                equation_id
            ]

            self.ripple.discard(
                equation_id
            )

    # ------------------------------------------------------------------
    # PEEL
    # ------------------------------------------------------------------

    def peel(self):

        progress = True

        while progress:

            progress = False

            while self.ripple:

                equation_id = (
                    self.ripple.pop()
                )

                equation = (
                    self.constraints.get(
                        equation_id
                    )
                )

                if equation is None:
                    continue

                if equation.degree != 1:
                    continue

                index = next(
                    iter(
                        equation.indices
                    )
                )

                value = equation.value

                if (
                    self.decoded[index]
                    is not None
                ):

                    if (
                        self.decoded[index]
                        != value
                    ):
                        self.inconsistent = True

                    del self.constraints[
                        equation_id
                    ]

                    continue

                # ------------------------------------------------------
                # STATE RESOLUTION
                # ------------------------------------------------------

                self.decoded[index] = value
                self.solved_count += 1
                progress = True

                del self.constraints[
                    equation_id
                ]

                connected = list(
                    self.by_symbol[index]
                )

                for other_id in connected:

                    self._reduce_constraint(
                        other_id,
                        index,
                        value,
                    )

                self.by_symbol[
                    index
                ].clear()

            if self.solved_count == self.k:
                return True

            # ----------------------------------------------------------
            # RESIDUAL BOUNDARY
            # ----------------------------------------------------------

            if self.enable_residual:

                recovered = (
                    self._residual_recovery()
                )

                if recovered:
                    progress = True

        return self.is_complete()

    # ------------------------------------------------------------------
    # RESIDUAL RECOVERY
    # ------------------------------------------------------------------

    def _residual_recovery(self):

        unresolved = {
            index
            for index, value
            in enumerate(
                self.decoded
            )
            if value is None
        }

        if not unresolved:
            return False

        equations = []

        for equation in (
            self.constraints.values()
        ):

            residual = (
                equation.indices
                & unresolved
            )

            if residual:

                equations.append(
                    Constraint(
                        residual,
                        equation.value,
                    )
                )

        if not equations:
            return False

        solution = gf2_solve(
            equations,
            unresolved,
        )

        if solution is None:
            return False

        progress = False

        for index, value in (
            solution.items()
        ):

            if self.decoded[index] is None:

                self.decoded[index] = value
                self.solved_count += 1
                progress = True

        if progress:
            self._rebuild_constraints()

        return progress

    # ------------------------------------------------------------------
    # REBUILD
    # ------------------------------------------------------------------

    def _rebuild_constraints(self):

        new_constraints = {}
        new_index = defaultdict(set)
        new_ripple = set()

        for equation_id, equation in (
            self.constraints.items()
        ):

            indices = set(
                equation.indices
            )

            value = equation.value

            for index in list(indices):

                known = self.decoded[index]

                if known is not None:

                    value ^= known
                    indices.remove(index)

            if not indices:

                if value != 0:
                    self.inconsistent = True

                continue

            new_equation = Constraint(
                indices,
                value,
            )

            new_constraints[
                equation_id
            ] = new_equation

            for index in indices:

                new_index[
                    index
                ].add(equation_id)

            if new_equation.degree == 1:

                new_ripple.add(
                    equation_id
                )

        self.constraints = (
            new_constraints
        )

        self.by_symbol = new_index
        self.ripple = new_ripple

    # ------------------------------------------------------------------
    # BOUNDARY
    # ------------------------------------------------------------------

    def boundary(self):

        unresolved = [
            index
            for index, value
            in enumerate(
                self.decoded
            )
            if value is None
        ]

        return {
            "total_states": self.k,
            "solved_states": self.solved_count,
            "unresolved_states": len(
                unresolved
            ),
            "received_packets": self.received,
            "active_constraints": len(
                self.constraints
            ),
            "boundary": bool(
                unresolved
            ),
            "closed": not unresolved,
            "inconsistent": self.inconsistent,
        }

    def is_complete(self):

        return (
            self.solved_count ==
            self.k
        )

    def result(self):

        if not self.is_complete():

            raise RuntimeError(
                f"system not closed: "
                f"{self.solved_count}/"
                f"{self.k}"
            )

        return list(
            self.decoded
        )


# ======================================================================
# 6. PRECODE
# ======================================================================

def ldpc_precode(
    k,
    rate=0.05,
    seed=0,
    degree=3,
):

    if k < 1:
        raise ValueError(
            "k must be >= 1"
        )

    rng = random.Random(seed)

    rows = []

    row_count = max(
        1,
        int(rate * k),
    )

    degree = min(
        degree,
        k,
    )

    for _ in range(row_count):

        indices = tuple(
            sorted(
                rng.sample(
                    range(k),
                    degree,
                )
            )
        )

        rows.append(indices)

    return rows


# ======================================================================
# 7. RAPTOR-STYLE {ALL_THINGS}
# ======================================================================

class AllThingsRaptorEncoder:

    def __init__(
        self,
        source,
        c=0.1,
        delta=0.05,
        precode_rate=0.05,
        precode_seed=0,
    ):

        self.source = list(source)
        self.k = len(self.source)

        self.pre = ldpc_precode(
            self.k,
            precode_rate,
            precode_seed,
        )

        self.parity = []

        for row in self.pre:

            value = 0

            for index in row:
                value ^= self.source[index]

            self.parity.append(value)

        self.combined = (
            self.source +
            self.parity
        )

        self.n = len(
            self.combined
        )

        self.lt = LTEncoder(
            self.combined,
            c,
            delta,
        )

    def packet(self, seed):

        return self.lt.packet(seed)


class AllThingsRaptorDecoder:

    def __init__(
        self,
        k,
        c=0.1,
        delta=0.05,
        precode_rate=0.05,
        precode_seed=0,
    ):

        self.k = k

        self.pre = ldpc_precode(
            k,
            precode_rate,
            precode_seed,
        )

        self.m = len(self.pre)
        self.n = k + self.m

        self.lt = AllThingsDecoder(
            self.n,
            c,
            delta,
            enable_residual=True,
        )

    def add(
        self,
        seed,
        data,
    ):

        return self.lt.add(
            seed,
            data,
        )

    def peel(self):

        self.lt.peel()

        if self.is_complete():
            return True

        unresolved = {
            index
            for index, value
            in enumerate(
                self.lt.decoded
            )
            if value is None
        }

        equations = []

        # --------------------------------------------------------------
        # PRECODE CONSTRAINTS
        # --------------------------------------------------------------

        for parity_number, row in (
            enumerate(self.pre)
        ):

            parity_index = (
                self.k +
                parity_number
            )

            involved = set(row)
            involved.add(
                parity_index
            )

            rhs = 0
            residual = set()

            for index in involved:

                value = (
                    self.lt.decoded[index]
                )

                if value is None:
                    residual.add(index)

                else:
                    rhs ^= value

            if residual:

                equations.append(
                    Constraint(
                        residual,
                        rhs,
                    )
                )

        # --------------------------------------------------------------
        # SURVIVING LT CONSTRAINTS
        # --------------------------------------------------------------

        for equation in (
            self.lt.constraints.values()
        ):

            residual = (
                equation.indices
                & unresolved
            )

            if residual:

                equations.append(
                    Constraint(
                        residual,
                        equation.value,
                    )
                )

        # --------------------------------------------------------------
        # COMBINED RESIDUAL SOLUTION
        # --------------------------------------------------------------

        if unresolved and equations:

            solution = gf2_solve(
                equations,
                unresolved,
            )

            if solution is not None:

                for index, value in (
                    solution.items()
                ):

                    if (
                        self.lt.decoded[index]
                        is None
                    ):

                        self.lt.decoded[index] = value
                        self.lt.solved_count += 1

        return self.is_complete()

    def is_complete(self):

        return all(
            value is not None
            for value in
            self.lt.decoded[:self.k]
        )

    def result(self):

        if not self.is_complete():

            raise RuntimeError(
                "Raptor-style "
                "{ALL_THINGS} system "
                "is not closed"
            )

        return list(
            self.lt.decoded[:self.k]
        )

    def boundary(self):

        return {
            "source_states": self.k,
            "combined_states": self.n,
            "precode_constraints": self.m,
            "source_complete": self.is_complete(),
            "combined_solved": (
                self.lt.solved_count
            ),
            "combined_total": self.n,
            "received_packets": (
                self.lt.received
            ),
            "inconsistent": (
                self.lt.inconsistent
            ),
        }


# ======================================================================
# 8. CRYPTOGRAPHIC CERTIFICATE
# ======================================================================

CERTIFICATE_VERSION = "ALL_THINGS-CERT-1"


def canonical_json(data):
    """
    Deterministic JSON representation.

    The same metadata must produce exactly the same
    bytes before signing and verification.
    """

    return json.dumps(
        data,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    ).encode("utf-8")


def sha256_text(text):
    """Return SHA-256 hex digest of UTF-8 text."""

    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def generate_certificate(
    source_code,
    author="Christopher Thomas Ronio",
):
    """
    Create a self-contained Ed25519 certificate.

    The certificate binds:

        author
        engine name
        source SHA-256
        timestamp
        certificate version

    to an Ed25519 signature.
    """

    private_key = (
        ed25519.Ed25519PrivateKey.generate()
    )

    public_key = (
        private_key.public_key()
    )

    source_hash = sha256_text(
        source_code
    )

    metadata = {
        "certificate_version":
            CERTIFICATE_VERSION,

        "author":
            author,

        "engine":
            "{ALL_THINGS} "
            "Finite-State Engine",

        "engine_sha256":
            source_hash,

        "timestamp":
            int(time.time()),
    }

    payload = canonical_json(
        metadata
    )

    signature = (
        private_key.sign(payload)
    )

    public_key_pem = (
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    certificate = {
        "metadata": metadata,

        "public_key_pem":
            public_key_pem,

        "signature_hex":
            signature.hex(),
    }

    return (
        certificate,
        private_key,
    )


# ======================================================================
# 9. CERTIFICATE VERIFICATION
# ======================================================================

def verify_certificate(
    certificate,
    current_source_code,
):
    """
    Verify BOTH:

        1. Source SHA-256 integrity
        2. Ed25519 signature authenticity

    Returns True only when both succeed.
    """

    try:

        metadata = certificate[
            "metadata"
        ]

        # --------------------------------------------------------------
        # SOURCE INTEGRITY
        # --------------------------------------------------------------

        current_hash = sha256_text(
            current_source_code
        )

        if (
            current_hash
            != metadata["engine_sha256"]
        ):
            return False

        # --------------------------------------------------------------
        # PUBLIC KEY
        # --------------------------------------------------------------

        public_key_pem = (
            certificate[
                "public_key_pem"
            ]
            .encode("utf-8")
        )

        public_key = (
            serialization.load_pem_public_key(
                public_key_pem
            )
        )

        # --------------------------------------------------------------
        # SIGNATURE
        # --------------------------------------------------------------

        payload = canonical_json(
            metadata
        )

        signature = bytes.fromhex(
            certificate[
                "signature_hex"
            ]
        )

        public_key.verify(
            signature,
            payload,
        )

        return True

    except Exception:

        return False


# ======================================================================
# 10. CERTIFICATE FINGERPRINT
# ======================================================================

def certificate_fingerprint(
    certificate,
):
    """
    SHA-256 fingerprint of the complete canonical
    certificate object.
    """

    encoded = canonical_json(
        certificate
    )

    return hashlib.sha256(
        encoded
    ).hexdigest()


# ======================================================================
# 11. LIVE CERTIFICATION
# ======================================================================

def certify_all_things(
    source_code,
):
    """
    Generate and immediately verify an
    {ALL_THINGS} certificate.
    """

    certificate, private_key = (
        generate_certificate(
            source_code
        )
    )

    verified = verify_certificate(
        certificate,
        source_code,
    )

    print()
    print("=" * 72)
    print("{ALL_THINGS} CRYPTOGRAPHIC CERTIFICATION")
    print("=" * 72)

    print(
        "Author:",
        certificate["metadata"]["author"],
    )

    print(
        "Engine:",
        certificate["metadata"]["engine"],
    )

    print(
        "Certificate:",
        certificate["metadata"][
            "certificate_version"
        ],
    )

    print(
        "SHA-256:",
        certificate["metadata"][
            "engine_sha256"
        ],
    )

    print(
        "Certificate fingerprint:",
        certificate_fingerprint(
            certificate
        ),
    )

    print(
        "Signature:",
        certificate[
            "signature_hex"
        ],
    )

    print(
        "Bridge Status:",
        (
            "VERIFIED & CROSSED"
            if verified
            else
            "VERIFICATION FAILED"
        ),
    )

    return certificate


# ======================================================================
# 12. TAMPER TEST
# ======================================================================

def tamper_test(
    certificate,
    source_code,
):
    """
    Demonstrate that changing the certified source
    causes verification failure.
    """

    original = verify_certificate(
        certificate,
        source_code,
    )

    tampered = (
        source_code +
        "\n# TAMPERED\n"
    )

    after_tampering = (
        verify_certificate(
            certificate,
            tampered,
        )
    )

    print()
    print("=" * 72)
    print("{ALL_THINGS} TAMPER TEST")
    print("=" * 72)

    print(
        "Original verification:",
        original,
    )

    print(
        "Tampered verification:",
        after_tampering,
    )

    return (
        original is True
        and
        after_tampering is False
    )


# ======================================================================
# 13. {ALL_THINGS} DIRECT DEMONSTRATION
# ======================================================================

def demonstrate_all_things():

    source = [
        0x12,
        0x34,
        0x56,
        0x78,
        0x9A,
    ]

    print()
    print("=" * 72)
    print("{ALL_THINGS} STATE / BOUNDARY / CLOSURE TEST")
    print("=" * 72)

    print(
        "Original:",
        source,
    )

    encoder = LTEncoder(
        source
    )

    decoder = AllThingsDecoder(
        len(source)
    )

    for seed in range(20):

        decoder.add(
            *encoder.packet(seed)
        )

        decoder.peel()

        state = decoder.boundary()

        print(
            f"seed={seed:2d} | "
            f"known={state['solved_states']} | "
            f"unknown={state['unresolved_states']} | "
            f"constraints={state['active_constraints']} | "
            f"boundary={state['boundary']} | "
            f"closed={state['closed']}"
        )

        if decoder.is_complete():
            break

    if decoder.is_complete():

        recovered = decoder.result()

        print()
        print(
            "Recovered:",
            recovered,
        )

        print(
            "IDENTITY:",
            recovered == source,
        )

    else:

        print()
        print(
            "Boundary:",
            decoder.boundary(),
        )


# ======================================================================
# 14. EXPERIMENT
# ======================================================================

def run_experiment(
    k,
    trials=200,
    max_packets=200,
):

    statistics = {
        "lt": [],
        "raptor": [],
    }

    for trial in range(trials):

        rng = random.Random(
            trial
        )

        source = [
            rng.getrandbits(8)
            for _ in range(k)
        ]

        # --------------------------------------------------------------
        # PURE LT
        # --------------------------------------------------------------

        encoder = LTEncoder(
            source
        )

        decoder = AllThingsDecoder(
            k
        )

        for packet_number in range(
            max_packets
        ):

            decoder.add(
                *encoder.packet(
                    packet_number
                )
            )

            if decoder.peel():

                statistics[
                    "lt"
                ].append(
                    packet_number + 1
                )

                break

        else:

            statistics[
                "lt"
            ].append(None)

        # --------------------------------------------------------------
        # RAPTOR-STYLE
        # --------------------------------------------------------------

        rencoder = (
            AllThingsRaptorEncoder(
                source
            )
        )

        rdecoder = (
            AllThingsRaptorDecoder(
                k
            )
        )

        for packet_number in range(
            max_packets
        ):

            rdecoder.add(
                *rencoder.packet(
                    packet_number
                )
            )

            if rdecoder.peel():

                statistics[
                    "raptor"
                ].append(
                    packet_number + 1
                )

                break

        else:

            statistics[
                "raptor"
            ].append(None)

    return statistics


def summarize(
    name,
    results,
    k,
    trials,
):

    successful = [
        result
        for result in results
        if result is not None
    ]

    failures = (
        trials -
        len(successful)
    )

    if not successful:

        return (
            f"{name}: 100% failure"
        )

    average = (
        sum(successful) /
        len(successful)
    )

    overhead = (
        average / k
    ) - 1

    success_rate = (
        len(successful) /
        trials
    )

    return (
        f"{name}: "
        f"avg={average:.2f} packets, "
        f"overhead={overhead:+.2%}, "
        f"success={success_rate:.2%}, "
        f"failures={failures}/{trials}"
    )


def test_all_things():

    print()
    print("=" * 72)
    print("{ALL_THINGS} FINITE-STATE RECOVERY EXPERIMENT")
    print("=" * 72)

    for k in [
        10,
        20,
        50,
        100,
        500,
    ]:

        statistics = run_experiment(
            k,
            trials=200,
            max_packets=200,
        )

        print()
        print(
            f"k = {k}"
        )

        print(
            "  " +
            summarize(
                "LT     ",
                statistics["lt"],
                k,
                200,
            )
        )

        print(
            "  " +
            summarize(
                "RAPTOR ",
                statistics["raptor"],
                k,
                200,
            )
        )


# ======================================================================
# 15. MAIN
# ======================================================================

if __name__ == "__main__":

    # --------------------------------------------------------------
    # STATE / CONSTRAINT / CLOSURE TEST
    # --------------------------------------------------------------

    demonstrate_all_things()

    # --------------------------------------------------------------
    # CRYPTOGRAPHIC CERTIFICATION
    # --------------------------------------------------------------

    # The certificate must contain the EXACT source text being
    # certified. For a production workflow, load this from the
    # actual .py file rather than duplicating the source manually.

    import pathlib

    source_path = pathlib.Path(__file__)

    source_code = source_path.read_text(
        encoding="utf-8"
    )

    certificate = certify_all_things(
        source_code
    )

    # --------------------------------------------------------------
    # TAMPER DETECTION
    # --------------------------------------------------------------

    tamper_test(
        certificate,
        source_code,
    )

    # --------------------------------------------------------------
    # CODING EXPERIMENT
    # --------------------------------------------------------------

    test_all_things()
