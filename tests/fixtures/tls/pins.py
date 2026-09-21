"""Expected SPKI pins for the committed TLS fixtures.

Fixed values, recorded when the fixtures were generated. Deliberately not
derived from the files at test time: a pin computed from the certificate it
is checking is a pin that checks nothing, and would go on agreeing with
itself after the extraction it is meant to verify had broken.
"""

PINS = {
    "client": "sha256:f30ba38178788bca0c9480109c15b85dd4154f79abb69c43384dd72eab6b9efb",
    "client-untrusted": "sha256:9b2f5b7e300b0658c260a7fc9208c416cbc90bf18b2d6d6ae2449e7eaa97890f",
    "server": "sha256:dfab280088edda6866f6add882b58cc3c4403a25d001a07791fd08a0ff8e70b0",
    "server-expired": "sha256:cd8d1d137bc2d9db015a7148f27992ac10f3603b2eef817e48ff72d49808cfe2",
    "server-untrusted-ca": "sha256:ba10dc17567f3ebd10c4d129407f4e43a3e635f1d1a108c2acd00433d27a86b8",
    "server-wrong-name": "sha256:9a408a171936fe712ea8d8ce3a558e0932d6c96be1d444994f510b2d1411af36",
    "trusted-ca": "sha256:4f8ca3820adcfb7c9fb7e1cdd61547e33ab51331baa74389316c6e93676c640e",
    "untrusted-ca": "sha256:f4da7ac169e3d28de2fc1d7ceac83f6858aa4fbfbf95d4681ed6b1ff77c1b2c2",
}
