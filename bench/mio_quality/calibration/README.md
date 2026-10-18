# Retrieval threshold calibration data

- `calib_frames.json` (60) and `valid_frames.json` (60): independently authored frames in the
  `azazel-nexus/mio-heldout/1` label format. Calibration also uses `../heldout_set.json` and
  `../heldout2_set.json`; the validation set was opened once, after the values were fixed.
- `dump_similarities.py`: run inside the bench image with the repository at `/src`, label sets at
  `/sets/<name>.json`, bge-m3 at `/models/bge-m3-Q8_0.gguf` and a writable `/out`; it writes the full
  similarity list per frame to `/out/sims.json` using the production text formulas.
- `analyze.py h1,h2,cal sims.json SETS_DIR`: derives the three values with the documented rules.

Results and the chosen values: `docs/evidence/mio-threshold-calibration-2026-10-18.md`.
