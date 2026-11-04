# Feature backlog

## Browser review: highlighted diffs

Status: deferred at the user's request. Do not implement until requested.

Extend `agentvault review SESSION_ID --web` with:

- Green added lines, red removed lines, and neutral unchanged lines.
- Aligned side-by-side comparison with placeholders for additions and deletions.
- Original and edited line numbers.
- Collapsed unchanged context with an expansion control.
- Per-file addition/deletion counts and file navigation.
- A toggle between side-by-side and unified views.

Keep whole-session application through the existing synchronization checks and
recovery journal. Partial file or line application is outside this scope. Keep
summary previews for binary and large files.

Validate additions, deletions, repeated lines, Unicode, missing final newlines,
HTML escaping, and browser behavior.

Rough estimate discussed: 2–4 hours for implementation and verification, subject
to findings. This is an estimate, not a delivery commitment.

Possible follow-up: word-level highlighting, syntax highlighting, and
next/previous change navigation (rough estimate: another 1–3 hours).
