# RFC 8785 appendix evidence (does not close the verifier gate)

Retrieved `2026-08-29T17:55:40Z` from `https://www.rfc-editor.org/rfc/rfc8785.txt`.

| Field | Value |
| --- | --- |
| Official text SHA-256 | `63d52294eb0e3f0014174288186d388b4ddbf2c67d1ce8af1d9726eb0c3ab240` |
| Appendix A | ECMAScript sample canonicalizer (code), not JSON vectors |
| Appendix B | IEEE 754 / JSON number serialization samples |

APCC-CJ1 admits objects and strings only (no numbers/bools/nulls).
Appendix B samples are therefore expected to be rejected by CJ1
(`WRONG_JSON_TYPE`). That is evidence the plan’s “RFC 8785 appendix
corpus / independent JCS canonicalizer” criterion is **not met**.
Verifier qualification remains PARTIAL.
