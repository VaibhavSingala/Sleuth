"""Discovery, hot-reload and schema derivation for model-authored skills.

A skill is one source file in ``config.SKILLS_DIR`` (``.py`` in-process, or
another supported language run as a subprocess). That is the whole format --
no extra manifest is required; optional ``<name>.meta.json`` stores language
and parameter schema for non-Python skills.
