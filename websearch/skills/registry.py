"""Discovery, hot-reload and schema derivation for model-authored skills.

A skill is one ``.py`` file in ``config.SKILLS_DIR`` defining a function of the
same name. That is the whole format -- no manifest, no regist