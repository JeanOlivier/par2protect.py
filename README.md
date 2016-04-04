# par2protect.py
Protect files in each directory recursively using par2. It repairs and updates with par2, if only adler32 sum of files does not match.

- TODO:
    - Turn it into a class with methods
    - Store the redundancy in the `.cksum` file to allow for updating to a different redundancy.
    - Add a "clean" option to remove the parity files.
        Make it verify integrity first and ask for confirmation before removing parity files.
        - I guess par2 -q option would be a good candidate
    - Allow to use the real par2 verify instead of fast adler check, keep the latter.


- DONE:
    - Idea: Separate creation, update, verify and update modes.

        Maybe simply allow for overriding a mode? (i.e. update because a file was intentionally removed)

