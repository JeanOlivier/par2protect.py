# par2protect.py
Protect files in each directory recursively using par2. It repairs and updates with par2, if only adler32 sum of files does not match.

- TODO:
    - Store the redundancy in the `.cksum` file to allow for updating to a different redundancy.
    - Idea: Separate creation, update, verify and update modes.

        Maybe simply allow for overriding a mode? (i.e. update because a file was intentionally removed)

    - Add a "clean" option to remove the parity files.
        
        Make it verify integrity first and ask for confirmation before removing parity files.
