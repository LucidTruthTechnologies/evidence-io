"""evidence-io - read E01 images in-process; write E01 images holding a
FAT32 or exFAT volume. Shared by Lucid Truth Technologies' triage tools.

Modules: ewf_reader (open an E01 read-only), image_walk (every file in every
filesystem, with original times and deleted flags), ewf_writer (E01 encoder),
fat32 and exfat (write-once volume builders), volume (choose and build).
"""

VERSION = "1.0.3"
__version__ = VERSION
