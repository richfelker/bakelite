# Bakelite

Incremental backup with strong cryptographic confidentiality baked
into the data model. In a small package, with no dependencies.

**This project is still experimental!** Things may break or change.
See below on status.

## Features

- Designed around public key cryptography such that decryption key can
  be kept offline, air-gapped.

- Backup to local or remote storage with arbitrary transport.

- Incremental update built on inode identity and hashed block
  contents, compatible with moving and reorganizing entire trees.

- Data deduplication.

- Low local storage requirements for change tracking -- roughly 56-120
  bytes per file plus 0.1-5% of total data size.

- Live-streamable to storage. Compatible with append-only media. No
  local storage required for staging a backup that will be stored
  remotely.

- Optional support for blinded garbage-collection of blobs on the
  storage host side.

- Written entirely in C with no library dependencies. Requires no
  installation.

- Built on modern cryptographic primitives: Curve25519 ECDH, ChaCha20,
  and SHA-3.



## Status

Bakelite is presently experimental and is a work in progress. The
above-described features are all present, but have not been subjected
to third party review or extensive testing. Moreover, many advanced
features normally expected in backup software, like to controls over
inclusion/exclusion of files, are not yet available. The codebase is
also in transition from a rapidly developed proof of concept to
something more mature and well-factored.

Data formats may be subject to change. If attempting to use Bakelite
as part of a real backup workflow, you should keep note of the
particular version used in case it's needed for restore. Note that the
actual backup format is more mature and stable than the configuration
and local index format, so the more likely mode of breakage when
upgrading is needing to start a new full (non-incremental) backup, not
inability to read old backups.



## Why another backup program?

Backups are inherently attack surface on the privacy/confidentiality
of one's data. For decades I've looked for a backup system with the
right cryptographic properties to minimize this risk, and turned up
nothing, leaving me reliant on redundant copies of important things
(the "Linus backup strategy") rather than universal system-wide
backups. After some moderately serious data loss, I decided it was
time to finally write what I had in mind.

Among the near-solutions out there, some required large library or
language runtime dependencies, some only worked with a particular
vendor's cloud storage service, and some had poor change tracking that
failed to account for whole trees being moved or renamed. But most
importantly, none with incremental capability addressed the
catastrophic loss of secrecy of **all past and current data** in the
event that the encryption key was exposed.






## Data model

A backup image is a Merkle tree of nodes representing directories,
files, and file content blocks, with each node identified by a SHA-3
hash of its *encrypted contents*, and the root of the tree referenced
by a signed summary record. For readers familiar with the git data
model, this is very much like a git *tree* (not *commit*) but with the
objects encrypted. Multiple trees can share common subtrees. This is
how incremental backups are represented, and is analogous to how git
commits share subtrees. Backup snapshots are not like git commits
however; they do not reference each other or have parent/child
relationships. This allows arbitrary retention policies to be
implemented without breaking any Merkle tree reference chains.

Since there is no way for the system being backed up to "read back"
from the backups when it doesn't hold the private decryption key, a
"local index" is kept to track how objects in storage correspond to
the live filesystem contents. It is a key/value dictionary mapping
(device,inode) pairs and hashes of *unencrypted* file content blocks
to the corresponding encrypted object hashes. The local index does not
need to be stored with the backup, and should not be. A party who has
read access to the local index can probe whether known data was
present on the filesystem at the time of last backup, which inode(s)
(thereby which files, if they exist in listable directories) contained
that data, and which inode(s) share common contents. (Note that these
are exactly the capabilities needed for deduplicating of data within
and between snapshots.)






## Intended security level properties

- If neither private nor public key is exposed (perspective of backup
  storage provider), breaking confidentiality of backup depends on
  breaking ChaCha20.

- If the public key is exposed (for example, via breach on the system
  being backed up), breaking confidentiality of backup depends on
  breaking ChaCha20 or solving the computational discrete logarithm
  problem on Curve25519.

- Breaking integrity of backup depends on breaking second-preimage
  resistance of SHA-3 or breaking the signing algorithm used
  (signature forgery). The latter admits only complete tree
  replacement, not selective modification.
  



## Setup

1. Key generation. This step does not need to be done on the system
   that will be backed up, and should be done on a system you
   absolutely trust -- both to have a working cryptographic entropy
   source, and not to expose data. Choose a place to store the secret
   key, such as an encrypted removable device, and run:

        bakelite genkey backup.sec
        bakelite pubkey backup.sec > backup.pub

   Then copy `backup.pub` to the system(s) you want to back up using
   this key.

2. Initialization. On the system to be backed up, create an empty
   directory and run:

        bakelite init /path/to/backup.pub /path/needing/backup

   This will create a skeleton configuration in the current working
   directory. All further steps should be performed from this
   directory.

3. Configure storage. Edit the `store_cmd` script produced by
   `bakelite init` to something that will accept data in tar format
   and write it to the desired storage, reporting success or failure
   via exit status. For example, for local storage to mounted media:

        tar -C /media/backup -kxf -

   or appending to a tape drive:

        cat >> /dev/nst0

   or to a remote host via ssh:

        ssh backup@remotehost

   In the latter (ssh) case, the remote `authorized_keys` file should
   force a `command` that stores the tar stream appropriately and
   disallows overwrite of existing data.

4. Configure devices. Normally, Bakelite will not traverse mount
   points to other devices; this avoids accidentally including
   transient mounts of external media or remote shares into a backup
   they don't belong in. If you want to include additional mounts,
   create a symlink to the root of each in the directory named
   "devices". The symlink name will serve as a "label" for the device
   used in the local indexing, so that changes to device numbering
   across reboots do not break the index. For example:

        ln -s /home devices/home
        ln -s /var devices/var

5. Configure signatures. Create an executable `sign_cmd` file that
   accepts data to sign on stdin and produces a signature file on
   stdout. For example, to use `signify`:

        signify -S -s signing.sec -x - -m -

6. Additional configuration. Edit the `config` file to change any
   other preferences as desired. It's recommended to at least set a
   `label` for the backup so that the signed summary files will be
   associated with a particular role/identity, unless separate signing
   keys will be used for each tree being backed up.

   To exclude files matching certain patterns from backups, create a
   file named `exclude` containing one pattern per line. Patterns are
   a superset of standard glob pattern functionality, intended to
   match `.gitignore` conventions, except that inversion using leading
   `!` is not supported. In particular, `**` can be used to match
   zero or more path components, final `/` forces only directories to
   match, and patterns with no `/` (except possibly a final one) can
   match in any directory (they have an implicit `**/` prefix).

7. Run the first backup.

        bakelite backup -v

   The `-v` (verbose) flag is helpful to see what's happening,
   especially for new or changed configurations. However, it does
   expose information about filesystem contents/changes. Setups aiming
   to maximize privacy should not use it in an automated setting with
   logging.

   When the job is finished, a text file named according to the label
   and UTC backup timestamp, in the form
   `label-yyyy-mm-ddThhmmss.nnnnnnnnnZ.txt`, should be present on
   the backage storage medium, along with a number of files with hex
   string names in the `objects` directory. A `.sig` file will be
   present too if signing was configured.

8. Setup a cron job to perform further backups on the desired
   schedule. For example:

        0 2 * * * bakelite -C /path/to/configuration/dir backup


## Restoring

It's recommended to test that you are able to restore backups. On a
system with the secret key available, run the `restore` command, as
in:

    bakelite restore -v -k backup.sec -d /dest/path summary_file.txt

If the secret key is protected by a passphrase you will need to enter
it. (Note: passphrase-protected key files are not yet implemented.)

By default, objects are searched for in `objects/` relative to the
location of the summary file (the same as the default tree layout in
the tar stream emitted by the `backup` command for storage).

During testing, original and restored trees should be compared, either
directly with a tool like `diff` or by recursively printing hashes and
metadata with `find`, `ls -lR`, or similar and diffing the output, to
satisfy oneself that the backup was faithful and faithfully restored.

Note that non-POSIX metadata such as extended attributes is not yet
stored in the backup inode records or restored. Support for this
functionality may be added in the future.



## Managing storage

It's entirely possible to treat the backup storage as append-only,
cycling media and performing a new full backup periodically or when
the media fills up. However, it's also possible to use a running
incremental backup indefinitely without filling up storage, by
scripting a retention policy to delete old summary files and and prune
(garbage collect) data objects that the remaining snapshots do not
reference. This can be done *without access to the backup contents*
(i.e. without the private key) via bloom filters attached to each
summary.

From the directory containing the summary records and `objects`
directory, run:

    bakelite prune *.txt

This will output a list of relative object file pathnames which are
not referenced by any of `*.txt`, which can be fed into `xargs` to
actually delete them.

