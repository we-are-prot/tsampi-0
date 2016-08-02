from __future__ import print_function
import monkeypatch  # nopep8

import argparse
import re
import hashlib
import cgitb
import json

from unidiff import PatchSet
from voluptuous import Schema, Required, All, Length, Any
from pow2 import pow2

#Because debugging from within the sandbox is a PITA.
cgitb.enable(format="text")


class ValidationError(Exception):
    pass



def parse_diff(lines):
    is_merge = False
    is_valid_sig = False
    commit_hash = None

    diff_lines = []
    for line in lines:
        if line.startswith("commit"):
            _, commit_hash = line.split()

        if diff_lines:
            diff_lines.append(line)

        # get the rest of the diffs afte the first one
        if line.startswith('diff') and not diff_lines:
            diff_lines = [line]

    patch = PatchSet(diff_lines)
    return commit_hash, is_valid_sig, is_merge, patch


def make_assertions(commit_hash, valid_sig, is_merge, patch):
    # TODO make proper work
    if not (commit_hash and re.match('^[0-9a-f]{40}$', commit_hash)):
        raise ValidationError('This is not a valid commit hash: %s' % commit_hash)
    errors = {}
    WORK_NEEDED = 500
    MAX_WORK = 1000
    if not pow2(commit_hash, WORK_NEEDED, MAX_WORK):
        errors['pow'] = False

    #if len(patch) > 1:
    #    raise ValidationError("Only too file per commit")

    #if len(patch.removed_files) != 0:
    #    raise ValidationError("No files can be removed")

    #if len(patch.added_files) != 1:
    #    raise ValidationError("One new file per commit")

    # TODO: implement gpg key distribution
    # assert GOOD_GPG_SIG, '%s missing valid signature' % (commit_hash,)

    # So we know that there is only a single new file that is being validated here.
    # Now extract the data without the unifieddiff meta data and hash it to match the
    # filename. Merge conflicts are possible when two users create the same exact
    # data. But fuck it.
    patched_file = patch[0]

    # Lol.
    raw_data = str('\n'.join('\n'.join(str(l)[1:] for l in h)
                             for h in patched_file))

    # Validate data structure now
    #data = None
    #try:
    #    data = bencode.bdecode(raw_data)
    #except ValueError as e:
    #    raise ValidationError(e)

    #schema = Schema({
    #    Required('parent_sha1'): Any("", All(str, Length(min=40, max=40))),
    #    Required('data'): Any(dict, str)
    #})

    # Validate it!
    # schema(data)

    # A thousand neckbeards screamed out why not sha256? Hey, just be
    # glad it's not md5, ok?
    data_hash = hashlib.sha1(raw_data).hexdigest()

    # Data hash matches file name in the ./data/ directory
    for p in patch:
        if not p.path.startswith('data/'):
            errors[p.path] = 'invalid directory. Should be in "data/"'  # we need better error messages


    #target_path = ('data/' + data_hash)
    #if patch.added_files[0].path != target_path:
    #    raise ValidationError('Target file %s is not named %s' % (patch.added_files[0].path, target_path))
    return errors


def add_arguments(parser):
    parser.add_argument('-f', '--git-show-file',
                        type=argparse.FileType('r'),
                        default='-',
                        dest='diff',
                        help='file with `git show --show-signature -c COMMIT_HASH` data (default stdin)')


def run(parser):  # pragma: no cover
    args = parser.parse_args()
    lines = args.diff.readlines()

    commit_hash, valid_sig, is_merge, patch = parse_diff(lines)
    errors = make_assertions(commit_hash, valid_sig, is_merge, patch)
    print(json.dumps(errors))

if __name__ == '__main__':  # pragma: no branch
    # Hmmm, coverage doesn't respect `pragma: no cover` for these kwargs on
    # different lines.
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description='Validated the potential child commit.\nPipe output of `git show --show-signature -c COMMIT_HASH` to this script')  # pragma: no cover

    # This allows other moduels to include these options in their argparer
    add_arguments(parser)  # pragma: no cover
    run(parser)  # pragma: no cover
