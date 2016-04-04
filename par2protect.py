#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import zlib
import ctypes
import subprocess

DESCRIPTION = 'Protect files in directories recursively with par2.'

VERSION = "0.2-rc1"

# Protect files in directory recursively using par2
#
# par2 must be installed and in PATH
#   debian/ubuntu: apt-get install -y par2
#   redhat/fedora: yum install -y par2cmdline

# Redundancy percent for par2
REDUNDANCY=10

# Set to true to exclude par2 generated files (ends with .[1-9]+[0-9]*)
EXCLUDE_REPAIRED = True


# Strings:
STR_PAR2_SETUP_ERROR = 'Unable to run par2, is it installed and set in the PATH?\n'

def par2protect(directory,
                redundancy       = 10,
                exclude_repaired = True,
                verbose          = False,
                update           = True):
    '''
    Protect files in directory recursively using par2, detect modification with
    fast adler32 checksums
    '''

    exclude_reg = re.compile(r'\.[1-9]+[0-9]*$') # par2 repaired files end with .N

    # Compute a fast ckecksum of all given files that do not start
    # with a dot
    def cksum(files):
        '''
        Compute adler32 cksum of a list of files
        '''
        val = 0
        for _fname in sorted(files):
            with open(_fname, 'rb') as _fdes:
                buf = ' '
                while len(buf) > 0:
                    buf = _fdes.read(1<<20)
                    val = zlib.adler32(buf, val)
        return ctypes.c_uint32(val).value

    with open(os.devnull, 'w') as null:

        if not verbose:
            out = null
            err = null
        else:
            out = None
            err = None

        # Walk recursively in each directory
        for root, dirs, files in os.walk(directory):

            files = [f for f in files if not f[0] == '.']
            dirs[:] = [d for d in dirs if not d[0] == '.']

            if exclude_repaired:
                _tmp = files
                files = [f for f in files if not exclude_reg.search(f) ]
                excluded = list((set(_tmp) - set(files)))
                if len(excluded):
                    print "par2protect: %s: excluded files:" % (root, ), \
                        ', '.join(excluded)

            oldcd = os.getcwd()
            os.chdir(root)
            try:
                with open('.cksum','rb') as f:
                    oval = f.read(8)
            except IOError:
                oval = ""
            nval = "%08x" % (cksum(files),)

            if nval != oval and len(files):
                print "par2protect: %s: different adler32 checksums" % (root, )

                try:
                    subprocess.check_call(["par2", "r", ".cksum.par2"],
                                          stdout=out, stderr=err)
                    nval = "%08x" % (cksum(files),)
                except subprocess.CalledProcessError:
                    sys.stderr.write(
                        "par2protect: %s: par2 unable to repair !\n" \
                        % (root, ))
                except OSError:
                    sys.stderr.write(STR_PAR2_SETUP_ERROR)
                    sys.exit(1)

                try:
                    if update:
                        subprocess.check_call(["par2", "c", '-n1', "-r%d" % redundancy,
                                               ".cksum.par2"] + files,
                                              stdout=out, stderr=err)
                        with open('.cksum', 'wb') as f:
                            f.write(nval)
                        print "par2protect: %s: par2 and checksum updated" % (root, )
                except subprocess.CalledProcessError:
                    sys.stderr.write(
                        "par2protect: %s: unable to update par2 or ckecksum\n" \
                        % (root, ))
                except OSError:
                    sys.stderr.write(STR_PAR2_SETUP_ERROR)
                    sys.exit(1)

            os.chdir(oldcd)

# Experimental functions follow
try :
    from termcolor import colored
except:
    colored = lambda x, *args, **kwargs:x

def cksum(files):
    '''
    Compute adler32 cksum of a list of files
    '''
    val = 0
    for _fname in sorted(files):
        with open(_fname, 'rb') as _fdes:
            buf = ' '
            while len(buf) > 0:
                buf = _fdes.read(1<<20)
                val = zlib.adler32(buf, val)
    return ctypes.c_uint32(val).value

exclude_reg = re.compile(r'\.[1-9]+[0-9]*$') # par2 repaired files end with .N

def _par2protect(directory,
                mode,
                redundancy       = 10,
                exclude_repaired = True,
                verbose          = True):
    '''
    Verify the checksums
    '''
    mode = set(mode if isinstance(mode,(list,tuple)) else [mode])
    if not verbose:
        out = open(os.devnull, 'w')
        err = out
    else:
        out = None
        err = None

    original_cwd = os.getcwd()

    # Walk recursively in the directory tree
    for root, dirs, files in os.walk(directory):
        files = [f for f in files if not f[0] == '.']
        dirs[:] = [d for d in dirs if not d[0] == '.']

        if exclude_repaired:
            _tmp = files
            files = [f for f in files if not exclude_reg.search(f) ]
            excluded = list((set(_tmp) - set(files)))
            if len(excluded):
                print "{}: excluded files:".format(root), \
                      ', '.join(excluded)
        oldcd = os.getcwd()
        os.chdir(root)
        
        if len(files) > 0:
            if not mode.isdisjoint(set(['v', 'verify'])):
                _verify_dir(root, dirs, files)
    
            if not mode.isdisjoint(set(['c', 'repair'])):
                _repair_dir(root, dirs, files, out, err)
    
            if not mode.isdisjoint(set(['c', 'create'])):
                _create_dir(root, dirs, files, redundancy, out, err)



    os.chdir(original_cwd)


def _create_dir(root, dirs, files, redundancy, out, err):
    nval = None
    print "create:", colored("Creating", "yellow"), "par2 for {}".format(root)
    try:
        par2cmd = ["par2", "c", '-n1', "-r%d" % redundancy, ".cksum.par2"] + files 
        subprocess.check_call(par2cmd, stdout=out, stderr=err)
        nval = "{:08x}".format(cksum(files))
        print "create:", colored("Successfully", "green"), "created par2"

    except:
        try:
            par2cmd = ["par2", "c", '-s524288','-n1', "-r%d" % redundancy, ".cksum.par2"] + files 
            subprocess.check_call(par2cmd, stdout=out, stderr=err)
            nval = "{:08x}".format(cksum(files))
            print "create:", colored("Successfully", "green"), "created par2"

        except subprocess.CalledProcessError:
            sys.stderr.write("create: {} to create par2\n".format(colored("Failed", "red")))

    if nval is None:
        sys.stderr.write(STR_PAR2_SETUP_ERROR)
        sys.exit(1)

    with open('.cksum', 'wb') as f:
        f.write(nval)
    


def _verify_dir(root, dirs, files):
    if not os.path.isfile('.cksum'):
        print "verify:", colored("MISSING","yellow"), \
                        "adler32 checksums for {}".format(root)
    else:
        try:
            with open('.cksum', 'rb') as f:
                oval = f.read(8)
            nval = "{:08x}".format(cksum(files))
            if nval != oval and len(files):
                print "verify:", colored(" WRONG ","red"), \
                        "adler32 checksums for {}".format(root)
            else:
                print "verify:", colored("Correct", "green"), \
                        "adler32 checksums for {}".format(root)
        except IOError:
            print "verify: there was an error reading "\
                    "{}/.cksum".format(root)


def _repair_dir(root, dirs, files, out, err):
    print "repair:", colored("Repairing", "yellow"), "{}".format(root)
    try:
        subprocess.check_call(["par2", "r", ".cksum.par2"], stdout=out, stderr=err)
        print "repair:", colored("Successfully", "green"), "repaired par2".format(root)

    except subprocess.CalledProcessError:
        sys.stderr.write("repair: {} to repair\n".format(colored("Failed", "red")))

    except OSError:
        sys.stderr.write(STR_PAR2_SETUP_ERROR)
        sys.exit(1)

    


def _delete_dir(root, dirs, files):
    pass 



if __name__ == '__main__':

    import argparse

    def _main():
        '''main fucntion when called as a program look at --help output for usage'''

        parser = argparse.ArgumentParser(prog            = 'par2protect.py',
                                         formatter_class =
                                         argparse.RawDescriptionHelpFormatter,
                                         description     = DESCRIPTION,
                                         epilog='''
Copyright (c) 2014, Stany MARCEL <stanypub@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
'''
                                     )
        parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
        parser.add_argument("-v", "--verbose",
                            help="increase output verbosity",
                            action="store_true")
        parser.add_argument("-r", "--redundancy",
                            help=("change the level of redundancy 1:100 (default: %d)" \
                                  % (REDUNDANCY,)),
                            metavar=('N',),
                            type=int,
                            default=REDUNDANCY)
        parser.add_argument("-n", "--no-update",
                            help="dont update par2 and checksum ",
                            action="store_true")

        parser.add_argument('DIR', nargs='+', help='directory to protect/repair')

        args = parser.parse_args()

        for _dname in args.DIR:
            if not os.path.isdir(_dname):
                parser.print_help()
                sys.exit(1)

        for _dname in args.DIR:
            par2protect(_dname,
                        redundancy = args.redundancy,
                        verbose    = args.verbose,
                        update     = not args.no_update)

        sys.exit(0)

    _main()
