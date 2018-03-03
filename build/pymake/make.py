#!/usr/bin/env python

"""
make.py

A drop-in or mostly drop-in replacement for GNU make.
"""

import sys, os
import pymake.command, pymake.process

import gc

def find_executable(executable, path=None):
    """Find if 'executable' can be run. Looks for it in 'path'
    (string that lists directories separated by 'os.pathsep';
    defaults to os.environ['PATH']). Checks for all executable
    extensions. Returns full path or None if no command is found.
    """
    if path is None:
        path = os.environ['PATH']
    paths = path.split(os.pathsep)
    extlist = ['']
    if os.name == 'os2':
        (base, ext) = os.path.splitext(executable)
        # executable files on OS/2 can have an arbitrary extension, but
        # .exe is automatically appended if no dot is present in the name
        if not ext:
            executable = executable + ".exe"
    elif sys.platform == 'win32':
        pathext = os.environ['PATHEXT'].lower().split(os.pathsep)
        (base, ext) = os.path.splitext(executable)
        if ext.lower() not in pathext:
            extlist = pathext
    for ext in extlist:
        execname = executable + ext
        if os.path.isfile(execname):
            return execname
        else:
            for p in paths:
                f = os.path.join(p, execname)
                if os.path.isfile(f):
                    return f
    else:
        return None

if __name__ == '__main__':
  # When building, execute mozmake instead. Until bug 978211, this is the easiest, albeit hackish, way to do this.
  import subprocess
  mozmake = find_executable('mozmake.exe')
  cmd = [mozmake]
  cmd.extend(sys.argv[1:])
  shell = os.environ.get('SHELL')
  if shell and not shell.lower().endswith('.exe'):
      cmd += ['SHELL=%s.exe' % shell]
  sys.exit(subprocess.call(cmd))

  sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
  sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)

  gc.disable()

  # This is meant as a temporary workaround until issues with many targets
  # and prerequisites is addressed. Bug 874210 tracks.
  try:
      sys.setrecursionlimit(2 * sys.getrecursionlimit())
  except Exception:
      print >>sys.stderr, 'Unable to increase Python recursion limit.'

  pymake.command.main(sys.argv[1:], os.environ, os.getcwd(), cb=sys.exit)
  pymake.process.ParallelContext.spin()
  assert False, "Not reached"
