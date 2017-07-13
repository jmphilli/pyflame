# Pyflame: A Ptracing Profiler For Python

[![Build Status](https://api.travis-ci.org/uber/pyflame.svg?branch=master)](https://travis-ci.org/uber/pyflame)

Pyflame is a tool for
generating [flame graphs](https://github.com/brendangregg/FlameGraph) for Python
processes. Pyflame is different from existing Python profilers because it
doesn't require explicit instrumentation: it will work with any running Python
process! Pyflame works by using
the [ptrace(2)](http://man7.org/linux/man-pages/man2/ptrace.2.html) system call
to analyze the currently-executing stack trace for a Python process. Pyflame is
also capable of profiling embedded Python interpreters, such
as [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/), or other binaries that
link against libpython.

Pyflame is written in C++, and was written with attention to speed. The
profiling overhead is low enough that you can use Pyflame to profile processes
in production.

![pyflame](https://cloud.githubusercontent.com/assets/2734/17949703/8ef7d08c-6a0b-11e6-8bbd-41f82086d862.png)

<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [Pyflame: A Ptracing Profiler For Python](#pyflame-a-ptracing-profiler-for-python)
    - [Installing From Source](#installing-from-source)
        - [Build Dependencies](#build-dependencies)
            - [Debian/Ubuntu](#debianubuntu)
            - [Fedora](#fedora)
        - [Compilation](#compilation)
            - [Creating A Debian Package](#creating-a-debian-package)
        - [Python 3 Support](#python-3-support)
    - [Installing A Pre-Built Package](#installing-a-pre-built-package)
        - [Ubuntu PPA](#ubuntu-ppa)
        - [Arch Linux](#arch-linux)
    - [Usage](#usage)
        - [Trace Mode](#trace-mode)
        - [Timestamp ("Flame Chart") Mode](#timestamp-flame-chart-mode)
    - [FAQ](#faq)
        - [What Is "(idle)" Time?](#what-is-idle-time)
        - [Are BSD / OS X / macOS Supported?](#are-bsd--os-x--macos-supported)
        - [What Are These Ptrace Permissions Errors?](#what-are-these-ptrace-permissions-errors)
            - [Ptrace Errors Within Docker Containers](#ptrace-errors-within-docker-containers)
            - [Ptrace Errors Outside Docker Containers Or When Not Using Docker](#ptrace-errors-outside-docker-containers-or-when-not-using-docker)
            - [Ptrace With SELinux](#ptrace-with-selinux)
    - [Blog Posts](#blog-posts)
    - [Contributing](#contributing)
        - [Hacking](#hacking)
        - [How Else Can I Help?](#how-else-can-i-help)
    - [Legal and Licensing](#legal-and-licensing)

<!-- markdown-toc end -->

## Installing From Source

To build Pyflame you will need a C++ compiler with basic C++11 support. Pyflame
is known to compile on versions of GCC as old as GCC 4.6. You'll also need GNU
Autotools ([GNU Autoconf](https://www.gnu.org/software/autoconf/autoconf.html)
and [GNU Automake](https://www.gnu.org/software/automake/automake.html)) if
you're building from the Git repository.

### Build Dependencies

#### Debian/Ubuntu

Install the following packages if you are building for Debian or Ubuntu. Note
that you technically only need one of `python-dev` or `python3-dev`, but if you have both
installed then you can use Pyflame to profile both Python 2 and Python 3
processes.

```bash
# Install build dependencies on Debian or Ubuntu.
sudo apt-get install autoconf automake autotools-dev g++ pkg-config python-dev python3-dev libtool make
```

#### Fedora

Again, you technically only need one of `python-devel` and `python3-devel`,
although installing both is recommended.

```bash
# Install build dependencies on Fedora.
sudo dnf install autoconf automake gcc-c++ python-devel python3-devel libtool
```

### Compilation

Once you've installed the appropriate build dependencies (see below), you can
compile Pyflame like so:

```bash
./autogen.sh
./configure      # Plus any options like --prefix.
make
make install
```

#### Creating A Debian Package

If you'd like to build a Debian package, run the following from the root of your
Pyflame git checkout:

```bash
# Install additional dependencies required for packaging.
sudo apt-get install debhelper dh-autoreconf dpkg-dev

# This create a file named something like ../pyflame_1.3.1_amd64.deb
dpkg-buildpackage -uc -us
```

### Python 3 Support

Pyflame will detect Python 3 headers at build time, and will be compiled with
Python 3 support if these headers are detected. Python 3.4 and 3.5 are known to
work. [Issue #69](https://github.com/uber/pyflame/issues/69) tracks Python 3.6
support. [Issue #77](https://github.com/uber/pyflame/issues/77) tracks
supporting earlier Python 3 releases.

There is one known bug specific to Python
3. [Issue #2](https://github.com/uber/pyflame/issues/2) describes the problem:
Pyflame assumes that Python 3 file names are encoded using ASCII. This is will
only affect you if you actually use non-ASCII code points in your `.py` file
names, which is probably quite uncommon. In principle it is possible to fix this
although a bit tricky; see the linked issue for details, if you're interested in
contributing a patch.

## Installing A Pre-Built Package

Several Pyflame users have created unofficial pre-built packages for different
distros. Uploads of these packages tend to lag the official Pyflame releases, so
you are **strongly encouraged to check the pre-built version** to ensure that it
is not too old. If you want the newest version of Pyflame, build from source.

### Ubuntu PPA

[Trevor Joynson](https://github.com/akatrevorjay) has set up an unofficial PPA
for all current Ubuntu
releases:
[ppa:trevorjay/pyflame](https://launchpad.net/~trevorjay/+archive/ubuntu/pyflame).

```bash
sudo apt-add-repository ppa:trevorjay/pyflame
sudo apt-get update
sudo apt-get install pyflame
```

Note also that you can build your own Debian package easily, using the one
provided in the `debian/` directory of this project.

### Arch Linux

[Oleg Senin](https://github.com/RealFatCat) has added an Arch Linux package
to [AUR](https://aur.archlinux.org/packages/pyflame-git/).

## Usage

After compiling Pyflame you'll get a small executable called `pyflame` (which
will be in the `src/` directory if you haven't run `make install`). The most
basic usage is:

```bash
# Profile PID for 1s, sampling every 1ms.
pyflame PID
```

The `pyflame` command will send data to stdout that is suitable for using with
Brendan Gregg's `flamegraph.pl` tool (which you can
get [here](https://github.com/brendangregg/FlameGraph)). Therefore a typical
command pipeline might be like this:

```bash
# Generate flame graph for pid 12345; assumes flamegraph.pl is in your $PATH.
pyflame 12345 | flamegraph.pl > myprofile.svg
```

You can also change the sample time and sampling frequency:

```bash
# Profile PID for 60 seconds, sampling every 100ms.
pyflame -s 60 -r 0.1 PID
```

### Trace Mode

Sometimes you want to trace a process from start to finish. An example would be
tracing the run of a test suite. Pyflame supports this use case. To use it, you
invoke Pyflame like this:

```bash
# Trace a given command until completion.
pyflame [regular pyflame options] -t command arg1 arg2...
```

Frequently the value of `command` will actually be `python`, but it could be
something else like `uwsgi` or `py.test`. For instance, here's how Pyflame can
be used to trace its own test suite:

```bash
# Trace the Pyflame test suite, a.k.a. pyflameception!
pyflame -t py.test tests/
```

Beware that when using the trace mode the stdout/stderr of the pyflame process
and the traced process will be mixed. This means if the traced process sends
data to stdout you may need to filter it somehow before sending the output to
`flamegraph.pl`.

### Timestamp ("Flame Chart") Mode

Pyflame can also generate data with timestamps which can be used to
generate ["flame charts"](https://addyosmani.com/blog/devtools-flame-charts/)
that can be viewed in Chrome. These are a type of inverted flamegraph that can
more readable in some cases. Output in this data format is controlled with the
`-T` option.

Use `utils/flame-chart-json` to generate the JSON data required for viewing
Flame Charts using the Chrome CPU profiler.

```
Usage: cat <pyflame_output_file> | flame-chart-json > <fc_output>.cpuprofile
(or) pyflame [regular pyflame options] | flame-chart-json > <fc_output>.cpuprofile
```

Then load the resulting `.cpuprofile` file into the Chrome CPU profiler to view
flame chart.

## FAQ

### What Is "(idle)" Time?

In Python, only one thread can execute Python code at any one time, due to the
Global Interpreter Lock, or GIL. The exception to this rule is that threads can
execute non-Python code (such as IO, or some native libraries such as NumPy)
without the GIL.

By default Pyflame will only profile code that holds the Global Interpreter
Lock. Since this is the only thread that can run Python code, in some sense this
is a more accurate representation of the profile of an application, even when it
is multithreaded. If nothing holds the GIL (so no Python code is executing)
Pyflame will report the time as "idle".

If you don't want to include this time you can use the invocation `pyflame -x`.

If instead you invoke Pyflame with the `--threads` option, Pyflame will take a
snapshot of each thread's stack each time it samples the target process. At the
end of the invocation, the profiling data for each thread will be printed to
stdout sequentially. This gives you a more accurate profile in the sense that
you will see what each thread was trying to do, even if it wasn't actually
scheduled to run.

**Pyflame may "freeze" the target process if you use this option with older
versions of the Linux kernel.** In particular, for this option to work you need
a kernel built with [waitid() ptrace support](https://lwn.net/Articles/688624/).
This change was landed for Linux kernel 4.7. Most Linux distros also backported
this change to older kernels, e.g. this change was backported to the 3.16 kernel
series in 3.16.37 (which is in Debian Jessie's kernel patches). For more
extensive discussion,
see [issue #55](https://github.com/uber/pyflame/issues/55).

One interesting use of this feature is to get a point-in-time snapshot of what
each thread is doing, like so:

```bash
# Get a point-in-time snapshot of what each thread is currently running.
pyflame -s 0 --threads PID
```

### Are BSD / OS X / macOS Supported?

No, these aren't supported. Someone who is proficient with low-level C
programming can probably get BSD to work, as described in issue #3. It is
probably much more difficult (although not impossible) to adapt this code to
work on OS X/macOS, since the current code assumes that the host
uses [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) files
as the executable file format for the Python interpreter.

### What Are These Ptrace Permissions Errors?

Because it's so powerful, the `ptrace(2)` system call is locked down by default
in various situations by different Linux distributions. In order to use ptrace
these conditions must be met:

 * You must have the
   [`SYS_PTRACE` capability](http://man7.org/linux/man-pages/man7/capabilities.7.html) (which
   is denied by default within Docker images).
 * The kernel must not have `kernel.yama.ptrace_scope` set to a value that is
   too restrictive.

In both scenarios you'll also find that `strace` and `gdb` do not work as
expected.

#### Ptrace Errors Within Docker Containers

By default Docker images do not have the `SYS_PTRACE` capability. When you
invoke `docker run` try using the `--cap-add SYS_PTRACE` option:

```bash
# Allows processes within the Docker container to use ptrace.
docker run --cap-add SYS_PTRACE ...
```

You can also use [capsh(1)](http://man7.org/linux/man-pages/man1/capsh.1.html)
to list your current capabilities:

```bash
# You should see cap_sys_ptrace in the "Bounding set".
capsh --print
```

Further note that by design you do not need to run Pyflame from within a Docker
container. If you have sufficient permissions (i.e. you are root, or the same
UID as the Docker process) Pyflame can be run from outside of the container and
inspect a process inside the container. That said, Pyflame will certainly work
within containers if that's how you want to use it.

#### Ptrace Errors Outside Docker Containers Or When Not Using Docker

If you're not in a Docker container, or you're not using Docker at all, ptrace
permissions errors are likely related to you having too restrictive a value set
for the `kernel.yama.ptrace_scope` sysfs knob.

Debian Jessie ships with `ptrace_scope` set to 1 by default, which will prevent
unprivileged users from attaching to already running processes.

To see the current value of this setting:

```bash
# Prints the current value for the ptrace_scope setting.
sysctl kernel.yama.ptrace_scope
```

If you see a value other than 0 you may want to change it. Note that by doing
this you'll affect the security of your system. Please read
[the relevant kernel documentation](https://www.kernel.org/doc/Documentation/security/Yama.txt)
for a comprehensive discussion of the possible settings and what you're
changing. If you want to completely disable the ptrace settings and get
"classic" permissions (i.e. root can ptrace anything, unprivileged users can
ptrace processes with the same user id) then use:

```bash
# Use this if you want "classic" ptrace permissions.
sudo sysctl kernel.yama.ptrace_scope=0
```

#### Ptrace With SELinux

If you're using SELinux,
[you may have problems with ptrace](https://fedoraproject.org/wiki/Features/SELinuxDenyPtrace).
To check if ptrace is disabled:

```bash
# Check if SELinux is denying ptrace.
getsebool deny_ptrace
```

If you'd like to enable it:

```bash
# Enable ptrace under SELinux.
setsebool -P deny_ptrace 0
```

## Blog Posts

If you write a blog post about Pyflame, we may include it here. Some existing
blog posts on Pyflame include:

 * [Pyflame: Uber Engineering's Ptracing Profiler For Python](http://eng.uber.com/pyflame/) by
   Evan Klitzke (2016-09)
 * [Pyflame Dual Interpreter Mode](https://eklitzke.org/pyflame-dual-interpreter-mode) by
   Evan Klitzke (2016-10)
 * [Using Uber's Pyflame and Logs to Tackle Scaling Issues](https://benbernardblog.com/using-ubers-pyflame-and-logs-to-tackle-scaling-issues/) by
   Benoit Bernard (2017-02)

## Contributing

We love getting pull requests and bug reports! This section outlines some ways
you can contribute to Pyflame.

### Hacking

This section will explain the Pyflame code for people who are interested in
contributing source code patches.

The code style in Pyflame (mostly) conforms to
the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html).
Additionally, all of the source code is formatted
with [clang-format](http://clang.llvm.org/docs/ClangFormat.html). There's a
`.clang-format` file checked into the root of this repository which will make
`clang-format` do the right thing. Different clang releases may format the
source code slightly differently, as the formatting rules are updated within
clang itself. Therefore you should eyeball the changes made when formatting,
especially if you have an older version of clang.

The Linux-specific code is be mostly restricted to the files `src/aslr.*`,
`src/namespace.*`, and `src/ptrace.*`. If you want to port Pyflame to another
Unix, you will probably only need to modify these files.

You can run the test suite locally like this:

```bash
# Run the Pyflame test suite.
make test
```

### How Else Can I Help?

Patches are not the only way to contribute to Pyflame! Bug reports are very
useful as well. If you file a bug, make sure you tell us the exact version of
Python you're using, and how to reproduce the issue.

## Legal and Licensing

Pyflame is [free software](https://www.gnu.org/philosophy/free-sw.en.html)
licensed under the
[Apache License, Version 2.0][].

[Apache License, Version 2.0]: LICENSE
