# policy-engine

Generic functional policy engine for functional simulation of security policies
on platforms such as Renode.

This project provides a framework for integrating policy code generated by the
Dover policy tool with functional simulators that are capable of simulating
complete or partial SOC environments.

The framework here was constructed primarily to allow integration with Renode,
but other bindings should be relatively easy to accomplish.

The framework currently builds on linux.  For installation
instructions, skip the the [Getting Started](#getting-started) section
below.

# Renode

[Renode](https://github.com/renode/renode) is an SOC simulator project by
[AntMicro](https://antmicro.com/).  The simulator is written primarily in C#,
but uses a number of external C/C++ libraries for some of its core.  In
particular, the underlying CPU emulations are implemented using libqemu.  Renode
runs on multiple platfoms, and supports debugging emulated code with GDB.

From an implementation standpoint, it is important to note that QEMU operates
by re-compiling target architecture binary instructions into functionally
equivalent blocks that are run as native code on the host.  QEMU is built for
speed, and prefers to transpile entire basic blocks of code to achieve best
performance.  This is worked around for debugging, or in our case for
validation, by restricting QEMU to a basic block size of 1 instruction.  This
gives up substantial performance, but it is still possible to get relatively
good simulation speed for functional testing purposes.  For those of you
familiar with an environment like Spike (RISCV), the implementation using QEMU
means that it is more difficult to reach into the simulated core, to do creative
fiddling with it.

# Basic Validation API

In this framework, there is a very basic API coupling to the simulator.  At each
instruction, the simulator calls a validate method before executing the
instruction, and a commit method after executing the instruction.

At the top most level, an implementation of a validator under this framework
doesn't know anything at all about tags, and could do something completely
arbitrary to effect its validation.

The validate method currently returns a simple true or false, indicating whether
or not to let the instruction execution proceed.  The validate method is passed
the address of the instruction being executed, and the instruction bits.  This
choice of information is purely for efficiency of the simulation.

The commit method is called to notify the validator that the instruction
actually retired, to allow the validator to do bookkeeping as needed.

# Integration of Policy Code

The framework is intended to facilitate integration of policy execution code
generated by the policy tool [ref policy tool project].

When the policy tool compiles a policy, it generates several artifacts:

* C code implementing the core policy evaluation function
* YAML files describing metadata required by the evalation function:
  - Metadata specific to particular groups of instructions
  - Concrete values for atomic metadata elements or symbols
  - Initialization requirements for various SOC elements, including registers,
    memory regions and named elements such as memorym mapped peripherals.
	
The policy evalation function is generated such that it should be able to run
unmodified (at the source level) on the actual host platform.  It has
dependencies that have to be met by the platform on which it runs.  Its API is
intended to be platform agnostic, but some of the input data to the function is
necessarily architecture dependent.

For a given architecture, the policy code establishes a stable set of input and
output structures.  A generic set of APIs and an invocation sequence is
specified allowing an implementor of a validator to follow a specification for
integrating generated policy code.

There are three main architecture specific structures that the policy code
relies on.  These structures will have internals that a validator implementation
must be familiar with:

* context_t - context information for a single validation
* operands_t - architecture specific input metadata operands for an instruction
* results_t - architecture specific output metadata operands for an evaluation

So for example, on RISCV, the context contains the PC address, a memory address
for the instruction, if there is one.  The operands contain up to 3 register
input metadata, one memory metadata, plus the PC metada, and the instruction
metadata.  The results struction contains an output register metadata, one csr
output metadata, and one memory metadata.

The validator implementation is required to setup the input structures for a
given evaluation call, then call the policy code, then deal with the outputs of
the policy evaluation.  This allows for efficient decoupling of the policy code
from a direct hardware integration to a functional simulator.

# Tags vs Metadata

There is a subtle distinction between tags and metadata records.  Tags
here are the architecture specific values associated with registers
and memory locations.  Metadata records (meta_set_t type in policy
code) are referred to by tags.  How that reference is accomplished is
intended to be flexible.  In the implementation here, they are simple
pointers, but a distinction is maintained at the API level to leave it
flexible.

# Metadata Management

The policy code operates on metadata records whose structure will change from
one generated policy to the next.  The policy code defines some stable APIs for
initializing those structures, using the data provided by the YAML output.  The
validator must implement the code that handles memory management for the dynamic
run of the system for all metadata.  It must also set up the initial state of
that metadata, based on the YAML data and whatever external tagging instructions
are provided it.

When the policy evaluation function executes, it returns some metadata
structures as output.  Then validator has to be able to hash these in order to
maintain any efficiency of operation.  Provided in this framework is a generic
metadata structure hashing utility that an architecture specific implementation
may call when receiving results from the policy code.

# Tag Interfaces

During normal operation, a tag based validator has to look up tags for
registers and memory operands to instructions.  The framework provides utility
code for storing register files of tags, as well as providing tags for system
memory and peripherals (memory mapped registers).  In some cases, we want to
provide a single tag for a region of memory, in some cases we want to provide
heterogeneous tags.

# Initial Tagging

When the system starts up, it is necessary to establish an initial tag state for
the SOC for the validator to operate from.  Provided in the framework is an API
for parsing the YAML files that are generated by the policy tool.  The API
allows for high level methods for creating the metadata records that the
generated policy code will consume.  That API is stable across different
policies and architectures.  It allows for identification of SOC elements by
name (e.g. "dover.SOC.IO.UART0"), permitting the validation framework to do
initialization using human readable data that can remain stable across policy
builds.

Support code is provided around these utility classes in architecture specific
implementations of validators to set up the initial system state.

# RISCV Tag Based Validator

There is a RISCV specific implementation of a validator provided.  The
implementation includes all the code necessary to set up the initial SOC
state, and maintain metadata across a run.

The validator uses a RISCV instruction decoder to decode incoming instructions
to determine which input tags (based on the registers used by the instruction)
are used, and what memory tag should be used (dependent on register state of
the CPU).

# Tools For Tags

See README in tagging_tools directory.

# Getting Started

## Build gcc

Pull the RISCV gnu toolchain from
<https://github.com/riscv/riscv-gnu-toolchain>.  Note that this is the
official version from the RISC-V foundation github, not the custom
Dover/Draper version.

Follow the instructions in that repository's README to pull its submodules and
install relevant prerequisites (the "Getting the sources" and "Prerequisites"
section in the README).  Then, configure it as follows:

```
mkdir build
cd build
../configure --prefix=<wherever you want it installed> --with-arch=rv32g --with-abi=ilp32
make
```

(On Arch Linux one also has to pass `--with-guile=no` to `configure`,
since [the guile version that comes with Arch is
incompatible](https://github.com/riscv/riscv-binutils-gdb/issues/82)
and for some reason it gets picked up by `riscv-binutils-gdb`)

The resulting binaries have names like "riscv32-unknown-elf-*".  A
later step will expect to find these on your PATH.

You will not have to build this again anytime soon.


## Build Renode

Pull our modified version of Renode:

<https://github.com/draperlaboratory/hope-renode.git>

You need to follow the instructions in the Renode repos README.rst for getting
the prerequisites and building renode.

The first time you build Renode, it will populate submodules.  The submodules
will not be on the proper branch, because of some git submodule issues that we
haven't sorted out.  So build the project once, then go to the
src/Infrastructure directory, and do a `git checkout dover` to ensure that it
is on the proper branch.  Then go back to the top level renode directory, and
run `./build.sh -c` followed by `./build.sh`.

You will not have to build this again anytime soon.


## Build the policy-tool

Pull the policy tool:

<https://github.com/draperlaboratory/hope-policy-tool.git>

The policy tool uses `stack` to build.  If you don't have stack
installed, you can find [installation instructions at the Stack
website](https://docs.haskellstack.org/en/stable/README/).

Once you have stack installed, build the policy tool by running `stack
install` from the top level `policy-tool` directory.  This may take a
while the first time, as a local instance of GHC and all dependencies
are installed.


## Build the policy-engine Project

Pull the repository containing the repositories:

<https://github.com/draperlaboratory/hope-policies.git>

This be in the same directory as the `policy-engine` repository (they
should have the same parent directory).

Go to the policy engine project.  Run the policy tool with
`./bld_policy`.  This will populate the local `policy` directory with
the RWX policy.

The policy engine requires `cmake` and a few C++ libraries to build.
On Ubuntu, you can get these with

```
sudo apt-get install cmake libboost-dev libboost-program-options-dev libyaml-cpp-dev
```

Then build the policy-engine project, proper:

```
mkdir build
cd build
cmake ..
make
```

This will build the renode validator, plus the standalone validator test app.  For example, from the build directory, you should see a simple policy violation error when you run:

```
./standalone ../policy ../soc_cfg/miv_cfg.yml
```


## Build a FreeRTOS project

Pull the FreeRTOS repos:

<https://github.com/draperlaboratory/hope-FreeRTOS.git>

Go to the `Demo/RISCV_MIV_GCC/hello_world` directory, and follow the
instructions in the README.md file for building the hello world
sample.


## Generate Tags

The next stem is to run the `policy-engine/tagging_tools/gen_tag_info`
script on your hello world binary.  This tool depends on some python
packages, so install those first:

```
sudo apt-get install python3-pip
pip3 install pyelftools
```

Then invoke the tagging tool, adjusting the paths appropriately:

```
hope-policy-engine/tagging_tools/gen_tag_info hope-policy-engine/policy 0x80000000 hope-policy-engine/application_tags.taginfo hello_world
```

You can ignore the warnings about missing tags for floating point
instructions.

The location of the `application_tags.taginfo` file has some hardcoding
requirements on it currently.  The Renode validator shared library will load
policy YAML files in order to set up register state.  It will look to the
environment variable mentioned in the `Run Under Renode` section for those.  It
will also load the file `application_tags.taginfo` from the directory one above
the policy directory.  This will be changed in the future to be configurable.


## Run Under Renode

In your `hope-policy-engine/scripts` directory, there is a `run_riscv` script.
You will have to change paths in there to point at your renode build, and at
your policy-engine build.

You have to export a variable to point to policy stuff:

```
export GENERATED_POLICY_DIR=<whatever>/policy-engine/policy
```

Then you can use the run_riscv script to run your app under renode:

```
hope-policy-engine/scripts/run_riscv hope-FreeRTOS/Demo/RISCV_MIV_GCC/hello_world/build/hello_world
```
