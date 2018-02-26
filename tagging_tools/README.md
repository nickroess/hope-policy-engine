# Tagging Tools

This directory contains code for two base level tagging utilities, that can be used generically
to generate tagging information for most policies.  The generated tagging information is used by
the Renode based validator to set up the initial state of tags for an application.

The utilities are intended to provide flexibility for experimentation with policies.  They can
be used to generate tagging information for arbitrary memory locations.

There are scripts that are layered on top of these base utilities that provide a single point of
control for generating tagging information for applications.

The idea behind using generic tagging utilities is to allow for the combination of hetergeneous
sources of information for applying tags to an application.  One set of data could come from the
compiler, while another might come from some external specification for marking, say, some particular
symbols in an application.

# Utilities

## md_range

```
usage: md_range <policy_dir> <base_address> <range_file> <tag_file>
```

* `policy_dir` is the directory into which the policy was generated by the policy tool.
* `base_address` is the base address that RAM will be at.  So 0x80000000 for a typical RISCV platform.
* `range_file` is the name of a text file containing range specifications to tag.
* `tag_file` is the name of tag info file to write.  If the file exists, it will be overwritten.

The range file has a format like this:

```
<start addr> <end addr> tag_name
...
```

So, for example:

```
0x80000000 0x80010000 requires.dover.Kernel.Code.ElfSection.SHF_EXECINSTR
0x80010000 0x80020000 requires.dover.Kernel.Code.ElfSection.SHF_WRITE
```

The same range can be specified more than once if you wish to apply multiple tags to it.
Ranges may overlap partially as well.

This utility is used to form the base set of tagging information.  In general, to make use
of the tagging information in the validator, you must follow up with `md_code` to put group
tags on instructions in your application.

## md_code

The `md_code` utility generates the group tags for instructions in an image.

```
usage: md_code <policy-dir> <base_address> <code_address> <tag_file>
```

The utility will read a stream of instructions (assumed to be RV32 at this point) from
stdin.  The given `tag_file` will be _updated_ with the group tags for the instructions.
The utility disassembles the input stream and matches the opgroups for the instructions
against group information provided by the policy compiler to develop the appropriate set
of group tags for each concrete instruction.

* `policy_dir` is the directory into which the policy was generated by the policy tool.
* `base_address` is the base address that RAM will be at.  So 0x80000000 for a typical RISCV platform.
* `code_address` is the address at which the stream of instructions from stdin is assumed to be based.
* `tag_file` is the name of the tag file to update.

# Scripts

There is one script that can be used used on an ELF format binary to generate tagging information
for an application.

`gen_tag_info` is a python script that uses pyelf to parse an input ELF file, and calls
both `md_range` and `md_code` to generate tagging information for the RWX policy for the application.
This utility can be expanded upon to add more policy support.

# Future

Probably will change md_range to take an option to update an existing tagging file, so that it
can be called multiple times by multiple tools.
