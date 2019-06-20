import sys
import shutil
import os.path
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS
from elftools.common.py3compat import itervalues
from elftools.dwarf.locationlists import LocationEntry
from elftools.dwarf.descriptions import describe_form_class

# This is the compartment tagger to support compartmentalization policies.
#
# add_function_ranges() assigns a unique identifier to each function in a program.
# add_global_ranges() assigns a unique identifier to each global variable.
# Both functions add their output into a range_file, which gets consumed by md_range
# to get incorporated into the .taginfo file.
# The tags placed on these words are either "Comp.funcID" or "Comp.globalID".
# The actual identifier is added to the .taginfo.args file which eventually
# gets set on the field values.

# Function to label each function in a program with a unique tag.
# Puts the Comp.funcID tag on each instruction in the program, then writes
# a unique identifier for that function in the taginfo.args file.
# Also generates a func_defs.h header file that maps these identifiers
# back to strings for pretty printing.
def add_function_ranges(elf_filename, range_file, taginfo_args_file, policy_dir):

    # Add defs into func_defs.h
    defs_file = open("func_defs.h", "w")
    defs_file.write("const char * func_defs[] = {\"<none>\",")
    
    # Open ELF
    with open(elf_filename, 'rb') as elf_file:

        ef = ELFFile(elf_file)

        # See if we have DWARF info. Currently required
        if not ef.has_dwarf_info():
            raise Exception('  file has no DWARF info')
            return

        dwarfinfo = ef.get_dwarf_info()

        function_number = 1
        
        # Code below taken from decode_funcname() in the ELFtools examples.
        # It understands how to interpert high_pc under two conditions.
        #
        # Iterate through each compilation unit.
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                try:
                    # We only care about functions (subprograms)
                    if str(DIE.tag) == "DW_TAG_subprogram":
                        func_name = DIE.attributes["DW_AT_name"].value.decode("utf-8")
                        func_display_name = str(func_name)
                        print("Compartment tagger: tagging function " + func_display_name)
                        
                        lowpc = DIE.attributes['DW_AT_low_pc'].value

                        # DWARF v4 in section 2.17 describes how to interpret the
                        # DW_AT_high_pc attribute based on the class of its form.
                        # For class 'address' it's taken as an absolute address
                        # (similarly to DW_AT_low_pc); for class 'constant', it's
                        # an offset from DW_AT_low_pc.
                        highpc_attr = DIE.attributes['DW_AT_high_pc']
                        highpc_attr_class = describe_form_class(highpc_attr.form)
                        if highpc_attr_class == 'address':
                            highpc = highpc_attr.value
                        elif highpc_attr_class == 'constant':
                            highpc = lowpc + highpc_attr.value
                        else:
                            print('Error: invalid DW_AT_high_pc class:',
                                  highpc_attr_class)
                            continue

                        # Okay, we now have the low addr, high addr, and name
                        # Currently high-pc is getting the first PC NOT part of this
                        # function, so subtracting 4 at the moment to cover range.
                        # Add Comp.funcID to taginfo file
                        range_file.write_range(lowpc, highpc, "Comp.funcID")
                        # Set the field for these instruction words in the taginfo_args file.
                        taginfo_args_file.write('%x %x %s\n' % (lowpc, highpc - 4, str(function_number) + " 0"))

                        # Add this function name to the header file defs if we're making one
                        defs_file.write("\"" + func_display_name + "\",")
                        function_number += 1
                        
                except KeyError:
                    print("KeyError: " + str(KeyError))
                    continue

        # Finish off definition file, then copy into policy include folder
        defs_file.write("\"\"};\n")
        defs_file.close()
        shutil.copy("func_defs.h", os.path.join(policy_dir, "engine", "policy", "include"))


# Analog to add_function_ranges() for extracting global variables. 
# I tried to get globals via pyelftools, but it doesn't look like the size/type DIEs
# are parsed for some reason. I spent a few hours and couldn't figure it out. Temp solution
# is to just dump from nm.
# TODO: this is currently just dumping global info from nm, should get from compiler metadata
def add_global_var_ranges(elf_filename, range_file, taginfo_args_file, policy_dir):
    
    # Check for nm:
    isp_prefix = os.environ['ISP']
    nm = os.path.join(isp_prefix, "riscv32-unknown-elf", "bin", "nm")

    if os.path.isfile(nm):
        print("Found nm at " + nm)
    else:
        print("WARNING: could not find nm. Looked for " + nm)
        return

    defs_file = open("global_defs.h", "w")
    defs_file.write("const char * global_defs[] = {\"<none>\",")    

    p = subprocess.Popen([nm, "-S", elf_filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Process nm output
    global_number = 0
    while True:
        line = p.stdout.readline().decode("utf-8").strip()
        parts = line.split()
        if len(parts) == 4:

            # Decode format of nm output
            addr = parts[0]
            size = parts[1]
            code = parts[2]
            name = parts[3]

            # Grab globals. Assuming come from .bss, .data, .ro...
            if code in ["b", "B", "d", "D", "r", "R", "g", "G"]:
                global_number += 1
                print("Compartment tagger: tagging global " + name + " at address " + addr + " size=" + size + " with ID " + str(global_number))
                
                # Compute highpc, needed for range file format
                lowpc = int(addr, 16)
                size = int(size, 16)
                highpc = lowpc + size
                range_file.write_range(lowpc, highpc, "Comp.globalID")
                taginfo_args_file.write('%x %x %s\n' % (lowpc, highpc, str(global_number) + " 0"))
                defs_file.write("\"" + name + "\",")
                

        # Exit when no more output from nm
        if not line:
            break
        
    # Finish off definition file, then copy into policy include folder
    defs_file.write("\"\"};\n")
    defs_file.close()
    shutil.copy("global_defs.h", os.path.join(policy_dir, "engine", "policy", "include"))
