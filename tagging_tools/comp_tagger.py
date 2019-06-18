import sys
import shutil
import os.path
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS
from elftools.common.py3compat import itervalues
from elftools.dwarf.locationlists import LocationEntry
from elftools.dwarf.descriptions import describe_form_class

# This is the compartment tagger to support compartmentalization policies.
#
# In its current form, it simply tags each function with a unique identifier.

# Associates a tag on each function, adds to an existing range file
# Uses DWARF info to get function name. Currently cycles through 5 function labels
def make_func_range_map(elf_filename, range_file, taginfo_args_file, headerfile_name = None, policy_dir = None):

    if headerfile_name != None:
        headerfile = open("comp_defs.h", "w")
        headerfile.write("const char * comp_defs[] = {\"<none>\",")
    
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
                        print("Compartment tagger tagging function: " + func_display_name)
                        
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
                        if headerfile_name != None:
                            headerfile.write("\"" + func_display_name + "\",")
                        function_number += 1
                        
                except KeyError:
                    print("KeyError: " + str(KeyError))
                    continue

        # Finish off definition file, then copy into policy include folder
        if headerfile_name != None:
            headerfile.write("\"\"};\n")
            headerfile.close()
            shutil.copy(headerfile_name, os.path.join(policy_dir, "engine", "policy", "include"))
