import pefile
import sys
import time

print('''
 mmmm   m      m              mmmm                                           
 #   "m #      #             #"   "  mmm    mmm   m mm   m mm    mmm    m mm 
 #    # #      #             "#mmm  #"  "  "   #  #"  #  #"  #  #"  #   #"  "
 #    # #      #                 "# #      m"""#  #   #  #   #  #""""   #    
 #mmm"  #mmmmm #mmmmm   #    "mmm#" "#mm"  "mm"#  #   #  #   #  "#mm"   #    by Wam11\n''')

mal_file = sys.argv[1]
pe = pefile.PE(mal_file)

print('\t--------Compile Timestamp--------\n')
timestamp = pe.FILE_HEADER.TimeDateStamp
print(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(timestamp)))

print('\t--------File Dependencies and Imports--------\n')
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print("{}".format(entry.dll))
        for imp in entry.imports:
            if imp.name != None:
                print("\t{}".format(imp.name))
            else:
                print("\tord {}".format(str(imp.ordinal)))
        print("\n")

print('\t--------File Exports--------\n')
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print('{}'.format(exp.name))

print("\n")

print('\t--------PE Section--------\n')
for section in pe.sections:
    print("{0} {1} {2} {3}".format (section.Name,
                           hex(section.VirtualAddress),
                           hex(section.Misc_VirtualSize),
                           section.SizeOfRawData))
print("\n")
print('\t--------Copleted!--------\n')
