import pefile
import sys

print('''
 mmmm   m      m              mmmm                                           
 #   "m #      #             #"   "  mmm    mmm   m mm   m mm    mmm    m mm 
 #    # #      #             "#mmm  #"  "  "   #  #"  #  #"  #  #"  #   #"  "
 #    # #      #                 "# #      m"""#  #   #  #   #  #""""   #    
 #mmm"  #mmmmm #mmmmm   #    "mmm#" "#mm"  "mm"#  #   #  #   #  "#mm"   #    by Wam11\n''')

mal_file = sys.argv[1]
pe = pefile.PE(mal_file)
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print("{}".format(entry.dll))
        for imp in entry.imports:
            if imp.name != None:
                print("\t{}".format(imp.name))
            else:
                print("\tord {}".format(str(imp.ordinal)))
        print("\n")

if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print('{}'.format(exp.name))

print("\nEnd ")
