# by David Reguera Garcia aka Dreg
# https://github.com/therealdreg/ida_bochs_windows
# https://www.fr33project.org - dreg@fr33project.org @therealdreg 

import ida_kernwin
import idautils
import ida_segment

cred = '''
IDA names to Bochs syms
https://github.com/therealdreg/ida_bochs_windows
GNU General Public License v3.0
-
by David Reguera Garcia aka Dreg
Twitter @therealdreg
https://www.fr33project.org
dreg@fr33project.org
https://github.com/therealdreg
'''
print(cred)

filename = ida_kernwin.ask_file(True, "*.txt", "Select file to save symbols")

with open(filename, "w+") as file:
    i = 0
    print("\n")
    for addr, name in idautils.Names():
        prfx = "unk_"
        try:
            prfx = ida_segment.get_segm_name(ida_segment.getnseg(ida_segment.get_segm_num(addr)))
            prfx = prfx.replace(".", "")[:5] + "_"
        except:
            pass
        inf = hex(addr) + " " + prfx + name + "\n"
        file.write(inf)
        if i < 10:
            print(inf)
        i += 1
    print("...\n")
    print("done symbols saved -> ", filename)
        
# Type in bochs debugger: ldsym global "C:\\Users\\Dreg\\bochs\\sym.txt"