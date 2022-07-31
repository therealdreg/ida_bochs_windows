# by David Reguera Garcia aka Dreg
# https://github.com/therealdreg/ida_bochs_windows
# https://www.fr33project.org - dreg@fr33project.org @therealdreg 

import ida_kernwin
import ida_segment

cred = '''
IDA segments to Bochs syms
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

filename = ida_kernwin.ask_file(True, "*.txt", "Select file to save segments")

with open(filename, "w+") as file:
    i = 0
    print("\n")
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if seg:
            file.write(hex(seg.start_ea) + " " + ida_segment.get_segm_name(seg).replace(".", "") + "\n")
            file.write(hex(seg.end_ea) + " " + ida_segment.get_segm_name(seg).replace(".", "") + "_end" + "\n")
    print("done segments saved -> ", filename)
        
# Type in bochs debugger: ldsym global "C:\\Users\\Dreg\\bochs\\sym.txt"